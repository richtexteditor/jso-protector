"use strict";

// Tests for jso-protector --estimate. Spins up a mock /v1/ai/usage.ashx
// endpoint and runs the CLI against it. Asserts the three gate states
// (ok / warn / fail), the bytes/files counting math, the --json
// envelope shape, and graceful handling of an unreachable usage
// endpoint.

const test       = require("node:test");
const assert     = require("node:assert");
const http       = require("node:http");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const { spawn }  = require("node:child_process");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

function startUsageMock(responder) {
    return new Promise(resolve => {
        const srv = http.createServer((req, res) => {
            let body = "";
            req.on("data", c => body += c);
            req.on("end", () => {
                if (!req.url.includes("/v1/ai/usage")) {
                    res.writeHead(404); res.end(); return;
                }
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify(responder(JSON.parse(body))));
            });
        });
        srv.listen(0, "127.0.0.1", () => resolve(srv));
    });
}

function makeFixture(...sources) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-est-"));
    fs.mkdirSync(path.join(root, "in"));
    sources.forEach((src, i) => fs.writeFileSync(path.join(root, "in", "f" + i + ".js"), src));
    return root;
}

function runCli(args) {
    return new Promise(resolve => {
        const c = spawn(process.execPath, [CLI, ...args]);
        let out = "", err = "";
        c.stdout.on("data", d => out += d.toString());
        c.stderr.on("data", d => err += d.toString());
        c.on("close", code => resolve({ code, out, err }));
    });
}

const HEALTHY_USAGE = {
    ok: true, previewMode: false, tier: "Basic",
    billingMonth: "2026-05-01",
    actionsUsed: 5, actionsCap: 50, actionsRemaining: 45,
    tokensUsed: 1000, tokensCap: 50000, tokensRemaining: 49000,
    approxCostCents: 100, costCapCents: 1900, costRemainingCents: 1800,
    providerKey: {
        hasKey: true,
        provider: "openai",
        status: "ready",
        label: "Key ready",
        testDue: false,
        rotationDue: false,
        lastTestStatus: "passed",
        lastTestUtc: "2026-05-27T12:00:00Z",
        nextTestDueUtc: "2026-06-26T12:00:00Z",
        rotationDueUtc: "2026-08-25T12:00:00Z",
        recommendedAction: "No action needed today."
    },
    quotaRejections: 0, asOfUtc: "2026-05-27T12:00:00Z",
};

test("--estimate: healthy quota, exits 0 with gate OK", async () => {
    const root = makeFixture("var x = 1;\nvar y = 2;\n", "console.log('hi');\n");
    const srv = await startUsageMock(() => HEALTHY_USAGE);
    try {
        const port = srv.address().port;
        const { code, out } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--estimate",
        ]);
        assert.equal(code, 0);
        assert.match(out, /Build inputs:\s+2 file\(s\)/);
        assert.match(out, /actions: 5 \/ 50.*45 remaining/);
        assert.match(out, /AI key health: Key ready \(openai\) \[ready\]/);
        assert.match(out, /next test due:\s+2026-06-26T12:00:00Z/);
        assert.match(out, /rotation review:\s+2026-08-25T12:00:00Z/);
        assert.match(out, /Gate: OK/);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("--estimate --json: machine-readable envelope", async () => {
    const root = makeFixture("var x;\n");
    const srv = await startUsageMock(() => HEALTHY_USAGE);
    try {
        const port = srv.address().port;
        const { code, out } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--estimate", "--json",
        ]);
        assert.equal(code, 0);
        const env = JSON.parse(out);
        assert.equal(env.estimate.input.files, 1);
        assert.ok(env.estimate.input.bytes > 0);
        assert.equal(env.estimate.quota.tier, "Basic");
        assert.equal(env.estimate.quota.actions.remaining, 45);
        assert.equal(env.estimate.providerKey.status, "ready");
        assert.equal(env.estimate.providerKey.provider, "openai");
        assert.equal(env.estimate.providerKey.nextTestDueUtc, "2026-06-26T12:00:00Z");
        assert.equal(Object.prototype.hasOwnProperty.call(env.estimate.providerKey, "apiKey"), false);
        assert.equal(env.estimate.gate, "ok");
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("--estimate: actionsRemaining=0 fails the gate (exit 1)", async () => {
    const root = makeFixture("var x;");
    const srv = await startUsageMock(() => ({ ...HEALTHY_USAGE, actionsUsed: 50, actionsRemaining: 0 }));
    try {
        const port = srv.address().port;
        const { code, out } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--estimate",
        ]);
        assert.equal(code, 1);
        assert.match(out, /Gate: FAIL/);
        assert.match(out, /quota exhausted/i);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("--estimate: actionsRemaining < 5 warns but doesn't fail", async () => {
    const root = makeFixture("var x;");
    const srv = await startUsageMock(() => ({ ...HEALTHY_USAGE, actionsUsed: 47, actionsRemaining: 3 }));
    try {
        const port = srv.address().port;
        const { code, out } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--estimate",
        ]);
        assert.equal(code, 0);
        assert.match(out, /Gate: WARN/);
        assert.match(out, /Action quota nearly exhausted/);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("--estimate: usage endpoint unreachable -> gate WARN with note", async () => {
    const root = makeFixture("var x;");
    try {
        // Point at a port we know is closed. The CLI should warn,
        // not crash, and not fail-exit.
        const { code, out } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", "http://127.0.0.1:1/HttpApi.ashx",
            "--api-key", "k", "--api-password", "p",
            "--estimate",
        ]);
        assert.equal(code, 0);
        assert.match(out, /Gate: WARN/);
        assert.match(out, /Could not read quota/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("--estimate: no input files -> error exit", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-est-"));
    fs.mkdirSync(path.join(root, "in"));    // empty input dir
    try {
        const { code, err } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", "http://127.0.0.1:1/HttpApi.ashx",
            "--api-key", "k", "--api-password", "p",
            "--estimate",
        ]);
        assert.notStrictEqual(code, 0);
        assert.match(err, /no matching input files/i);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
