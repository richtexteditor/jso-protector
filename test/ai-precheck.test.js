"use strict";

// Smoke test for jso-protector --ai-precheck. Spins up a single mock server
// that routes /v1/ai/compat-check.ashx and /HttpApi.ashx separately, so
// the same --endpoint base URL covers both. Exit code + per-route call
// counts verify the contract: when the gate fails, the obfuscation API
// must NOT be called; when it passes, the build proceeds.

const test       = require("node:test");
const assert     = require("node:assert");
const http       = require("node:http");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const { spawn }  = require("node:child_process");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

function startMock(aiResponse, obfResponseBuilder) {
    const state = { aiCalls: 0, obfCalls: 0 };
    return new Promise(resolve => {
        const srv = http.createServer((req, res) => {
            let body = "";
            req.on("data", c => body += c);
            req.on("end", () => {
                if (req.url.includes("/v1/ai/compat-check")) {
                    state.aiCalls++;
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify(aiResponse));
                } else if (req.url.includes("/HttpApi.ashx")) {
                    state.obfCalls++;
                    const parsed = JSON.parse(body);
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify(obfResponseBuilder(parsed)));
                } else {
                    res.writeHead(404); res.end();
                }
            });
        });
        srv.listen(0, "127.0.0.1", () => resolve({ srv, state }));
    });
}

function makeFixture(source) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-precheck-"));
    fs.mkdirSync(path.join(root, "in"));
    fs.writeFileSync(path.join(root, "in", "app.js"), source);
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

function echoBack(parsed) {
    return {
        Type: "Succeed",
        Items: (parsed.Items || []).map(it => ({ FileName: it.FileName, FileCode: it.FileCode })),
        Report: { BuildId: "test-build-1" },
    };
}

test("--ai-precheck: gate fails on error finding, obfuscation API never called", async () => {
    const root = makeFixture("eval('boom');");
    const { srv, state } = await startMock({
        ok: true,
        report: {
            summary: { errors: 1, warnings: 0, infos: 0 },
            findings: [{
                category: "dynamic-eval", severity: "error",
                line: 1, column: 1, message: "eval", suggestedFix: "remove",
            }],
        },
    }, echoBack);
    try {
        const port = srv.address().port;
        const { code } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--ai-precheck",
        ]);
        assert.notStrictEqual(code, 0, "gate should fail the build");
        assert.equal(state.aiCalls, 1);
        assert.equal(state.obfCalls, 0, "obfuscation must NOT run when gate fails");
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("--ai-precheck: clean file passes gate, obfuscation proceeds", async () => {
    const root = makeFixture("var x = 1;");
    const { srv, state } = await startMock({
        ok: true,
        report: { summary: { errors: 0, warnings: 0, infos: 0 }, findings: [] },
    }, echoBack);
    try {
        const port = srv.address().port;
        const { code } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--ai-precheck",
        ]);
        assert.equal(code, 0, "clean gate should let the build finish");
        assert.equal(state.aiCalls, 1);
        assert.equal(state.obfCalls, 1);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("--ai-precheck-fail-on never: ignores findings, build proceeds", async () => {
    const root = makeFixture("eval('still bad');");
    const { srv, state } = await startMock({
        ok: true,
        report: { summary: { errors: 99, warnings: 0, infos: 0 }, findings: [] },
    }, echoBack);
    try {
        const port = srv.address().port;
        const { code } = await runCli([
            "--input", path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--ai-precheck", "--ai-precheck-fail-on", "never",
        ]);
        assert.equal(code, 0);
        assert.equal(state.obfCalls, 1);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});
