"use strict";

// Smoke test for `jso ai compat-scan`. Spins up a mock JSO endpoint,
// drops a tiny fixture project on disk, then invokes the CLI as a child
// process (so the node:test runner's own stdout writes don't pollute the
// JSON envelope we parse).

const test       = require("node:test");
const assert     = require("node:assert");
const http       = require("node:http");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const { spawn } = require("node:child_process");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

function startMock(handler) {
    return new Promise(resolve => {
        const srv = http.createServer((req, res) => {
            let body = "";
            req.on("data", c => body += c);
            req.on("end", () => handler(req, body, res));
        });
        srv.listen(0, "127.0.0.1", () => resolve(srv));
    });
}

function makeFixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-scan-"));
    fs.mkdirSync(path.join(root, "src"));
    fs.writeFileSync(path.join(root, "src", "a.js"), "eval('x');");
    fs.writeFileSync(path.join(root, "src", "b.js"), "var x = 1;");
    fs.mkdirSync(path.join(root, "src", "ignored"));
    fs.writeFileSync(path.join(root, "src", "ignored", "c.js"), "bad();");
    fs.writeFileSync(path.join(root, "jso.config.json"), JSON.stringify({
        input: "src", extensions: [".js"], framework: "react", exclude: ["ignored"]
    }));
    return root;
}

function runCli(args) {
    return new Promise(resolve => {
        const c = spawn(process.execPath, [CLI, "ai", ...args]);
        let out = "", err = "";
        c.stdout.on("data", d => out += d.toString());
        c.stderr.on("data", d => err += d.toString());
        c.on("close", code => resolve({ code, out, err }));
    });
}

test("compat-scan: walks input dir, skips exclude, aggregates findings, gate fails on error", async () => {
    const root = makeFixture();
    let calls = 0;
    const srv = await startMock((req, body, res) => {
        calls++;
        const b = JSON.parse(body);
        assert.equal(b.framework, "react");
        const hasEval = b.source.includes("eval");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            ok: true,
            report: {
                summary: { errors: hasEval ? 1 : 0, warnings: 0, infos: 0 },
                findings: hasEval ? [{
                    category: "dynamic-eval", severity: "error",
                    line: 1, column: 1, message: "eval", suggestedFix: "remove",
                }] : [],
            },
        }));
    });
    const { port } = srv.address();
    try {
        const { code, out } = await runCli([
            "compat-scan",
            "--config", path.join(root, "jso.config.json"),
            "--endpoint", `http://127.0.0.1:${port}`,
            "--api-key", "k", "--api-password", "p",
        ]);
        assert.equal(calls, 2, "ignored/c.js must not be scanned");
        const env = JSON.parse(out);
        assert.equal(env.summary.files, 2);
        assert.equal(env.summary.errors, 1);
        assert.equal(env.ok, false);
        assert.equal(code, 1);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("compat-scan: --fail-on never always passes the gate", async () => {
    const root = makeFixture();
    const srv = await startMock((req, body, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            ok: true,
            report: { summary: { errors: 5, warnings: 0, infos: 0 }, findings: [] },
        }));
    });
    const { port } = srv.address();
    try {
        const { code, out } = await runCli([
            "compat-scan",
            "--config", path.join(root, "jso.config.json"),
            "--endpoint", `http://127.0.0.1:${port}`,
            "--api-key", "k", "--api-password", "p",
            "--fail-on", "never",
        ]);
        const env = JSON.parse(out);
        assert.equal(env.ok, true);
        assert.equal(code, 0);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("compat-scan: --max-files caps the walk", async () => {
    const root = makeFixture();
    let calls = 0;
    const srv = await startMock((req, body, res) => {
        calls++;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            ok: true,
            report: { summary: { errors: 0, warnings: 0, infos: 0 }, findings: [] },
        }));
    });
    const { port } = srv.address();
    try {
        await runCli([
            "compat-scan",
            "--config", path.join(root, "jso.config.json"),
            "--endpoint", `http://127.0.0.1:${port}`,
            "--api-key", "k", "--api-password", "p",
            "--max-files", "1",
        ]);
        assert.equal(calls, 1);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("compat-scan: missing config exits 2", async () => {
    const { code, out, err } = await runCli([
        "compat-scan", "--config", "/no/such/file.json",
        "--api-key", "k", "--api-password", "p",
    ]);
    assert.equal(code, 2);
    assert.match(out + err, /config not found/);
});
