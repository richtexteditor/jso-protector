"use strict";

// Tests for the watermark module + the CLI flags that wire it in.
// Two layers:
//   - direct module tests against ../watermark.js (signing, parsing,
//     constant-time compare, encoding round-trip)
//   - end-to-end CLI smoke: spin up a mock obfuscation server that
//     echoes Items back, verify the watermark survives the round-trip
//     and that --verify-watermark exits correctly

const test       = require("node:test");
const assert     = require("node:assert");
const http       = require("node:http");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const { spawn }  = require("node:child_process");
const watermark  = require("../watermark.js");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

// ---------- direct module tests ----------

test("watermark: signTag is deterministic and key-bound", () => {
    const a = watermark.signTag("release-42", "secret-key");
    const b = watermark.signTag("release-42", "secret-key");
    const c = watermark.signTag("release-42", "different-key");
    assert.equal(a, b, "same (tag, key) -> same signature");
    assert.notEqual(a, c, "different keys produce different signatures");
});

test("watermark: signTag throws on missing inputs", () => {
    assert.throws(() => watermark.signTag("", "k"), /tag is required/);
    assert.throws(() => watermark.signTag("t", ""), /key is required/);
});

test("watermark: injectInto prepends header that verify can read back", () => {
    const src = "var x = 1; console.log(x);";
    const stamped = watermark.injectInto(src, "license-XYZ", "shh");
    assert.ok(stamped.startsWith("/*! __jso_watermark_v1"), "header is at top");
    const v = watermark.verify(stamped, "shh");
    assert.equal(v.present, true);
    assert.equal(v.valid, true);
    assert.equal(v.tag, "license-XYZ");
});

test("watermark: wrong key fails verification (constant-time compare)", () => {
    const stamped = watermark.injectInto("var x;", "tag", "right-key");
    const v = watermark.verify(stamped, "wrong-key");
    assert.equal(v.present, true);
    assert.equal(v.valid, false);
});

test("watermark: lookup-only mode (no key) returns tag without validating", () => {
    const stamped = watermark.injectInto("var x;", "release-99", "k");
    const v = watermark.verify(stamped, null);
    assert.equal(v.present, true);
    assert.equal(v.tag, "release-99");
    assert.equal(v.valid, false, "valid is false when no key was passed");
});

test("watermark: clean file (no marker) returns present=false", () => {
    const v = watermark.verify("var x = 1;", "k");
    assert.equal(v.present, false);
    assert.match(v.error, /marker not found/);
});

test("watermark: marker survives surrounding code (multi-line, regex anchors)", () => {
    // Simulate the obfuscator preserving the comment but injecting other content.
    const stamped = watermark.injectInto("function f() { return 1; }", "tag-A", "k");
    const fakeProtected = stamped + "\nvar _0xa1b2 = ['foo', 'bar'];\n";
    const v = watermark.verify(fakeProtected, "k");
    assert.equal(v.valid, true);
    assert.equal(v.tag, "tag-A");
});

test("watermark: unicode tags round-trip via base64url", () => {
    const src = "var x;";
    const tag = "リリース-2026-Q3-α";
    const stamped = watermark.injectInto(src, tag, "k");
    const v = watermark.verify(stamped, "k");
    assert.equal(v.tag, tag);
    assert.equal(v.valid, true);
});

// ---------- CLI: --verify-watermark ----------

function runCli(args) {
    return new Promise(resolve => {
        const c = spawn(process.execPath, [CLI, ...args]);
        let out = "", err = "";
        c.stdout.on("data", d => out += d.toString());
        c.stderr.on("data", d => err += d.toString());
        c.on("close", code => resolve({ code, out, err }));
    });
}

test("CLI --verify-watermark: valid file exits 0 with key", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "jso-wm-"));
    const file = path.join(tmp, "p.js");
    fs.writeFileSync(file, watermark.injectInto("var x;", "rel-1", "K"));
    try {
        const { code, out } = await runCli(["--verify-watermark", file, "--watermark-key", "K"]);
        assert.equal(code, 0);
        assert.match(out, /OK +.+: valid watermark, tag=rel-1/);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI --verify-watermark: wrong key exits 1", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "jso-wm-"));
    const file = path.join(tmp, "p.js");
    fs.writeFileSync(file, watermark.injectInto("var x;", "rel-2", "RIGHT"));
    try {
        const { code, out } = await runCli(["--verify-watermark", file, "--watermark-key", "WRONG"]);
        assert.equal(code, 1);
        assert.match(out, /FAIL .+ signature does NOT match/);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI --verify-watermark: missing marker exits 2", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "jso-wm-"));
    const file = path.join(tmp, "p.js");
    fs.writeFileSync(file, "var x = 1;");
    try {
        const { code, out } = await runCli(["--verify-watermark", file, "--watermark-key", "K"]);
        assert.equal(code, 2);
        assert.match(out, /FAIL .+ marker not found/);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("CLI --verify-watermark: --json prints structured envelope", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "jso-wm-"));
    const file = path.join(tmp, "p.js");
    fs.writeFileSync(file, watermark.injectInto("var x;", "rel-3", "K"));
    try {
        const { code, out } = await runCli(["--verify-watermark", file, "--watermark-key", "K", "--json"]);
        assert.equal(code, 0);
        const env = JSON.parse(out);
        assert.equal(env.valid, true);
        assert.equal(env.tag, "rel-3");
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

// ---------- CLI: --watermark end-to-end through mock obfuscation API ----------

function startMockObf() {
    return new Promise(resolve => {
        const srv = http.createServer((req, res) => {
            let body = "";
            req.on("data", c => body += c);
            req.on("end", () => {
                const parsed = JSON.parse(body);
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                    Type: "Succeed",
                    // The real obfuscator preserves the header comment because
                    // KeepComment=true; the mock just echoes FileCode unchanged
                    // which is functionally equivalent for the watermark-survival
                    // test (the bytes are what we care about).
                    Items: (parsed.Items || []).map(it => ({
                        FileName: it.FileName, FileCode: it.FileCode,
                    })),
                    Report: { BuildId: "wm-test" },
                    __requestEcho: parsed,    // for assertions
                }));
            });
        });
        srv.listen(0, "127.0.0.1", () => resolve(srv));
    });
}

test("CLI --watermark: injects header that obfuscation API receives", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-wm-"));
    fs.mkdirSync(path.join(root, "in"));
    fs.writeFileSync(path.join(root, "in", "app.js"), "var x = 1;");
    const srv = await startMockObf();
    let receivedSource = null;
    srv.on("request", req => {
        // capture is via the response body anyway; nothing to do here
    });
    // Wrap server to capture request body. Simpler: re-create with capture.
    srv.close();
    const cap = await new Promise(resolve => {
        const s = http.createServer((req, res) => {
            let body = "";
            req.on("data", c => body += c);
            req.on("end", () => {
                const parsed = JSON.parse(body);
                receivedSource = parsed.Items[0].FileCode;
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                    Type: "Succeed",
                    Items: parsed.Items.map(it => ({ FileName: it.FileName, FileCode: it.FileCode })),
                }));
            });
        });
        s.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
        const port = cap.address().port;
        const { code } = await runCli([
            "--input",  path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--watermark", "release-77", "--watermark-key", "S3CR3T",
        ]);
        assert.equal(code, 0);
        assert.ok(receivedSource, "mock server captured the request");
        assert.ok(receivedSource.includes("__jso_watermark_v1"),
                  "the source sent to the API carries the watermark marker");
        const v = watermark.verify(receivedSource, "S3CR3T");
        assert.equal(v.valid, true);
        assert.equal(v.tag, "release-77");

        // The mock echoes the source back, so the output file should also
        // verify. This proves the full CLI round-trip works.
        const outFile = path.join(root, "out", "app.js");
        assert.ok(fs.existsSync(outFile));
        const outV = watermark.verify(fs.readFileSync(outFile, "utf8"), "S3CR3T");
        assert.equal(outV.valid, true);
    } finally {
        cap.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("CLI --watermark without --watermark-key fails fast", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-wm-"));
    fs.mkdirSync(path.join(root, "in"));
    fs.writeFileSync(path.join(root, "in", "app.js"), "var x;");
    try {
        const { code, err, out } = await runCli([
            "--input",  path.join(root, "in"),
            "--output", path.join(root, "out"),
            "--api-key", "k", "--api-password", "p",
            "--endpoint", "http://127.0.0.1:1/HttpApi.ashx",   // unreachable; we should never get there
            "--watermark", "rel-x",
        ]);
        assert.notStrictEqual(code, 0);
        assert.match(err + out, /watermark.+requires.+watermark-key/i);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
