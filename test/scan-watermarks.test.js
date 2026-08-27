"use strict";

// Tests for `jso-protector --scan-watermarks <dir>`.
//
// Builds a fixture directory tree containing:
//   - watermarked files (valid signature)
//   - watermarked files (different key — invalid under our key)
//   - clean files (no marker)
//   - node_modules subtree (must be skipped)
//   - non-JS files (.txt — must be ignored)
//
// Then runs the CLI and asserts the report shape + exit codes.

const test       = require("node:test");
const assert     = require("node:assert");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const { spawn }  = require("node:child_process");
const watermark  = require("../watermark.js");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

function runCli(args) {
    return new Promise(resolve => {
        const c = spawn(process.execPath, [CLI, ...args]);
        let out = "", err = "";
        c.stdout.on("data", d => out += d.toString());
        c.stderr.on("data", d => err += d.toString());
        c.on("close", code => resolve({ code, out, err }));
    });
}

function makeFixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-scan-wm-"));
    // Two watermarked with key "K", one with key "OTHER", one clean.
    fs.writeFileSync(path.join(root, "a.js"),
        watermark.injectInto("var a;", "release-A", "K"));
    fs.mkdirSync(path.join(root, "sub"));
    fs.writeFileSync(path.join(root, "sub", "b.js"),
        watermark.injectInto("var b;", "release-B", "K"));
    fs.writeFileSync(path.join(root, "sub", "c.js"),
        watermark.injectInto("var c;", "from-other-build", "OTHER"));
    fs.writeFileSync(path.join(root, "clean.js"), "var clean = 1;");
    // node_modules subtree — must be skipped.
    fs.mkdirSync(path.join(root, "node_modules", "pkg"), { recursive: true });
    fs.writeFileSync(path.join(root, "node_modules", "pkg", "index.js"),
        watermark.injectInto("var nm;", "node-modules-tag", "K"));
    // Non-JS file with marker text — must be ignored (wrong extension).
    fs.writeFileSync(path.join(root, "notes.txt"),
        watermark.injectInto("note;", "txt-tag", "K"));
    return root;
}

test("scan: with --watermark-key validates each, OK/FAIL marks correct", async () => {
    const root = makeFixture();
    try {
        const { code, out } = await runCli(["--scan-watermarks", root, "--watermark-key", "K"]);
        // Mixed result: 2 valid, 1 invalid (c.js was signed with OTHER) -> exit 1
        assert.equal(code, 1, "any invalid signature should fail the gate");
        assert.match(out, /Watermarked: 3 +valid=2 +invalid=1/);
        assert.match(out, /\[OK\].+a\.js.+tag=release-A/);
        assert.match(out, /\[OK\].+b\.js.+tag=release-B/);
        assert.match(out, /\[FAIL\].+c\.js.+tag=from-other-build/);
        // node_modules must NOT be in the report
        assert.doesNotMatch(out, /node_modules/);
        // .txt extension must NOT be in the report
        assert.doesNotMatch(out, /notes\.txt/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("scan: without --watermark-key, lookup-only mode (no validation, exits 0)", async () => {
    const root = makeFixture();
    try {
        const { code, out } = await runCli(["--scan-watermarks", root]);
        // 3 watermarked files (a, b, c). No key -> all unverified. Exit 0.
        assert.equal(code, 0);
        assert.match(out, /Watermarked: 3/);
        assert.match(out, /no --watermark-key/);
        assert.match(out, /\[WM\].+a\.js.+tag=release-A/);
        assert.match(out, /\[WM\].+c\.js.+tag=from-other-build/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("scan: --json envelope is structured + sortable", async () => {
    const root = makeFixture();
    try {
        const { code, out } = await runCli(["--scan-watermarks", root, "--watermark-key", "K", "--json"]);
        assert.equal(code, 1);
        const env = JSON.parse(out);
        assert.equal(env.watermarked, 3);
        assert.equal(env.valid, 2);
        assert.equal(env.invalid, 1);
        assert.equal(env.keyProvided, true);
        // Files sorted alphabetically for diff-friendly output.
        const names = env.files.map(f => f.file);
        const sorted = [...names].sort();
        assert.deepEqual(names, sorted);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("scan: empty directory exits 2 (no watermarks found)", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-scan-wm-empty-"));
    try {
        const { code, out } = await runCli(["--scan-watermarks", root, "--watermark-key", "K"]);
        assert.equal(code, 2);
        assert.match(out, /Scanned 0 JS file/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("scan: clean directory (JS files but no watermarks) exits 2", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "jso-scan-wm-clean-"));
    fs.writeFileSync(path.join(root, "x.js"), "var x = 1;");
    fs.writeFileSync(path.join(root, "y.js"), "var y = 2;");
    try {
        const { code, out } = await runCli(["--scan-watermarks", root]);
        assert.equal(code, 2);
        assert.match(out, /Scanned 2 JS file/);
        assert.match(out, /Watermarked: 0/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("scan: missing directory exits non-zero with clear error", async () => {
    const { code, err } = await runCli(["--scan-watermarks", "/no/such/dir/here"]);
    assert.notStrictEqual(code, 0);
    assert.match(err, /directory not found/);
});

test("scan: --watermark-key via JSO_WATERMARK_KEY env works", async () => {
    const root = makeFixture();
    try {
        // Re-spawn with env set.
        const c = spawn(process.execPath, [CLI, "--scan-watermarks", root],
            { env: { ...process.env, JSO_WATERMARK_KEY: "K" } });
        let out = "";
        c.stdout.on("data", d => out += d.toString());
        const code = await new Promise(r => c.on("close", r));
        // 2 valid, 1 invalid -> exit 1 (key was active)
        assert.equal(code, 1);
        assert.match(out, /valid=2 +invalid=1/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
