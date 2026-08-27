"use strict";

// Tests for `jso-protector --local`, the source-local bridge.
//
// The bridge's contract is narrow and worth pinning exactly: write the SAME
// payload the hosted path would POST, hand it to jso-local, and read back the
// SAME response shape the hosted endpoint returns. So these tests drive the
// real CLI end to end against a STUB protector that records what it was given.
//
// A stub, not the real jso-local.exe, on purpose: the real executable needs a
// paid account and a network round-trip for its plan check, which would make
// this test non-deterministic and unrunnable on a build agent. The real
// executable's own protection is covered by tools/local-report,
// tools/mixedfile-protect and the desktop archive gate, which execute it.
// What is genuinely this layer's job - payload contents, argument order,
// response parsing, credential/source hygiene, failure surfacing - is what a
// stub can prove, and does here.

const test   = require("node:test");
const assert = require("node:assert");
const fs     = require("node:fs");
const path   = require("node:path");
const os     = require("node:os");
const { spawnSync } = require("node:child_process");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

function workspace() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jso-local-bridge-"));
    fs.mkdirSync(path.join(dir, "dist"), { recursive: true });
    fs.writeFileSync(path.join(dir, "dist", "app.js"),
        "function greet(){ var message = 'hello'; return message; } console.log(greet());", "utf8");
    return dir;
}

// A stub jso-local: copies the request it was handed to a known path (so the
// test can assert on it) and writes a canned hosted-shaped response.
function writeStub(dir, { body = null, exitCode = 0, writeResponse = true } = {}) {
    const recorded = path.join(dir, "recorded-request.json");
    const script = path.join(dir, "stub.js");
    fs.writeFileSync(script, `
const fs = require("fs");
const args = process.argv.slice(2);
const payloadPath = args[args.indexOf("--http-project") + 1];
const responsePath = args[args.indexOf("--response") + 1];
fs.copyFileSync(payloadPath, ${JSON.stringify(recorded)});
const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
const body = ${body ? JSON.stringify(body) : "null"} || {
  Type: "Succeed",
  Items: (payload.Items || []).map((item) => ({
    FileName: item.FileName,
    FileCode: "/* stub-protected */" + String(item.FileCode || "").replace(/message/g, "m0")
  })),
  ErrorCode: null, Message: null, FileName: null, LineNumber: null,
  ExceptionToString: null, Report: { PolymorphismFingerprint: "0123456789abcdef" }
};
${writeResponse ? 'fs.writeFileSync(responsePath, JSON.stringify(body), "utf8");' : ""}
process.exit(${exitCode});
`, "utf8");

    let exe;
    if (process.platform === "win32") {
        exe = path.join(dir, "stub.cmd");
        fs.writeFileSync(exe, `@echo off\r\nnode "${script}" %*\r\n`, "utf8");
    } else {
        exe = path.join(dir, "stub.sh");
        fs.writeFileSync(exe, `#!/bin/sh\nexec node "${script}" "$@"\n`, "utf8");
        fs.chmodSync(exe, 0o755);
    }
    return { exe, recorded };
}

function runCli(dir, args, env = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
        cwd: dir,
        encoding: "utf8",
        env: { ...process.env, JSO_API_KEY: "dGVzdC1jb2RlOjQy", JSO_API_PASSWORD: "c2VjcmV0", ...env }
    });
}

test("--local sends the hosted payload to jso-local and writes its output", () => {
    const dir = workspace();
    const { exe, recorded } = writeStub(dir);

    const run = runCli(dir, ["--input", "dist", "--output", "out", "--local", "--local-exe", exe]);
    assert.strictEqual(run.status, 0, `CLI failed: ${run.stderr || run.stdout}`);

    // The protected file came from the stub, so the local transport really ran.
    const output = fs.readFileSync(path.join(dir, "out", "app.js"), "utf8");
    assert.match(output, /stub-protected/);

    // The payload is the hosted request shape, credentials and all.
    const payload = JSON.parse(fs.readFileSync(recorded, "utf8"));
    assert.strictEqual(payload.APIKey, "dGVzdC1jb2RlOjQy");
    assert.strictEqual(payload.APIPwd, "c2VjcmV0");
    assert.ok(Array.isArray(payload.Items) && payload.Items.length === 1, "payload carries Items");
    assert.strictEqual(payload.Items[0].FileName, "app.js");
    assert.match(payload.Items[0].FileCode, /function greet/);
    // Preset options travel too - a local build must not silently protect less.
    assert.ok(Object.keys(payload).some((key) => /^[A-Z]/.test(key) && !["APIKey", "APIPwd", "Name", "Items", "MixedServer"].includes(key)),
        "payload carries engine options");
});

test("--local reads JSO_LOCAL_EXE when no --local-exe is given", () => {
    const dir = workspace();
    const { exe } = writeStub(dir);

    const run = runCli(dir, ["--input", "dist", "--output", "out", "--local"], { JSO_LOCAL_EXE: exe });
    assert.strictEqual(run.status, 0, `CLI failed: ${run.stderr || run.stdout}`);
    assert.match(fs.readFileSync(path.join(dir, "out", "app.js"), "utf8"), /stub-protected/);
});

test("--local surfaces a protector error instead of writing output", () => {
    const dir = workspace();
    const { exe } = writeStub(dir, {
        body: {
            Type: "Error",
            ErrorCode: "LocalUnsupportedOption",
            Message: "VM bytecode protection is hosted-only and cannot run locally.",
            Items: null
        },
        exitCode: 1
    });

    const run = runCli(dir, ["--input", "dist", "--output", "out", "--local", "--local-exe", exe]);
    assert.notStrictEqual(run.status, 0, "CLI must fail when the protector reports an error");
    assert.match(run.stderr + run.stdout, /hosted-only/);
    assert.ok(!fs.existsSync(path.join(dir, "out", "app.js")), "no output file on failure");
});

test("--local explains how to get jso-local when it is missing", () => {
    const dir = workspace();
    const run = runCli(dir, ["--input", "dist", "--output", "out", "--local", "--local-exe", path.join(dir, "nope.exe")]);
    assert.notStrictEqual(run.status, 0);
    assert.match(run.stderr + run.stdout, /jso-local/);
});

test("--local leaves no temp copy of the source or credentials behind", () => {
    const dir = workspace();
    const { exe, recorded } = writeStub(dir);
    const before = fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("jso-local-"));

    const run = runCli(dir, ["--input", "dist", "--output", "out", "--local", "--local-exe", exe]);
    assert.strictEqual(run.status, 0, `CLI failed: ${run.stderr || run.stdout}`);

    // The stub proves a payload existed; the bridge must still have removed it.
    assert.ok(fs.existsSync(recorded), "stub recorded a payload");
    const after = fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("jso-local-"));
    assert.deepStrictEqual(after, before, "the bridge's temp directory was not cleaned up");
});
