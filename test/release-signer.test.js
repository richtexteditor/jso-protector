"use strict";

// Tests for the Ed25519 release-signer module + the CLI flags.
// Three layers:
//   - direct module tests (canonicalize is deterministic, sign+verify
//     roundtrip, tampering detected, wrong key rejected, file re-hash
//     stage catches post-signing artifact tampering)
//   - CLI --genkey-release writes a usable keypair
//   - CLI --sign-release / --verify-release end-to-end against a mock
//     obfuscation server

const test       = require("node:test");
const assert     = require("node:assert");
const http       = require("node:http");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const crypto     = require("node:crypto");
const { spawn }  = require("node:child_process");
const signer     = require("../release-signer.js");

const CLI = path.resolve(__dirname, "..", "bin", "jso-protector.js");

function tmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

// ---------- module: canonicalize ----------

test("canonicalize: sorts keys and is whitespace-stable", () => {
    const a = signer.canonicalize({ b: 1, a: 2, c: { z: 9, y: 8 } });
    const b = signer.canonicalize({ a: 2, c: { y: 8, z: 9 }, b: 1 });
    assert.equal(a, b, "same object different key order produces same bytes");
    assert.equal(a, '{"a":2,"b":1,"c":{"y":8,"z":9}}');
});

test("canonicalize: arrays preserve order", () => {
    const a = signer.canonicalize([3, 1, 2]);
    assert.equal(a, "[3,1,2]");
});

// ---------- module: sign + verify ----------

test("signRelease + verifyRelease: happy path round-trip", () => {
    const { publicKeyPem, privateKeyPem } = signer.generateKeyPair();
    const env = signer.signRelease({
        buildId: "build-1", polymorphismFingerprint: "fp-1", label: "v1.2.3",
        files: [{ name: "app.js", sha256: "deadbeef" }],
    }, privateKeyPem);
    assert.equal(env.v, 1);
    assert.ok(env.signature, "envelope has a signature");
    const r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem });
    assert.equal(r.valid, true);
    assert.equal(r.stage1, true);
});

test("verifyRelease: detects manifest tampering", () => {
    const { publicKeyPem, privateKeyPem } = signer.generateKeyPair();
    const env = signer.signRelease({
        buildId: "b1", label: "v1",
        files: [{ name: "a.js", sha256: "h1" }],
    }, privateKeyPem);
    // Mutate the embedded manifest after signing.
    env.manifest.files[0].sha256 = "tampered";
    const r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem });
    assert.equal(r.valid, false);
    assert.equal(r.stage1, false);
    assert.match(r.error, /signature does not match/);
});

test("verifyRelease: --public-key pin rejects substituted pubkey", () => {
    const a = signer.generateKeyPair();
    const b = signer.generateKeyPair();
    // Sign with B but pin to A.
    const env = signer.signRelease({ files: [] }, b.privateKeyPem);
    const r = signer.verifyRelease(env, { expectedPublicKeyPem: a.publicKeyPem });
    assert.equal(r.valid, false);
    assert.match(r.error, /does not match --public-key/);
});

test("verifyRelease: signature-only mode trusts embedded pubkey", () => {
    const { privateKeyPem } = signer.generateKeyPair();
    const env = signer.signRelease({ files: [] }, privateKeyPem);
    const r = signer.verifyRelease(env);
    assert.equal(r.valid, true, "no pin = trust embedded pubkey for sig verification");
});

test("verifyRelease: stage2 catches modified files on disk", () => {
    const dir = tmp("rs-");
    const file = path.join(dir, "app.js");
    fs.writeFileSync(file, "original");
    const origHash = signer.sha256OfFile(file);

    const { publicKeyPem, privateKeyPem } = signer.generateKeyPair();
    const env = signer.signRelease({
        files: [{ name: "app.js", sha256: origHash }],
    }, privateKeyPem);

    // First: untouched files pass.
    let r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem, fileRoot: dir });
    assert.equal(r.valid, true);
    assert.equal(r.stage2, true);

    // Then: tamper the artifact and re-verify.
    fs.writeFileSync(file, "tampered");
    r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem, fileRoot: dir });
    assert.equal(r.valid, false);
    assert.equal(r.stage1, true, "signature still verifies — manifest itself untouched");
    assert.equal(r.stage2, false);
    assert.equal(r.mismatches.length, 1);
    assert.equal(r.mismatches[0].name, "app.js");

    fs.rmSync(dir, { recursive: true, force: true });
});

test("verifyRelease: missing referenced file is reported", () => {
    const dir = tmp("rs-");
    const { publicKeyPem, privateKeyPem } = signer.generateKeyPair();
    const env = signer.signRelease({
        files: [{ name: "ghost.js", sha256: "deadbeef" }],
    }, privateKeyPem);
    const r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem, fileRoot: dir });
    assert.equal(r.valid, false);
    assert.equal(r.mismatches[0].missing, true);
    fs.rmSync(dir, { recursive: true, force: true });
});

test("signRelease: rejects non-Ed25519 keys", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" });
    assert.throws(
        () => signer.signRelease({ files: [] }, pem),
        /not Ed25519/);
});

// ---------- CLI ----------

function runCli(args) {
    return new Promise(resolve => {
        const c = spawn(process.execPath, [CLI, ...args]);
        let out = "", err = "";
        c.stdout.on("data", d => out += d.toString());
        c.stderr.on("data", d => err += d.toString());
        c.on("close", code => resolve({ code, out, err }));
    });
}

test("CLI --genkey-release: writes usable .priv.pem + .pub.pem", async () => {
    const dir = tmp("rs-key-");
    const base = path.join(dir, "ci");
    try {
        const { code } = await runCli(["--genkey-release", base]);
        assert.equal(code, 0);
        assert.ok(fs.existsSync(base + ".priv.pem"));
        assert.ok(fs.existsSync(base + ".pub.pem"));
        // Round-trip: sign with the new key, verify with its pub.
        const priv = fs.readFileSync(base + ".priv.pem", "utf8");
        const pub  = fs.readFileSync(base + ".pub.pem",  "utf8");
        const env = signer.signRelease({ files: [] }, priv);
        const r = signer.verifyRelease(env, { expectedPublicKeyPem: pub });
        assert.equal(r.valid, true);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

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
                    Items: (parsed.Items || []).map(it => ({
                        FileName: it.FileName, FileCode: it.FileCode,
                    })),
                    Report: {
                        BuildId: "test-build-42",
                        PolymorphismFingerprint: "fp-abc",
                    },
                }));
            });
        });
        srv.listen(0, "127.0.0.1", () => resolve(srv));
    });
}

test("CLI --sign-release: writes .manifest.json.sig, --verify-release validates it", async () => {
    const root = tmp("rs-e2e-");
    fs.mkdirSync(path.join(root, "in"));
    fs.writeFileSync(path.join(root, "in", "app.js"), "var x = 1;");

    // Generate a keypair to use for the build.
    const keyBase = path.join(root, "key");
    let r = await runCli(["--genkey-release", keyBase]);
    assert.equal(r.code, 0);

    const srv = await startMockObf();
    try {
        const port = srv.address().port;
        const out  = path.join(root, "out");
        const manifestPath = path.join(out, "build.manifest.json");
        const { code, err } = await runCli([
            "--input",  path.join(root, "in"),
            "--output", out,
            "--manifest", manifestPath,
            "--endpoint", `http://127.0.0.1:${port}/HttpApi.ashx`,
            "--api-key", "k", "--api-password", "p",
            "--label", "v1.0.0",
            "--sign-release", keyBase + ".priv.pem",
        ]);
        assert.equal(code, 0, "build failed: " + err);

        const sigPath = manifestPath + ".sig";
        assert.ok(fs.existsSync(sigPath), "sig file produced next to manifest");
        const env = JSON.parse(fs.readFileSync(sigPath, "utf8"));
        assert.equal(env.v, 1);
        assert.equal(env.manifest.buildId, "test-build-42");
        assert.equal(env.manifest.polymorphismFingerprint, "fp-abc");
        assert.equal(env.manifest.label, "v1.0.0");
        assert.equal(env.manifest.files.length, 1);
        assert.equal(env.manifest.files[0].name, "app.js");

        // Verify with the public key + file-root: should pass cleanly.
        const verify = await runCli([
            "--verify-release", sigPath,
            "--public-key", keyBase + ".pub.pem",
            "--verify-root", out,
        ]);
        assert.equal(verify.code, 0, "fresh artifact should verify clean");
        assert.match(verify.out, /OK +.+: signature valid/);

        // Tamper one output file post-signing; verify should fail stage 2.
        fs.writeFileSync(path.join(out, "app.js"), "TAMPERED");
        const verifyBad = await runCli([
            "--verify-release", sigPath,
            "--public-key", keyBase + ".pub.pem",
            "--verify-root", out,
        ]);
        assert.equal(verifyBad.code, 1, "tampered artifact should fail");
        assert.match(verifyBad.out, /FAIL/);
        assert.match(verifyBad.out, /app\.js/);
    } finally {
        srv.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("CLI --verify-release: signature-only verification (no --verify-root)", async () => {
    const root = tmp("rs-sigonly-");
    const keyBase = path.join(root, "key");
    let r = await runCli(["--genkey-release", keyBase]);
    assert.equal(r.code, 0);

    // Build a sig file by hand (no obfuscation needed).
    const env = signer.signRelease({
        buildId: "b", files: [{ name: "x.js", sha256: "abc" }],
    }, fs.readFileSync(keyBase + ".priv.pem", "utf8"));
    const sigPath = path.join(root, "sig.json");
    fs.writeFileSync(sigPath, JSON.stringify(env));

    try {
        const v = await runCli([
            "--verify-release", sigPath,
            "--public-key", keyBase + ".pub.pem",
        ]);
        assert.equal(v.code, 0);
        assert.match(v.out, /signature valid/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
