"use strict";

// Wire-format conformance vectors.
//
// These tests pin specific byte-level outputs that any new client port
// (Go/Ruby/Java/Kotlin/Rust/PHP/...) must reproduce exactly. They are
// the "is your implementation correct?" smoke for the formats
// documented at /Docs/WireFormat.aspx#watermark and #release-attestation.
//
// If anything here breaks, do NOT fix the test — the wire format is a
// public contract. The fix is to bump the version (v1 -> v2) and ship
// both clients until customers have migrated.

const test       = require("node:test");
const assert     = require("node:assert");
const watermark  = require("../watermark.js");
const signer     = require("../release-signer.js");

// ---------- watermark vectors ----------

// These three vectors cover ASCII, multi-byte UTF-8, and an empty
// source. Implementations should produce byte-for-byte identical
// header blocks from the same (tag, key) inputs.
const WATERMARK_VECTORS = [
    {
        name: "ASCII tag + ASCII key",
        tag:  "release-2026-Q3",
        key:  "very-secret-key",
        // Pre-computed: HMAC-SHA256(key="very-secret-key", tag="release-2026-Q3")
        // base64url over UTF-8 of "release-2026-Q3":
        tagB64: "cmVsZWFzZS0yMDI2LVEz",
    },
    {
        name: "Unicode tag (Japanese + Greek)",
        tag:  "リリース-2026-Q3-α",
        key:  "secret",
        // base64url(UTF-8 bytes of the tag)
        tagB64: "44Oq44Oq44O844K5LTIwMjYtUTMtzrE",
    },
    {
        name: "single-character tag",
        tag:  "X",
        key:  "k",
        tagB64: "WA",
    },
];

for (const v of WATERMARK_VECTORS) {
    test("wire vector: watermark — " + v.name, () => {
        const header = watermark.buildHeader(v.tag, v.key);
        // First line must be the literal marker prefix.
        assert.ok(header.startsWith("/*! __jso_watermark_v1\n"),
                  "header starts with marker token: " + JSON.stringify(header.slice(0, 30)));
        // The embedded tag is base64url-no-padding over the UTF-8 bytes.
        assert.ok(header.includes(" * tag: " + v.tagB64 + "\n"),
                  "expected tag line ' * tag: " + v.tagB64 + "', got: " + header);
        // signTag is deterministic; recompute and confirm it lands in the header.
        const sig = watermark.signTag(v.tag, v.key);
        assert.ok(header.includes(" * sig: " + sig + "\n"),
                  "expected sig line in header");
        // Round-trip: verify() must accept what buildHeader() produced.
        const r = watermark.verify(header, v.key);
        assert.equal(r.present, true);
        assert.equal(r.valid, true);
        assert.equal(r.tag, v.tag);
    });
}

test("wire vector: watermark base64url alphabet has no +/= chars", () => {
    // base64url uses '-' and '_' instead of '+' and '/', and strips
    // padding. A correct implementation never emits '+', '/', or '='
    // in the tag or sig fields.
    const tag = "tag-with-bytes-that-might-collide+/";
    const header = watermark.buildHeader(tag, "k");
    const tagLine = /\* tag: (\S+)/.exec(header)[1];
    const sigLine = /\* sig: (\S+)/.exec(header)[1];
    assert.doesNotMatch(tagLine, /[+/=]/, "tag uses url-safe alphabet");
    assert.doesNotMatch(sigLine, /[+/=]/, "sig uses url-safe alphabet");
});

// ---------- release-attestation vectors ----------

test("wire vector: canonical JSON sorts object keys and strips whitespace", () => {
    // Pin the canonical-JSON shape implementers must produce.
    assert.equal(
        signer.canonicalize({ b: 2, a: 1 }),
        '{"a":1,"b":2}');
    assert.equal(
        signer.canonicalize({ z: { y: 2, x: 1 }, a: 0 }),
        '{"a":0,"z":{"x":1,"y":2}}');
    assert.equal(
        signer.canonicalize([3, 1, 2]),
        "[3,1,2]",
        "arrays preserve order — only object keys get sorted");
    assert.equal(
        signer.canonicalize("hello"),
        '"hello"');
    assert.equal(
        signer.canonicalize(null),
        "null");
});

test("wire vector: canonical JSON is identical regardless of input key order", () => {
    const a = signer.canonicalize({ buildId: "b", label: "L", files: [{ name: "x", sha256: "h" }] });
    const b = signer.canonicalize({ files: [{ sha256: "h", name: "x" }], label: "L", buildId: "b" });
    assert.equal(a, b, "same content, any input order -> same bytes");
});

test("wire vector: release envelope is verifiable end-to-end", () => {
    // Generate, sign, verify — pin the envelope shape.
    const { publicKeyPem, privateKeyPem } = signer.generateKeyPair();
    const env = signer.signRelease({
        buildId: "test-build-1",
        polymorphismFingerprint: "fp-abc",
        label: "v1.0.0",
        files: [
            { name: "a.js", sha256: "0".repeat(64) },
            { name: "b.js", sha256: "f".repeat(64) },
        ],
    }, privateKeyPem);
    // Required envelope fields, exact names:
    assert.equal(env.v, 1, "v field is 1");
    assert.ok(env.signedAt, "signedAt is set");
    assert.ok(env.manifest, "manifest subobject present");
    assert.ok(env.publicKey, "publicKey (base64 SPKI DER) present");
    assert.ok(env.signature, "signature (base64) present");
    // Manifest preserves the input keys exactly:
    assert.equal(env.manifest.buildId, "test-build-1");
    assert.equal(env.manifest.polymorphismFingerprint, "fp-abc");
    assert.equal(env.manifest.label, "v1.0.0");
    assert.equal(env.manifest.files.length, 2);
    // Signature must round-trip with the embedded pubkey.
    const r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem });
    assert.equal(r.valid, true);
    assert.equal(r.stage1, true);
});

test("wire vector: tampering ANY manifest field breaks the signature", () => {
    // Fuzz a few mutations to confirm the canonical encoding covers them.
    const { publicKeyPem, privateKeyPem } = signer.generateKeyPair();
    const baseFields = {
        buildId: "b1",
        polymorphismFingerprint: "fp",
        label: "v1",
        files: [{ name: "a.js", sha256: "h" }],
    };
    const mutations = [
        env => { env.manifest.buildId = "b2"; },
        env => { env.manifest.polymorphismFingerprint = "fp2"; },
        env => { env.manifest.label = "v2"; },
        env => { env.manifest.files[0].name = "b.js"; },
        env => { env.manifest.files[0].sha256 = "h2"; },
        env => { env.manifest.files.push({ name: "c.js", sha256: "h" }); },
    ];
    for (const mutate of mutations) {
        const env = signer.signRelease(baseFields, privateKeyPem);
        mutate(env);
        const r = signer.verifyRelease(env, { expectedPublicKeyPem: publicKeyPem });
        assert.equal(r.valid, false, "mutation should invalidate signature");
    }
});
