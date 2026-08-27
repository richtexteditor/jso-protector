"use strict";

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const ef = require("../compliance/evidence-forwarder.js");

// A representative PCI reporter JSON (subset of the real shape).
function sampleReport() {
    return {
        standard: "PCI DSS",
        version: "4.0.1",
        organizationName: "Example Corp",
        buildId: "build-2026-06-02-abc",
        buildLabel: "v1.2.3",
        generatedAt: "2026-06-02T12:00:00Z",
        summary: { pass: 5, partial: 1, fail: 0, exitCode: 1 },
        controls: [
            { id: "6.4.3", title: "Payment page scripts", status: "pass",
              subRequirements: [{ id: "6.4.3.a", status: "pass", detail: "watermarks valid" }] },
            { id: "11.6.1", title: "Tamper detection", status: "partial",
              subRequirements: [{ id: "11.6.1.c", status: "partial", detail: "no SIEM named" }] },
        ],
    };
}

// Capturing transport: records the POST and returns a canned response.
function capturingTransport(canned) {
    const calls = [];
    const fn = function (endpoint, rawBody, headers) {
        calls.push({ endpoint, rawBody, headers });
        return Promise.resolve(canned || { ok: true, status: 200, body: "{}" });
    };
    fn.calls = calls;
    return fn;
}

test("buildArtifact: normalizes report + adds stable sha256", function () {
    const a = ef.buildArtifact(sampleReport());
    assert.equal(a.source, "jso-protector");
    assert.equal(a.standard, "PCI DSS");
    assert.equal(a.buildId, "build-2026-06-02-abc");
    assert.equal(a.controls.length, 2);
    assert.match(a.artifactSha256, /^[a-f0-9]{64}$/);
    // Deterministic: same input -> same hash.
    const b = ef.buildArtifact(sampleReport());
    assert.equal(a.artifactSha256, b.artifactSha256);
});

test("buildArtifact: changing any control flips the hash", function () {
    const a = ef.buildArtifact(sampleReport());
    const mutated = sampleReport();
    mutated.controls[0].status = "fail";
    const b = ef.buildArtifact(mutated);
    assert.notEqual(a.artifactSha256, b.artifactSha256);
});

test("buildArtifact: throws on non-object report", function () {
    assert.throws(function () { ef.buildArtifact(null); }, /report object is required/);
});

test("forward: requires an endpoint (never throws)", async function () {
    const forward = ef.createEvidenceForwarder({ profile: "generic" });
    const res = await forward(sampleReport());
    assert.equal(res.ok, false);
    assert.equal(res.status, 0);
    assert.match(res.error, /endpoint is required/);
});

test("forward: generic profile posts the artifact as-is", async function () {
    const t = capturingTransport();
    const forward = ef.createEvidenceForwarder({ profile: "generic", endpoint: "https://grc.example/evidence", transport: t });
    const res = await forward(sampleReport());
    assert.equal(res.ok, true);
    assert.equal(res.status, 200);
    assert.equal(res.profile, "generic");
    const body = JSON.parse(t.calls[0].rawBody);
    assert.equal(body.source, "jso-protector");
    assert.equal(body.standard, "PCI DSS");
    assert.match(body.artifactSha256, /^[a-f0-9]{64}$/);
});

test("forward: generic profile with secret signs the body (verifiable HMAC)", async function () {
    const t = capturingTransport();
    const secret = "grc-shared-secret";
    const forward = ef.createEvidenceForwarder({ profile: "generic", endpoint: "https://grc.example/x", secret: secret, transport: t });
    await forward(sampleReport());
    const h = t.calls[0].headers;
    const ts = h["X-JSO-Timestamp"];
    const sig = h["X-JSO-Signature"];
    assert.ok(ts, "timestamp header present");
    assert.match(sig, /^sha256=[a-f0-9]{64}$/);
    // Re-derive and confirm.
    const expected = "sha256=" + crypto.createHmac("sha256", secret).update(ts + "." + t.calls[0].rawBody).digest("hex");
    assert.equal(sig, expected);
});

test("forward: drata profile wraps in name/controls/evidence + bearer", async function () {
    const t = capturingTransport();
    const forward = ef.createEvidenceForwarder({ profile: "drata", endpoint: "https://api.drata.example/v1/evidence", token: "drata-tok", transport: t });
    await forward(sampleReport());
    const body = JSON.parse(t.calls[0].rawBody);
    assert.ok(body.name.indexOf("PCI DSS") >= 0);
    assert.deepEqual(body.controls, ["6.4.3", "11.6.1"]);
    assert.equal(body.evidence.source, "jso-protector");
    assert.equal(t.calls[0].headers["Authorization"], "Bearer drata-tok");
});

test("forward: vanta profile wraps in resourceId/testIds/document + bearer", async function () {
    const t = capturingTransport();
    const forward = ef.createEvidenceForwarder({ profile: "vanta", endpoint: "https://api.vanta.example/v1/evidence", token: "vanta-tok", transport: t });
    await forward(sampleReport());
    const body = JSON.parse(t.calls[0].rawBody);
    assert.equal(body.resourceId, "build-2026-06-02-abc");
    assert.deepEqual(body.testIds, ["6.4.3", "11.6.1"]);
    assert.equal(body.document.source, "jso-protector");
    assert.equal(t.calls[0].headers["Authorization"], "Bearer vanta-tok");
});

test("forward: fieldMap overrides envelope key names", async function () {
    const t = capturingTransport();
    const forward = ef.createEvidenceForwarder({
        profile: "drata", endpoint: "https://x", token: "t", transport: t,
        fieldMap: { name: "title", controls: "controlCodes", evidence: "payload" },
    });
    await forward(sampleReport());
    const body = JSON.parse(t.calls[0].rawBody);
    assert.ok(body.title, "name -> title");
    assert.ok(Array.isArray(body.controlCodes), "controls -> controlCodes");
    assert.ok(body.payload, "evidence -> payload");
});

test("forward: unknown profile falls back to generic", async function () {
    const t = capturingTransport();
    const forward = ef.createEvidenceForwarder({ profile: "servicenow", endpoint: "https://x", transport: t });
    const res = await forward(sampleReport());
    assert.equal(res.profile, "generic");
});

test("forward: transport failure surfaces as ok:false status:0, never throws", async function () {
    const failing = function () { return Promise.resolve({ ok: false, status: 0, error: "ECONNREFUSED" }); };
    const forward = ef.createEvidenceForwarder({ profile: "generic", endpoint: "https://down.example", transport: failing });
    const res = await forward(sampleReport());
    assert.equal(res.ok, false);
    assert.equal(res.status, 0);
    assert.equal(res.error, "ECONNREFUSED");
});

test("forward: transport that throws is caught, not propagated", async function () {
    const thrower = function () { throw new Error("boom"); };
    const forward = ef.createEvidenceForwarder({ profile: "generic", endpoint: "https://x", transport: thrower });
    const res = await forward(sampleReport());
    assert.equal(res.ok, false);
    assert.equal(res.error, "boom");
});

test("forward: non-2xx status reports ok:false but keeps the status code", async function () {
    const t = capturingTransport({ ok: false, status: 403, body: "forbidden" });
    const forward = ef.createEvidenceForwarder({ profile: "drata", endpoint: "https://x", token: "bad", transport: t });
    const res = await forward(sampleReport());
    assert.equal(res.ok, false);
    assert.equal(res.status, 403);
});

test("canonicalize: stable regardless of key order", function () {
    const a = ef._canonicalize({ b: 1, a: 2, c: [3, { y: 1, x: 2 }] });
    const b = ef._canonicalize({ c: [3, { x: 2, y: 1 }], a: 2, b: 1 });
    assert.equal(a, b);
});
