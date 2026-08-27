"use strict";

// Compliance evidence forwarder — pushes a generated compliance report
// (e.g. the PCI DSS v4 reporter's JSON output) to a GRC platform as an
// evidence artifact, so the per-build report that already exists also
// lands in Drata / Vanta / an in-house GRC system without a manual
// upload step.
//
// Design stance (read before extending)
// --------------------------------------
// GRC platforms are multi-tenant: the evidence-upload endpoint and the
// API token are per-customer values the operator supplies. This module
// therefore does NOT hardcode a vendor API version or base URL it can't
// keep current. Instead a `profile` shapes the outbound ENVELOPE and
// HEADERS, and the operator passes the tenant `endpoint` + `token`.
// That keeps the forwarder honest (no pretending to track an external
// API we don't control) and stable (a vendor field rename is a config
// override, not a code change).
//
// Three profiles:
//   "generic" — POST the normalized artifact as-is, optionally HMAC-
//               signed exactly like the jso-beacon-slack webhook adapter
//               (X-JSO-Signature: sha256=<hex> over `<ts>.<body>`).
//   "drata"   — wrap the artifact in a { name, controls[], evidence{} }
//               shape, Authorization: Bearer <token>.
//   "vanta"   — wrap in a { resourceId, testIds[], document{} } shape,
//               Authorization: Bearer <token>.
// Field names per profile are overridable via `fieldMap` so an operator
// can match their tenant's exact contract.
//
// Contract (mirrors the SIEM adapters): the returned function never
// throws — transport/validation failures resolve to
// { ok:false, status:0, error } so a flaky GRC endpoint can't abort a
// build's reporting step.

const https = require("node:https");
const http = require("node:http");
const { URL } = require("node:url");
const crypto = require("node:crypto");

const SIGNATURE_HEADER = "X-JSO-Signature";
const TIMESTAMP_HEADER = "X-JSO-Timestamp";
const USER_AGENT = "jso-protector/evidence-forwarder";
const PROFILES = ["generic", "drata", "vanta"];

// Normalize a compliance report (the PCI reporter's `json` object, or
// any report carrying {standard, version, controls[], summary}) into a
// vendor-neutral evidence artifact. Deterministic + side-effect free so
// it is trivially testable and the sha256 below is reproducible.
function buildArtifact(report, opts) {
    opts = opts || {};
    if (!report || typeof report !== "object") {
        throw new Error("evidence-forwarder: report object is required");
    }
    const controls = Array.isArray(report.controls) ? report.controls.map(function (c) {
        return {
            id: c.id,
            title: c.title || null,
            status: c.status || null,
            subRequirements: Array.isArray(c.subRequirements)
                ? c.subRequirements.map(function (s) { return { id: s.id, status: s.status, detail: s.detail || null }; })
                : [],
        };
    }) : [];

    const artifact = {
        source: "jso-protector",
        standard: report.standard || null,
        version: report.version || null,
        organizationName: report.organizationName || opts.organizationName || null,
        buildId: report.buildId || null,
        buildLabel: report.buildLabel || null,
        generatedAt: report.generatedAt || opts.now || null,
        summary: report.summary || null,
        controls: controls,
    };
    // Stable content hash over the canonical artifact (sorted keys), so
    // the GRC side can dedupe re-uploads of the same evidence.
    const canonical = canonicalize(artifact);
    artifact.artifactSha256 = crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
    return artifact;
}

// Minimal canonical JSON (sorted keys, no whitespace) — same idea as
// release-signer's canonicalize, kept local to avoid a cross-module dep.
function canonicalize(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
    const keys = Object.keys(value).sort();
    return "{" + keys.map(function (k) { return JSON.stringify(k) + ":" + canonicalize(value[k]); }).join(",") + "}";
}

// Shape the outbound body + headers for a profile. Returns { body, headers }.
function shapeRequest(profile, artifact, config) {
    const fieldMap = config.fieldMap || {};
    let body, headers = { "Content-Type": "application/json", "User-Agent": USER_AGENT };

    if (profile === "drata") {
        body = {
            [fieldMap.name || "name"]: (artifact.standard || "Compliance") + " evidence — build " + (artifact.buildLabel || artifact.buildId || "unlabeled"),
            [fieldMap.controls || "controls"]: artifact.controls.map(function (c) { return c.id; }),
            [fieldMap.evidence || "evidence"]: artifact,
        };
        if (config.token) headers["Authorization"] = "Bearer " + config.token;
    } else if (profile === "vanta") {
        body = {
            [fieldMap.resourceId || "resourceId"]: artifact.buildId || artifact.artifactSha256,
            [fieldMap.testIds || "testIds"]: artifact.controls.map(function (c) { return c.id; }),
            [fieldMap.document || "document"]: artifact,
        };
        if (config.token) headers["Authorization"] = "Bearer " + config.token;
    } else {
        // generic — artifact as-is, optional bearer, optional HMAC.
        body = artifact;
        if (config.token) headers["Authorization"] = "Bearer " + config.token;
    }
    return { body: body, headers: headers };
}

function signGeneric(secret, timestamp, rawBody) {
    const signingString = String(timestamp) + "." + String(rawBody);
    return "sha256=" + crypto.createHmac("sha256", secret).update(signingString).digest("hex");
}

// Default transport: POST rawBody to endpoint with headers. Resolves
// { ok, status, body } / { ok:false, status:0, error }. Never rejects.
function defaultTransport(endpoint, rawBody, headers) {
    return new Promise(function (resolve) {
        let url;
        try { url = new URL(endpoint); }
        catch (e) { resolve({ ok: false, status: 0, error: "invalid endpoint URL: " + (e.message || String(e)) }); return; }
        const lib = url.protocol === "http:" ? http : https;
        const req = lib.request(url, {
            method: "POST",
            headers: Object.assign({ "Content-Length": Buffer.byteLength(rawBody) }, headers),
        }, function (res) {
            let chunks = "";
            res.on("data", function (d) { chunks += d; });
            res.on("end", function () {
                const status = res.statusCode || 0;
                resolve({ ok: status >= 200 && status < 300, status: status, body: chunks });
            });
        });
        req.on("error", function (e) { resolve({ ok: false, status: 0, error: e.message || String(e) }); });
        req.write(rawBody);
        req.end();
    });
}

function createEvidenceForwarder(config) {
    config = config || {};
    const profile = PROFILES.indexOf(config.profile) >= 0 ? config.profile : "generic";
    const transport = typeof config.transport === "function" ? config.transport : defaultTransport;
    const nowFn = config.now || function () { return new Date().toISOString(); };

    return async function forward(report) {
        if (!config.endpoint) {
            return { ok: false, status: 0, error: "evidence-forwarder: endpoint is required" };
        }
        let artifact, shaped, rawBody;
        try {
            artifact = buildArtifact(report, { organizationName: config.organizationName, now: nowFn() });
            shaped = shapeRequest(profile, artifact, config);
            rawBody = JSON.stringify(shaped.body);
        } catch (e) {
            return { ok: false, status: 0, error: e.message || String(e) };
        }

        const headers = Object.assign({}, shaped.headers);
        if (profile === "generic" && config.secret) {
            const ts = String(safeNowMs(nowFn));
            headers[TIMESTAMP_HEADER] = ts;
            headers[SIGNATURE_HEADER] = signGeneric(config.secret, ts, rawBody);
        }

        let res;
        try { res = await transport(config.endpoint, rawBody, headers); }
        catch (e) { return { ok: false, status: 0, error: e.message || String(e) }; }
        if (!res || typeof res !== "object") return { ok: false, status: 0, error: "transport returned no result" };

        return {
            ok: !!res.ok,
            status: typeof res.status === "number" ? res.status : 0,
            error: res.error || null,
            profile: profile,
            artifactSha256: artifact.artifactSha256,
        };
    };
}

// Date.now() is unavailable in some sandboxes; fall back to parsing the
// ISO string from nowFn so the HMAC timestamp is still monotone-ish.
function safeNowMs(nowFn) {
    try { return Date.now(); }
    catch (e) {
        const t = Date.parse(nowFn());
        return Number.isFinite(t) ? t : 0;
    }
}

module.exports = {
    PROFILES: PROFILES.slice(),
    createEvidenceForwarder: createEvidenceForwarder,
    buildArtifact: buildArtifact,
    // exposed for tests:
    _canonicalize: canonicalize,
    _shapeRequest: shapeRequest,
    _signGeneric: signGeneric,
};
