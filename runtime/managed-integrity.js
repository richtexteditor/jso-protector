"use strict";

// Versioned policy evaluation and incident operations for managed browser
// integrity. The browser sensor remains third-party-inventory.js; this module
// supplies the control-plane contract used by a hosted worker or an on-prem
// collector without coupling policy decisions to a particular database.

const VALID_MODES = Object.freeze(["monitor", "block"]);
const VALID_STATUSES = Object.freeze(["open", "reviewing", "resolved", "ignored"]);

function normalizeOrigin(value) {
  const parsed = new URL(String(value));
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("managed-integrity: origins must use http(s)");
  return parsed.origin;
}

function createManagedIntegrityPolicy(input) {
  input = input || {};
  if (!input.id || !input.version) throw new Error("managed-integrity: policy id and version are required");
  const mode = String(input.mode || "monitor").toLowerCase();
  if (!VALID_MODES.includes(mode)) throw new Error("managed-integrity: mode must be monitor or block");
  const origins = Array.from(new Set((input.allowedOrigins || []).map(normalizeOrigin))).sort();
  const hashes = Array.from(new Set((input.allowedInlineHashes || []).map((value) => String(value).toLowerCase()))).sort();
  const expectedContent = Object.freeze(Object.assign({}, input.expectedContentBySrc || {}));
  return Object.freeze({
    id: String(input.id), version: String(input.version), mode,
    allowedOrigins: Object.freeze(origins),
    allowedInlineHashes: Object.freeze(hashes),
    expectedContentBySrc: expectedContent,
    blockLateInjection: input.blockLateInjection !== false,
    effectiveAt: new Date(input.effectiveAt || Date.now()).toISOString()
  });
}

function evaluateSnapshot(policy, snapshot) {
  if (!policy || !snapshot || !Array.isArray(snapshot.scripts)) throw new Error("managed-integrity: policy and inventory snapshot are required");
  const violations = [];
  for (const script of snapshot.scripts) {
    const row = Object.assign({}, script);
    if (row.inline) {
      if (!row.sha256 || !policy.allowedInlineHashes.includes(String(row.sha256).toLowerCase())) violations.push(Object.assign({ reason: "unknown-inline-content" }, row));
    } else {
      let origin = null;
      try { origin = normalizeOrigin(row.src); } catch (_) {}
      if (!origin || !policy.allowedOrigins.includes(origin)) violations.push(Object.assign({ reason: "unknown-origin" }, row));
      const expected = row.src && policy.expectedContentBySrc[row.src];
      if (expected && row.sha256 && expected !== row.sha256) violations.push(Object.assign({ reason: "content-hash-mismatch", expectedSha256: expected }, row));
      if (policy.blockLateInjection && row.injectedAfterLoad) violations.push(Object.assign({ reason: "late-script-injection" }, row));
    }
  }
  const unique = [];
  const seen = new Set();
  for (const violation of violations) {
    const key = [violation.reason, violation.src || "inline", violation.sha256 || ""].join("|");
    if (!seen.has(key)) { seen.add(key); unique.push(violation); }
  }
  return {
    v: 1, kind: "managed-integrity-decision", policyId: policy.id, policyVersion: policy.version,
    buildId: snapshot.buildId || null, pageHref: snapshot.pageHref || null,
    verdict: unique.length ? "violation" : "clean",
    action: unique.length && policy.mode === "block" ? "block" : "monitor",
    violations: unique
  };
}

function createIntegrityOperations(config) {
  config = config || {};
  const incidents = new Map();
  let sequence = 0;
  const now = typeof config.now === "function" ? config.now : () => new Date().toISOString();

  function ingest(decision) {
    if (!decision || decision.verdict !== "violation") return [];
    const touched = [];
    for (const violation of decision.violations || []) {
      const fingerprint = [decision.policyId, decision.buildId || "", decision.pageHref || "", violation.reason, violation.src || violation.sha256 || "unknown"].join("|");
      let incident = incidents.get(fingerprint);
      if (incident && incident.status !== "resolved" && incident.status !== "ignored") {
        incident.count++; incident.lastSeenAt = now();
      } else {
        incident = { id: "wpi-" + (++sequence), fingerprint, policyId: decision.policyId, policyVersion: decision.policyVersion, buildId: decision.buildId, pageHref: decision.pageHref, reason: violation.reason, src: violation.src || null, sha256: violation.sha256 || null, action: decision.action, status: "open", count: 1, firstSeenAt: now(), lastSeenAt: now(), assignee: null, resolution: null };
        incidents.set(fingerprint, incident);
      }
      touched.push(Object.assign({}, incident));
    }
    return touched;
  }

  function transition(id, status, metadata) {
    status = String(status || "").toLowerCase();
    if (!VALID_STATUSES.includes(status)) throw new Error("managed-integrity: invalid incident status");
    const incident = Array.from(incidents.values()).find((row) => row.id === String(id));
    if (!incident) return null;
    incident.status = status;
    incident.assignee = metadata && metadata.assignee != null ? String(metadata.assignee) : incident.assignee;
    incident.resolution = metadata && metadata.resolution != null ? String(metadata.resolution) : incident.resolution;
    incident.updatedAt = now();
    return Object.assign({}, incident);
  }

  return {
    ingest, transition,
    list: (status) => Array.from(incidents.values()).filter((row) => !status || row.status === status).map((row) => Object.assign({}, row)),
    exportJson: () => JSON.stringify({ v: 1, kind: "managed-integrity-incidents", incidents: Array.from(incidents.values()) }, null, 2)
  };
}

module.exports = { VALID_MODES, VALID_STATUSES, createManagedIntegrityPolicy, evaluateSnapshot, createIntegrityOperations };
