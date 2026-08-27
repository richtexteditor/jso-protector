"use strict";
const test = require("node:test");
const assert = require("node:assert");
const managed = require("../runtime/managed-integrity");

test("managed integrity policy monitors clean inventories", function () {
  const policy = managed.createManagedIntegrityPolicy({ id: "checkout", version: "7", allowedOrigins: ["https://cdn.example.com"], allowedInlineHashes: ["abc"] });
  const decision = managed.evaluateSnapshot(policy, { buildId: "b1", pageHref: "https://shop.example/checkout", scripts: [{ src: "https://cdn.example.com/app.js", sha256: "ok", inline: false }, { inline: true, sha256: "abc" }] });
  assert.equal(decision.verdict, "clean");
  assert.equal(decision.action, "monitor");
});

test("block policy detects origin content and late-injection drift", function () {
  const policy = managed.createManagedIntegrityPolicy({ id: "checkout", version: "8", mode: "block", allowedOrigins: ["https://cdn.example.com"], expectedContentBySrc: { "https://cdn.example.com/app.js": "good" } });
  const decision = managed.evaluateSnapshot(policy, { scripts: [{ src: "https://evil.example/skimmer.js", inline: false }, { src: "https://cdn.example.com/app.js", sha256: "changed", inline: false, injectedAfterLoad: true }] });
  assert.equal(decision.action, "block");
  assert.deepEqual(new Set(decision.violations.map((row) => row.reason)), new Set(["unknown-origin", "content-hash-mismatch", "late-script-injection"]));
});

test("integrity operations deduplicate and transition incidents", function () {
  let tick = 0;
  const operations = managed.createIntegrityOperations({ now: () => "2026-07-13T22:5" + (++tick) + ":00Z" });
  const decision = { verdict: "violation", action: "block", policyId: "checkout", policyVersion: "8", buildId: "b1", pageHref: "/checkout", violations: [{ reason: "unknown-origin", src: "https://evil.example/a.js" }] };
  const first = operations.ingest(decision)[0];
  operations.ingest(decision);
  assert.equal(operations.list()[0].count, 2);
  assert.equal(operations.transition(first.id, "reviewing", { assignee: "security@example.com" }).assignee, "security@example.com");
  assert.equal(JSON.parse(operations.exportJson()).incidents.length, 1);
});
