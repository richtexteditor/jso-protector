"use strict";

// Tests for ../../polyglot-smoke/check-github-action.js.
//
// Three layers:
//   1. The real action.yml passes (regression: nobody can land a broken
//      action.yml + a passing linter at the same time).
//   2. Fixture-based negative tests: mutate the real action.yml in
//      memory, write it to a temp file, point the checker at it via a
//      spawned subprocess, confirm the checker exits non-zero.
//   3. Edge cases: empty inputs, missing required keys.

const test       = require("node:test");
const assert     = require("node:assert");
const fs         = require("node:fs");
const path       = require("node:path");
const os         = require("node:os");
const { spawn }  = require("node:child_process");

const CHECKER = path.resolve(__dirname, "..", "..", "polyglot-smoke", "check-github-action.js");
const REAL_ACTION_YML = path.resolve(__dirname, "..", "..", "jso-github-action", "action.yml");

// Every test here asserts the checker's EXIT CODE, so they only mean something
// when the checker can actually parse action.yml. It needs js-yaml, which is
// reached from an installed node_modules and is therefore absent in a fresh
// clone; without it the checker correctly reports SKIPPED and exits 0, and
// these negative tests would then fail for a reason that has nothing to do
// with the action. Skip in lockstep with the thing under test, and say why.
const JS_YAML_PATHS = [
    path.resolve(__dirname, "..", "..", "eslint-plugin-jso-protector", "node_modules", "js-yaml"),
    path.resolve(__dirname, "..", "..", "polyglot-smoke", "node_modules", "js-yaml"),
];
const JS_YAML_AVAILABLE = JS_YAML_PATHS.some((candidate) => fs.existsSync(candidate));
const SKIP_REASON = JS_YAML_AVAILABLE
    ? false
    : "js-yaml unavailable (run npm install in packages/eslint-plugin-jso-protector); the checker itself skips too";

function runChecker(env) {
    return new Promise(resolve => {
        const c = spawn(process.execPath, [CHECKER], { env: { ...process.env, ...(env || {}) } });
        let out = "", err = "";
        c.stdout.on("data", d => out += d.toString());
        c.stderr.on("data", d => err += d.toString());
        c.on("close", code => resolve({ code, out, err }));
    });
}

// The checker resolves the action.yml via a relative path. To test fixtures
// we need to mutate the REAL file in place, then restore — risky. Safer:
// the checker module exports nothing right now; we call it via spawn but
// substitute the action.yml file by mutating + restoring atomically.
//
// We snapshot the original bytes before each negative test, mutate, run,
// restore in a finally. Use a unique sentinel string in mutations so we
// can't accidentally leave a broken file behind even if the test crashes.

async function withMutated(mutateFn, fn) {
    const original = fs.readFileSync(REAL_ACTION_YML);
    try {
        const mutated = mutateFn(original.toString("utf8"));
        fs.writeFileSync(REAL_ACTION_YML, mutated);
        // CRITICAL: await before restoring, otherwise the spawned checker
        // reads the file AFTER finally has already put it back. That
        // would make every negative test silently pass.
        return await fn();
    } finally {
        fs.writeFileSync(REAL_ACTION_YML, original);
    }
}

test("check-github-action: real action.yml passes", { skip: SKIP_REASON }, async () => {
    const r = await runChecker();
    assert.equal(r.code, 0, "exit code; out=" + r.out + "; err=" + r.err);
    assert.match(r.out, /check-github-action: PASS/);
    // Sanity check the parse picked up real structure.
    assert.match(r.out, /inputs:\s+\d+/);
    assert.match(r.out, /outputs:\s+\d+/);
    assert.match(r.out, /steps:\s+\d+/);
});

test("check-github-action: real action exposes source-free evidence preflights", { skip: SKIP_REASON }, () => {
    const src = fs.readFileSync(REAL_ACTION_YML, "utf8");
    for (const token of [
        "source-map-evidence:",
        "source-map-evidence-report:",
        "id: source-map-evidence",
        "--source-map-evidence",
        "--source-map-evidence-output",
        "steps.source-map-evidence.outputs.source-map-evidence-report",
        "runtime-incident-export:",
        "runtime-incident-evidence-report:",
        "id: runtime-incident-evidence",
        "--runtime-incident-evidence",
        "--runtime-incident-evidence-output",
        "::error title=JSO runtime incident evidence",
        "steps.runtime-incident-evidence.outputs.runtime-incident-evidence-report",
        "pci-dss-v4-evidence:",
        "pci-dss-v4-report:",
        "pci-dss-v4-json-report:",
        "pci-dss-v4-organization:",
        "pci-dss-v4-root:",
        "pci-dss-v4-beacon-url:",
        "pci-dss-v4-siem:",
        "pci-dss-v4-allow-unsigned:",
        "id: pci-dss-v4-evidence",
        "compliance\" \"pci-dss-v4",
        "--json-output",
        "--payment-page-headers",
        "::error title=JSO PCI DSS v4 evidence",
        "steps.pci-dss-v4-evidence.outputs.pci-dss-v4-report",
        "steps.pci-dss-v4-evidence.outputs.pci-dss-v4-json-report",
        "report-path:",
        "steps.run.outputs.report-path",
        "migration-review:",
        "migration-review-report:",
        "id: migration-review",
        "--migration-review",
        "--migration-review-output",
        "steps.migration-review.outputs.migration-review-report",
        "vm-proof-pack:",
        "vm-proof-pack-report:",
        "id: vm-proof-pack",
        "--vm-proof-pack",
        "--vm-proof-output",
        "::error title=JSO VM proof pack",
        "steps.vm-proof-pack.outputs.vm-proof-pack-report",
        "ai-resistance-evidence:",
        "ai-resistance-evidence-report:",
        "ai-resistance-require-vm-proof:",
        "min-vm-functions:",
        "id: ai-resistance-evidence",
        "--ai-resistance-evidence",
        "--ai-resistance-evidence-output",
        "--require-vm-proof",
        "::error title=JSO AI-resistance evidence",
        "steps.ai-resistance-evidence.outputs.ai-resistance-evidence-report",
        "payment-script-inventory:",
        "runtime-inventory-snapshot:",
        "script-inventory-audit-report:",
        "id: script-inventory-audit",
        "--script-inventory-audit",
        "--runtime-inventory-snapshot",
        "--script-inventory-audit-output",
        "GITHUB_STEP_SUMMARY",
        "::error title=JSO payment-page audit",
        "steps.script-inventory-audit.outputs.script-inventory-audit-report",
        "payment-page-har:",
        "payment-page-headers-baseline:",
        "payment-page-url-pattern:",
        "payment-page-headers-report:",
        "id: payment-page-headers",
        "--payment-page-headers-from-har",
        "--payment-page-headers-baseline",
        "--payment-page-headers-output",
        "::warning title=JSO payment-page security headers",
        "steps.payment-page-headers.outputs.payment-page-headers-report"
    ]) {
        assert.equal(src.includes(token), true, "missing action audit token: " + token);
    }
});

test("check-github-action: rejects ${{ steps.X }} that doesn't resolve", { skip: SKIP_REASON }, async () => {
    await withMutated(
        src => src.replace(
            "value: ${{ steps.run.outputs.build-id }}",
            "value: ${{ steps.RUNNNN.outputs.build-id }}",
        ),
        async () => {
            const r = await runChecker();
            assert.notStrictEqual(r.code, 0, "should fail; out=" + r.out + "; err=" + r.err);
            assert.match(r.err + r.out, /no step has id: RUNNNN/);
        });
});

test("check-github-action: rejects ${{ inputs.X }} that isn't declared", { skip: SKIP_REASON }, async () => {
    await withMutated(
        src => src.replace(
            "JSO_API_KEY: ${{ inputs.api-key }}",
            "JSO_API_KEY: ${{ inputs.bogus-input-name }}",
        ),
        async () => {
            const r = await runChecker();
            assert.notStrictEqual(r.code, 0);
            assert.match(r.err + r.out, /no input declared with name: bogus-input-name/);
        });
});

test("check-github-action: rejects input missing description (Marketplace requirement)", { skip: SKIP_REASON }, async () => {
    // Strip the description from the first input block (`input:`).
    // Use a regex that targets the description line under the first input only.
    await withMutated(
        src => {
            // Find the first `input:` declaration block and remove its description line.
            const idx = src.indexOf("  input:");
            if (idx < 0) throw new Error("test setup: couldn't find input: in real action.yml");
            const before = src.slice(0, idx);
            const after = src.slice(idx);
            // Strip the description line that follows.
            const stripped = after.replace(/(\n)    description: "[^"]*"\n/, "$1");
            return before + stripped;
        },
        async () => {
            const r = await runChecker();
            assert.notStrictEqual(r.code, 0);
            assert.match(r.err + r.out, /inputs\.input: missing description/);
        });
});

test("check-github-action: detects duplicate step id", { skip: SKIP_REASON }, async () => {
    // Find a unique step id, duplicate it onto another step.
    await withMutated(
        src => src.replace("\n      id: run\n", "\n      id: release-check\n"),    // collide with the existing release-check step
        async () => {
            const r = await runChecker();
            assert.notStrictEqual(r.code, 0);
            assert.match(r.err + r.out, /duplicate step id: release-check/);
        });
});

test("check-github-action: detects malformed YAML", { skip: SKIP_REASON }, async () => {
    await withMutated(
        src => src + "\nthis is not: : valid: yaml: at all\n  - bad indent\n nope",
        async () => {
            const r = await runChecker();
            assert.notStrictEqual(r.code, 0);
            // Either parse error message or downstream missing-key complaints.
            assert.ok(r.code !== 0);
        });
});
