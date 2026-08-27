#!/usr/bin/env node
"use strict";

// Smoke validator for the shipped CI templates.
//
// Verifies that every template ships with consistent conventions so we never
// publish a broken one. Checks:
//
//   1. File exists, is non-empty, is readable.
//   2. YAML files: no tab characters in indentation (YAML forbids it).
//   3. Every template calls jso-protector with --label and --report so audit
//      and symbolication conventions stay uniform across CI systems.
//   4. Jenkinsfile: balanced { } and pipeline { ... } opener.
//   5. The GitHub composite Action exposes source-free migration preflight
//      reports as inputs and outputs.
//
// Exit code: 0 if all clean, 1 otherwise. Used by `npm run verify:ci`.

const fs = require("node:fs");
const path = require("node:path");

const CI_DIR = path.join(__dirname);
const GITHUB_ACTION_FILE = path.resolve(__dirname, "..", "..", "jso-github-action", "action.yml");

const YAML_TEMPLATES = [
    "github-actions.yml",
    "gitlab-ci.yml",
    "circleci.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "drone.yml",
    "buildkite.yml",
    "woodpecker.yml",
    "tekton.yaml",
    "gocd.yaml",
    "argo-workflows.yaml"
];

// Jenkinsfile (Groovy) and teamcity.kts (Kotlin) get language-specific checks.
const SPECIAL_TEMPLATES = ["Jenkinsfile", "teamcity.kts"];

function fail(msg) {
    console.error("verify-templates: " + msg);
    process.exitCode = 1;
}

function checkExistsAndNonEmpty(file) {
    const p = path.join(CI_DIR, file);
    if (!fs.existsSync(p)) { fail(file + ": missing"); return null; }
    const text = fs.readFileSync(p, "utf8");
    if (!text.trim()) { fail(file + ": empty"); return null; }
    return text;
}

function checkYamlIndentation(file, text) {
    // YAML forbids tabs in indentation. Skip lines that are entirely inside a
    // quoted string (best-effort: we only flag leading-tab lines, which is the
    // most common mistake when copy-pasting from a Jenkinsfile).
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        if (/^\t/.test(lines[i])) {
            fail(file + ":" + (i + 1) + ": YAML disallows leading tab characters");
        }
    }
}

function checkLabelAndReport(file, text) {
    // Every template must invoke jso-protector with --label and --report so
    // audit and symbolication conventions stay uniform across CI systems.
    if (!/--label\b/.test(text)) fail(file + ": missing --label invocation");
    if (!/--report\b/.test(text)) fail(file + ": missing --report invocation");
}

function checkSupplyChainHint(file, text) {
    // Every template must carry the "Optional: migration and supply-chain"
    // commented-out hint block so customers using a non-GitHub CI system can
    // discover --competitor-gap-report, source-map evidence,
    // payment-page inventory audit and HAR-to-header evidence,
    // --ai-precheck, --watermark, and --sign-release without hunting through
    // docs. Block is commented out by default: opt-in, no behavior change to
    // existing pipelines.
    if (!/Optional: migration and supply-chain checks/.test(text)) {
        fail(file + ": missing 'Optional: migration and supply-chain checks' hint block " +
             "(see _add-supply-chain-block.js for the canonical block content)");
    }
    // The flags listed must all appear in the commented block; a future
    // template can't ship advertising only some of the surface.
    for (const flag of [
        "--competitor-gap-report",
        "--source-map-evidence",
        "--script-inventory-audit",
        "--runtime-inventory-snapshot",
        "--script-inventory-audit-output",
        "--payment-page-headers-from-har",
        "--payment-page-headers-baseline",
        "--payment-page-headers-output",
        "--ai-precheck",
        "--estimate",
        "--watermark",
        "--sign-release"
    ]) {
        if (!text.includes(flag)) {
            fail(file + ": migration/supply-chain hint block missing flag " + flag);
        }
    }
}
function checkJenkinsfile(text) {
    const opens = (text.match(/\{/g) || []).length;
    const closes = (text.match(/\}/g) || []).length;
    if (opens !== closes) fail("Jenkinsfile: unbalanced braces (" + opens + " { vs " + closes + " })");
    if (!/^\s*pipeline\s*\{/m.test(text)) fail("Jenkinsfile: missing top-level `pipeline {` block");
    if (!/--label/.test(text)) fail("Jenkinsfile: missing --label invocation");
    if (!/--report/.test(text)) fail("Jenkinsfile: missing --report invocation");
    checkSupplyChainHint("Jenkinsfile", text);
}

function checkTeamCityKts(text) {
    const opens = (text.match(/\{/g) || []).length;
    const closes = (text.match(/\}/g) || []).length;
    if (opens !== closes) fail("teamcity.kts: unbalanced braces (" + opens + " { vs " + closes + " })");
    if (!/object\s+\w+\s*:\s*BuildType/.test(text)) fail("teamcity.kts: missing BuildType object declaration");
    if (!/--label/.test(text)) fail("teamcity.kts: missing --label invocation");
    if (!/--report/.test(text)) fail("teamcity.kts: missing --report invocation");
    checkSupplyChainHint("teamcity.kts", text);
}

function checkGitHubActionContract() {
    if (!fs.existsSync(GITHUB_ACTION_FILE)) {
        fail("jso-github-action/action.yml: missing");
        return;
    }
    const text = fs.readFileSync(GITHUB_ACTION_FILE, "utf8");
    for (const token of [
        "release-check:",
        "release-check-report:",
        "competitor-gap-report:",
        "competitor-gap-report-path:",
        "payment-script-inventory:",
        "runtime-inventory-snapshot:",
        "script-inventory-audit-report:",
        "payment-page-har:",
        "payment-page-headers-baseline:",
        "payment-page-url-pattern:",
        "payment-page-headers-report:",
        "pci-dss-v4-evidence:",
        "pci-dss-v4-report:",
        "pci-dss-v4-json-report:",
        "source-map-evidence:",
        "source-map-evidence-report:",
        "--release-check",
        "--competitor-gap-report",
        "--source-map-evidence",
        "--script-inventory-audit",
        "--payment-page-headers-from-har",
        "--payment-page-headers-baseline",
        "compliance\" \"pci-dss-v4",
        "steps.release-check.outputs.release-check-report",
        "steps.competitor-gap.outputs.competitor-gap-report-path",
        "steps.script-inventory-audit.outputs.script-inventory-audit-report",
        "steps.payment-page-headers.outputs.payment-page-headers-report",
        "steps.pci-dss-v4-evidence.outputs.pci-dss-v4-report",
        "steps.pci-dss-v4-evidence.outputs.pci-dss-v4-json-report",
        "steps.source-map-evidence.outputs.source-map-evidence-report"
    ]) {
        if (!text.includes(token)) {
            fail("jso-github-action/action.yml: missing " + token);
        }
    }
}

let checked = 0;
for (const file of YAML_TEMPLATES) {
    const text = checkExistsAndNonEmpty(file);
    if (text == null) continue;
    checkYamlIndentation(file, text);
    checkLabelAndReport(file, text);
    checkSupplyChainHint(file, text);
    checked++;
}

for (const file of SPECIAL_TEMPLATES) {
    const text = checkExistsAndNonEmpty(file);
    if (text == null) continue;
    if (file === "Jenkinsfile") checkJenkinsfile(text);
    else if (file === "teamcity.kts") checkTeamCityKts(text);
    checked++;
}

checkGitHubActionContract();

if (process.exitCode) {
    console.error("verify-templates: FAILED (" + checked + " templates inspected)");
} else {
    console.log("verify-templates: OK (" + checked + " templates inspected, action preflight contract checked)");
}
