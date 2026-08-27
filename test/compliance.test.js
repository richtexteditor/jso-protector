"use strict";

// Unit + smoke tests for the PCI DSS v4 compliance reporter.
// No network. We synthesize a build (two protected files + their signed
// manifest) in os.tmpdir(), then drive the reporter against it and
// assert the evidence rows + summary + exit code resolve correctly.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const releaseSigner = require("../release-signer.js");
const watermark = require("../watermark.js");
const compliance = require("../compliance/pci-dss-v4/index.js");
const complianceCli = require("../compliance/cli.js");

const BIN = path.join(__dirname, "..", "bin", "jso-protector.js");
const NODE = process.execPath;

function makeBuild(label) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jso-pci-" + (label || "") + "-"));
    return tmpDir;
}

function writeProtectedFile(dir, name, tag, key) {
    // Build a tiny protected file with a watermark header so the
    // reporter can exercise the per-file evidence path.
    const body = "// protected payload for " + name + "\nconsole.log(\"" + name + "\");\n";
    const wrapped = watermark.injectInto(body, tag, key);
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, wrapped, "utf8");
    return wrapped;
}

function buildSignedManifest(dir, files, opts) {
    // files: [{name: "app.js", source: "<bytes>"}, ...]
    // opts: { buildId, polymorphismFingerprint, label }
    const manifestFiles = files.map(function (f) {
        return {
            name: f.name,
            sha256: crypto.createHash("sha256").update(f.source).digest("hex"),
        };
    });
    const keys = releaseSigner.generateKeyPair();
    const envelope = releaseSigner.signRelease({
        buildId: opts.buildId || "test-build-" + Date.now(),
        polymorphismFingerprint: opts.polymorphismFingerprint || "pf-test",
        label: opts.label || "test-label",
        files: manifestFiles,
    }, keys.privateKeyPem);
    const sigPath = path.join(dir, "build.manifest.json.sig");
    fs.writeFileSync(sigPath, JSON.stringify(envelope, null, 2) + "\n", "utf8");
    return { sigPath: sigPath, envelope: envelope, manifestFiles: manifestFiles, keys: keys };
}

function writeRuntimeIncidentCsv(dir, rows) {
    const headers = [
        "IncidentID", "Status", "Severity", "Kind", "Reason", "BuildID",
        "Fingerprint", "PageUrl", "RemoteIP", "EventUtc", "ReceivedUtc", "UserAgent",
    ];
    function esc(value) {
        value = value == null ? "" : String(value);
        return /[",\r\n]/.test(value) ? "\"" + value.replace(/"/g, "\"\"") + "\"" : value;
    }
    const lines = [headers.join(",")];
    for (const row of rows) {
        lines.push(headers.map(function (h) { return esc(row[h]); }).join(","));
    }
    const csvPath = path.join(dir, "runtime-incidents.csv");
    fs.writeFileSync(csvPath, "\uFEFF" + lines.join("\r\n") + "\r\n", "utf8");
    return csvPath;
}

function writeRuntimeIncidentJson(dir, rows, filters, routing, responseChecklist, responseWindow, dashboardActions) {
    const jsonPath = path.join(dir, "runtime-incidents.json");
    const payload = {
        format: "jso-runtime-incident-export",
        version: 1,
        sourceFree: true,
        generatedUtc: "2026-06-06T12:00:00Z",
        maxRows: 500,
        filters: filters || {},
        routing: routing || {},
        responseWindow: responseWindow || undefined,
        responseChecklist: responseChecklist || undefined,
        dashboardActions: dashboardActions || undefined,
        incidentCount: rows.length,
        incidents: rows.map(function (row) {
            return {
                incidentId: row.IncidentID,
                status: row.Status,
                severity: row.Severity,
                kind: row.Kind,
                reason: row.Reason,
                buildId: row.BuildID,
                fingerprint: row.Fingerprint,
                pageUrl: row.PageUrl,
                remoteIp: row.RemoteIP,
                eventUtc: row.EventUtc,
                receivedUtc: row.ReceivedUtc,
                userAgent: row.UserAgent,
            };
        }),
    };
    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2) + "\n", "utf8");
    return jsonPath;
}

function writeScriptInventoryJson(dir, rows) {
    const jsonPath = path.join(dir, "payment-script-inventory.json");
    const payload = {
        format: "jso-payment-script-inventory",
        version: 1,
        sourceFree: true,
        generatedUtc: "2026-06-06T12:00:00Z",
        scripts: rows,
    };
    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2) + "\n", "utf8");
    return jsonPath;
}

function writeScriptInventoryAuditJson(dir, summaryOverrides) {
    const jsonPath = path.join(dir, "payment-script-inventory-audit.json");
    const summary = Object.assign({
        approvedScripts: 1,
        observedScripts: 1,
        unknownObserved: 0,
        unauthorizedObserved: 0,
        integrityMismatches: 0,
        missingApproved: 0,
        injectedAfterLoad: 0,
        runtimeViolations: 0,
        observedWithoutIntegrityReference: 0,
        inventoryGaps: 0,
        duplicateApproved: 0,
        blockingIssues: 0,
    }, summaryOverrides || {});
    const payload = {
        format: "jso-payment-script-inventory-audit",
        version: 1,
        sourceFree: true,
        generatedAt: "2026-06-06T12:15:00Z",
        generatedBy: "jso-protector --script-inventory-audit",
        ok: summary.blockingIssues === 0,
        approvedInventory: {
            source: "payment-script-inventory.json",
            sourceFormat: "json",
            sourceSha256: "a".repeat(64),
        },
        runtimeSnapshot: {
            source: "runtime-inventory.json",
            sourceSha256: "b".repeat(64),
            snapshotCount: 1,
            buildIds: ["checkout-build"],
            pageHrefs: ["https://example.test/checkout"],
        },
        summary: summary,
        checklist: [],
        findings: {},
        recommendations: [],
    };
    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2) + "\n", "utf8");
    return jsonPath;
}

function writeSecurityHeaderJson(dir, pages) {
    const jsonPath = path.join(dir, "payment-page-headers.json");
    const payload = {
        format: "jso-payment-page-security-headers",
        version: 1,
        sourceFree: true,
        generatedUtc: "2026-06-06T12:20:00Z",
        pages: pages,
    };
    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2) + "\n", "utf8");
    return jsonPath;
}

test("pci-dss-v4: signed manifest + watermark key + beacon + siem => PASS, exit 0", function () {
    const dir = makeBuild("pass");
    const key = "test-secret-watermark-key-32bytes";
    const wm1 = writeProtectedFile(dir, "app.js",  "v1.2.3", key);
    const wm2 = writeProtectedFile(dir, "lib/dep.js", "v1.2.3", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "app.js",     source: wm1 },
        { name: "lib/dep.js", source: wm2 },
    ], { label: "v1.2.3" });
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        beaconUrl: "https://beacon.example.com/v1/jso?tenant=acme",
        siemAdapter: "splunk-hec",
        organizationName: "Example Corp",
        now: "2026-06-02T12:00:00Z",
    });
    assert.equal(report.exitCode, 0, "exit code should be 0 (no gaps)");
    assert.equal(report.summary.fail, 0);
    assert.equal(report.summary.partial, 0);
    assert.equal(report.summary.not_inspected, 0);
    assert.equal(report.summary.signatureVerified, true);
    assert.equal(report.json.reviewAssistant.sourceFree, true);
    assert.equal(report.json.reviewAssistant.title, "PCI DSS Review Assistant");
    assert.match(report.json.reviewAssistant.intendedUse, /BYO AI key/);
    assert.equal(report.json.reviewAssistant.doNotInclude.includes("payment-card data"), true);
    assert.equal(report.json.reviewAssistant.questions.some(function (item) { return item.topic === "QSA handoff boundary"; }), true);
    assert.match(report.markdown, /Example Corp/);
    assert.match(report.markdown, /## PCI DSS Review Assistant/);
    assert.match(report.markdown, /QSA handoff boundary/);
    // Multi-line: section header on one line, "Overall status: **PASS**" two lines below
    assert.match(report.markdown, /6\.4\.3[^\n]*\n\nOverall status: \*\*PASS\*\*/);
    assert.match(report.markdown, /11\.6\.1[^\n]*\n\nOverall status: \*\*PASS\*\*/);
    // Inventory row contains both files.
    assert.match(report.markdown, /`app\.js`/);
    assert.match(report.markdown, /`lib\/dep\.js`/);
    // Beacon URL is redacted (no query string leak).
    assert.ok(!report.markdown.includes("tenant=acme"), "report must not leak beacon query string");
});

test("pci-dss-v4: runtime incident CSV summarizes Dashboard Monitoring evidence", function () {
    const dir = makeBuild("runtime-incidents");
    const key = "test-secret-runtime-incidents";
    const wm1 = writeProtectedFile(dir, "checkout.js", "checkout-v1", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "checkout.js", source: wm1 },
    ], { label: "checkout-v1", buildId: "build-checkout-1" });
    const csvPath = writeRuntimeIncidentCsv(dir, [
        {
            IncidentID: "101",
            Status: "Open",
            Severity: "Critical",
            Kind: "script-injection",
            Reason: "unknown script",
            BuildID: "build-checkout-1",
            Fingerprint: "fp-1",
            PageUrl: "https://shop.example/checkout?step=pay,review",
            RemoteIP: "203.0.113.5",
            EventUtc: "2026-06-06T10:00:00Z",
            ReceivedUtc: "2026-06-06T10:01:00Z",
            UserAgent: "Test Browser",
        },
        {
            IncidentID: "102",
            Status: "Reviewing",
            Severity: "Medium",
            Kind: "integrity-heartbeat",
            Reason: "heartbeat mismatch",
            BuildID: "build-checkout-1",
            Fingerprint: "fp-1",
            PageUrl: "https://shop.example/checkout",
            RemoteIP: "203.0.113.6",
            EventUtc: "2026-06-06T10:05:00Z",
            ReceivedUtc: "2026-06-06T10:06:00Z",
            UserAgent: "Test Browser 2",
        },
        {
            IncidentID: "103",
            Status: "Resolved",
            Severity: "High",
            Kind: "unknown-origin",
            Reason: "reviewed",
            BuildID: "build-checkout-2",
            Fingerprint: "fp-2",
            PageUrl: "https://shop.example/wallet",
            RemoteIP: "203.0.113.7",
            EventUtc: "2026-06-06T11:00:00Z",
            ReceivedUtc: "2026-06-06T11:02:00Z",
            UserAgent: "Test Browser 3",
        },
    ]);
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        beaconUrl: "https://b.example/runtime",
        runtimeIncidentsPath: csvPath,
        now: "2026-06-06T12:00:00Z",
    });
    assert.equal(report.json.runtimeIncidents.sourceFormat, "csv");
    assert.equal(report.json.runtimeIncidents.count, 3);
    assert.equal(report.json.runtimeIncidents.statusCounts.Open, 1);
    assert.equal(report.json.runtimeIncidents.statusCounts.Reviewing, 1);
    assert.equal(report.json.runtimeIncidents.unresolvedCount, 2);
    assert.equal(report.json.runtimeIncidents.unresolvedHighCriticalCount, 1);
    assert.deepEqual(report.json.runtimeIncidents.buildIds, ["build-checkout-1", "build-checkout-2"]);
    assert.equal(report.json.runtimeIncidents.responseWindow.sourceFree, true);
    assert.equal(report.json.runtimeIncidents.responseWindow.targetMinutes, 15);
    assert.equal(report.json.runtimeIncidents.responseWindow.targetLabel, "15 minutes");
    assert.equal(report.json.runtimeIncidents.responseWindow.responseDueUtc, "2026-06-06T10:16:00.000Z");
    assert.equal(report.json.runtimeIncidents.responseWindow.windowState, "due-time-recorded");
    assert.equal(report.json.runtimeIncidents.responseWindow.overdue, null);
    assert.equal(report.json.runtimeIncidents.responseChecklist.sourceFree, true);
    assert.equal(report.json.runtimeIncidents.responseChecklist.steps.some(function (s) { return s.id === "acknowledge-active-high-critical"; }), true);
    assert.equal(report.json.runtimeIncidents.responseChecklist.steps.some(function (s) { return s.id === "preserve-source-free-boundary"; }), true);
    assert.match(report.json.runtimeIncidents.sourceSha256, /^[a-f0-9]{64}$/);
    assert.match(report.markdown, /## Runtime incident evidence/);
    assert.match(report.markdown, /runtime-incidents\.csv/);
    assert.match(report.markdown, /Response window/);
    assert.match(report.markdown, /due=2026-06-06T10:16:00\.000Z/);
    assert.match(report.markdown, /Open\/reviewing high-or-critical \| 1/);
    assert.match(report.markdown, /Runtime incident response checklist/);
    assert.match(report.markdown, /preserve-source-free-boundary/);
    const alertSub = report.json.controls
        .find(function (c) { return c.id === "11.6.1"; })
        .subRequirements.find(function (s) { return s.id === "11.6.1.c"; });
    assert.equal(alertSub.status, "partial");
    assert.match(alertSub.detail, /Runtime incident CSV export summarizes 3 Dashboard Monitoring incidents/);
    assert.match(alertSub.evidence[0].artefact, /Dashboard Monitoring runtime incident CSV/);
});

test("pci-dss-v4: runtime incident JSON export summarizes Dashboard Monitoring evidence", function () {
    const dir = makeBuild("runtime-incidents-json");
    const key = "test-secret-runtime-incidents-json";
    const wm1 = writeProtectedFile(dir, "checkout.js", "checkout-json", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "checkout.js", source: wm1 },
    ], { label: "checkout-json", buildId: "build-checkout-json" });
    const jsonPath = writeRuntimeIncidentJson(dir, [
        {
            IncidentID: "301",
            Status: "Open",
            Severity: "High",
            Kind: "unknown-origin",
            Reason: "unknown third-party script",
            BuildID: "build-checkout-json",
            Fingerprint: "fp-json",
            PageUrl: "https://shop.example/checkout",
            RemoteIP: "203.0.113.9",
            EventUtc: "2026-06-06T12:10:00Z",
            ReceivedUtc: "2026-06-06T12:10:03Z",
            UserAgent: "JSON Browser",
        },
        {
            IncidentID: "302",
            Status: "Ignored",
            Severity: "Low",
            Kind: "heartbeat",
            Reason: "test release",
            BuildID: "build-checkout-json",
            Fingerprint: "fp-json",
            PageUrl: "https://shop.example/checkout",
            RemoteIP: "203.0.113.10",
            EventUtc: "2026-06-06T12:15:00Z",
            ReceivedUtc: "2026-06-06T12:15:03Z",
            UserAgent: "JSON Browser 2",
        },
    ], { status: "Active", severity: "HighOrCritical", buildId: "build-checkout-json" }, {
        sourceFree: true,
        escalationLevel: "urgent",
        recommendedQueue: "security-incident-response",
        preferredEvidence: "active-high-critical-json",
        recommendedAction: "Route this active high/critical packet to the security response queue.",
        responseTargetMinutes: 15,
        responseTargetLabel: "15 minutes",
        statusAction: "Move matching Open incidents to Reviewing.",
        filterContext: "status=Active, severity=HighOrCritical, buildId=build-checkout-json",
        buildId: "build-checkout-json",
        routeConfirmedIncidentsTo: ["customer-owned SIEM", "Splunk HEC", "signed webhook"],
        alertRoutingPlaybook: [
            {
                id: "security-response",
                lane: "Security response",
                owner: "dashboard security desk",
                trigger: "Active high/critical runtime incident",
                target: "15 minutes",
                evidence: "active-high-critical-json",
                action: "Move matching Open incidents to Reviewing and notify security response.",
                boundary: "Use source-free Dashboard Monitoring packet first.",
            },
            {
                id: "customer-owned-alerting",
                lane: "Customer-owned alerting",
                owner: "monitoring owner",
                trigger: "Confirmed production tamper signal",
                target: "Same response window",
                evidence: "Dashboard Monitoring JSON plus payload SHA-256",
                action: "Route confirmed production incidents to Splunk HEC and signed webhook.",
                boundary: "Long-term alert history stays in customer monitoring.",
            },
            {
                id: "support-handoff",
                lane: "JSO support handoff",
                owner: "account owner",
                trigger: "Support help is needed",
                target: "15 minutes",
                evidence: "Per-incident Evidence JSON",
                action: "Send BuildID, incident ID, payload SHA-256, and export file.",
                boundary: "Do not send raw source or provider credentials.",
            },
            {
                id: "reviewer-packet",
                lane: "Reviewer packet",
                owner: "review coordinator",
                trigger: "Build-scoped checkout review",
                target: "Before external review",
                evidence: "Filtered runtime incident JSON plus PCI DSS v4 evidence report",
                action: "Attach filtered export, response checklist, and response window.",
                boundary: "Filtered exports prove the selected view only.",
            },
        ],
    }, {
        sourceFree: true,
        filterScope: "status=Active, severity=HighOrCritical, buildId=build-checkout-json",
        routingScope: "level=urgent, queue=security-incident-response, evidence=active-high-critical-json, target=15 minutes",
        steps: [
            {
                id: "acknowledge-active-high-critical",
                owner: "dashboard security desk",
                target: "10 minutes",
                action: "Dashboard export says acknowledge this packet before the PCI reporter opens it.",
            },
            {
                id: "route-confirmed-incidents",
                owner: "security response owner",
                target: "15 minutes",
                action: "Route confirmed production incidents to Splunk HEC and signed webhook.",
            },
            {
                id: "dashboard-exported-step",
                owner: "dashboard reviewer",
                target: "before handoff",
                action: "Keep the dashboard-authored checklist intact.",
            },
        ],
    }, {
        sourceFree: true,
        basis: "oldest active high/critical receivedUtc",
        generatedUtc: "2026-06-06T12:00:00Z",
        targetMinutes: 15,
        targetLabel: "15 minutes",
        recommendedQueue: "security-incident-response",
        statusAction: "Move matching Open incidents to Reviewing.",
        oldestActiveReceivedUtc: "2026-06-06T12:10:03Z",
        oldestHighOrCriticalActiveReceivedUtc: "2026-06-06T12:10:03Z",
        responseDueUtc: "2026-06-06T12:25:03Z",
        overdue: false,
        windowState: "within-target",
    }, [
        {
            id: "mark-open-reviewing",
            label: "Move open in view to Reviewing",
            dashboardAction: "mark_filtered_reviewing",
            formFieldName: "runtime_action",
            formFieldValue: "mark_filtered_reviewing",
            method: "POST",
            sourceFree: true,
            requiresDashboardLogin: true,
            enabled: true,
            matchingOpenIncidentCount: 1,
            statusFrom: "Open",
            statusTo: "Reviewing",
            scope: "current account and selected status, severity, and BuildID filters",
            filterContext: "status=Active, severity=HighOrCritical, buildId=build-checkout-json",
            safety: "Leaves resolved, ignored, and already-reviewing incidents unchanged.",
            preserves: ["Resolved", "Ignored", "Reviewing"],
        },
    ]);
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        runtimeIncidentsPath: jsonPath,
        now: "2026-06-06T12:20:00Z",
    });
    assert.equal(report.json.runtimeIncidents.sourceFormat, "json");
    assert.equal(report.json.runtimeIncidents.count, 2);
    assert.equal(report.json.runtimeIncidents.statusCounts.Open, 1);
    assert.equal(report.json.runtimeIncidents.statusCounts.Ignored, 1);
    assert.equal(report.json.runtimeIncidents.unresolvedCount, 1);
    assert.equal(report.json.runtimeIncidents.unresolvedHighCriticalCount, 1);
    assert.deepEqual(report.json.runtimeIncidents.buildIds, ["build-checkout-json"]);
    assert.deepEqual(report.json.runtimeIncidents.filters, { status: "Active", severity: "HighOrCritical", buildId: "build-checkout-json" });
    assert.equal(report.json.runtimeIncidents.routing.escalationLevel, "urgent");
    assert.equal(report.json.runtimeIncidents.routing.recommendedQueue, "security-incident-response");
    assert.equal(report.json.runtimeIncidents.routing.preferredEvidence, "active-high-critical-json");
    assert.equal(report.json.runtimeIncidents.routing.responseTargetMinutes, 15);
    assert.equal(report.json.runtimeIncidents.routing.responseTargetLabel, "15 minutes");
    assert.equal(report.json.runtimeIncidents.routing.statusAction, "Move matching Open incidents to Reviewing.");
    assert.deepEqual(report.json.runtimeIncidents.routing.routeConfirmedIncidentsTo, ["customer-owned SIEM", "Splunk HEC", "signed webhook"]);
    assert.equal(report.json.runtimeIncidents.routing.alertRoutingPlaybook.length, 4);
    assert.equal(report.json.runtimeIncidents.routing.alertRoutingPlaybook[0].id, "security-response");
    assert.equal(report.json.runtimeIncidents.routing.alertRoutingPlaybook[0].lane, "Security response");
    assert.equal(report.json.runtimeIncidents.routing.alertRoutingPlaybook.some(function (s) {
        return s.id === "support-handoff" && s.evidence === "Per-incident Evidence JSON";
    }), true);
    assert.equal(report.json.runtimeIncidents.routing.alertRoutingPlaybook.some(function (s) {
        return s.id === "reviewer-packet" && /Filtered runtime incident JSON/.test(s.evidence);
    }), true);
    assert.equal(report.json.runtimeIncidents.responseWindow.sourceFree, true);
    assert.equal(report.json.runtimeIncidents.responseWindow.basis, "oldest active high/critical receivedUtc");
    assert.equal(report.json.runtimeIncidents.responseWindow.generatedUtc, "2026-06-06T12:00:00Z");
    assert.equal(report.json.runtimeIncidents.responseWindow.targetMinutes, 15);
    assert.equal(report.json.runtimeIncidents.responseWindow.responseDueUtc, "2026-06-06T12:25:03Z");
    assert.equal(report.json.runtimeIncidents.responseWindow.overdue, false);
    assert.equal(report.json.runtimeIncidents.responseWindow.windowState, "within-target");
    assert.equal(report.json.runtimeIncidents.responseChecklist.sourceFree, true);
    assert.equal(report.json.runtimeIncidents.responseChecklist.filterScope, "status=Active, severity=HighOrCritical, buildId=build-checkout-json");
    assert.equal(report.json.runtimeIncidents.responseChecklist.routingScope, "level=urgent, queue=security-incident-response, evidence=active-high-critical-json, target=15 minutes");
    const checklistStepIds = report.json.runtimeIncidents.responseChecklist.steps.map(function (s) { return s.id; });
    assert.equal(checklistStepIds.indexOf("acknowledge-active-high-critical") >= 0, true);
    assert.equal(checklistStepIds.indexOf("route-confirmed-incidents") >= 0, true);
    assert.equal(checklistStepIds.indexOf("dashboard-exported-step") >= 0, true);
    assert.equal(report.json.runtimeIncidents.responseChecklist.steps.some(function (s) {
        return s.owner === "dashboard security desk" && s.target === "10 minutes" && /Dashboard export says acknowledge/.test(s.action);
    }), true);
    assert.equal(report.json.runtimeIncidents.responseChecklist.steps.some(function (s) {
        return s.id === "route-confirmed-incidents" && /Splunk HEC/.test(s.action);
    }), true);
    assert.equal(report.json.runtimeIncidents.dashboardActions.length, 1);
    assert.equal(report.json.runtimeIncidents.dashboardActions[0].dashboardAction, "mark_filtered_reviewing");
    assert.equal(report.json.runtimeIncidents.dashboardActions[0].enabled, true);
    assert.equal(report.json.runtimeIncidents.dashboardActions[0].matchingOpenIncidentCount, 1);
    assert.match(report.markdown, /Dashboard Monitoring JSON export/);
    assert.match(report.markdown, /\| Export format \| JSON \|/);
    assert.match(report.markdown, /\| Filters \| status=Active, severity=HighOrCritical, buildId=build-checkout-json \|/);
    assert.match(report.markdown, /\| Routing \| level=urgent, queue=security-incident-response, evidence=active-high-critical-json, target=15 minutes \|/);
    assert.match(report.markdown, /\| Alert routing playbook \| security-response \(Security response\), customer-owned-alerting \(Customer-owned alerting\), support-handoff \(JSO support handoff\), reviewer-packet \(Reviewer packet\) \|/);
    assert.match(report.markdown, /\| Response window \| state=within-target, target=15 minutes, due=2026-06-06T12:25:03Z, overdue=no, basis=oldest active high\/critical receivedUtc \|/);
    assert.match(report.markdown, /Runtime incident alert routing playbook/);
    assert.match(report.markdown, /JSO support handoff/);
    assert.match(report.markdown, /Filtered runtime incident JSON plus PCI DSS v4 evidence report/);
    assert.match(report.markdown, /Runtime incident dashboard actions/);
    assert.match(report.markdown, /Move open in view to Reviewing/);
    assert.match(report.markdown, /Runtime incident response checklist/);
    assert.match(report.markdown, /route-confirmed-incidents/);
    assert.match(report.markdown, /dashboard-exported-step/);
    const alertSub = report.json.controls
        .find(function (c) { return c.id === "11.6.1"; })
        .subRequirements.find(function (s) { return s.id === "11.6.1.c"; });
    assert.equal(alertSub.status, "partial");
    assert.match(alertSub.detail, /Runtime incident JSON export summarizes 2 Dashboard Monitoring incidents; filters: status=Active, severity=HighOrCritical, buildId=build-checkout-json; .* routing: level=urgent, queue=security-incident-response, evidence=active-high-critical-json, target=15 minutes/);
    assert.match(alertSub.detail, /response window: state=within-target, target=15 minutes, due=2026-06-06T12:25:03Z, overdue=no/);
    assert.match(alertSub.detail, /alert routing playbook: security-response \(Security response\), customer-owned-alerting \(Customer-owned alerting\), support-handoff \(JSO support handoff\), reviewer-packet \(Reviewer packet\)/);
    assert.match(alertSub.detail, /dashboard actions: mark-open-reviewing \(Move open in view to Reviewing\) enabled, open=1/);
    assert.match(alertSub.evidence[0].artefact, /Dashboard Monitoring runtime incident JSON/);
    assert.match(alertSub.evidence[0].citation, /runtime_export=incidents-json/);
});

test("pci-dss-v4: script inventory JSON evidences payment-page authorization and justification", function () {
    const dir = makeBuild("script-inventory");
    const key = "test-secret-script-inventory";
    const wm1 = writeProtectedFile(dir, "checkout.js", "checkout-inventory", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "checkout.js", source: wm1 },
    ], { label: "checkout-inventory", buildId: "build-checkout-inventory" });
    const inventoryPath = writeScriptInventoryJson(dir, [
        {
            source: "https://js.stripe.com/v3/",
            authorized: true,
            justification: "Card tokenization provider.",
            owner: "Payments",
            category: "payment-provider",
            integrity: "provider-managed",
            lastReviewedUtc: "2026-06-01T00:00:00Z",
            checkoutSurface: "hosted-checkout",
            frameContext: "psp-iframe",
            frameOwner: "Payments",
            parentPageHref: "https://shop.example/checkout",
            frameHref: "https://checkout.stripe.example/frame",
            frameOrigin: "https://checkout.stripe.example",
            risk: "medium",
            dataAccess: "payment-tokenization",
            approvalTicket: "CHG-1001",
        },
        {
            source: "/assets/checkout.js",
            authorized: "approved",
            justification: "First-party checkout orchestration.",
            owner: "Payments",
            category: "first-party",
            integrity: "manifest-sha256",
            lastReviewedUtc: "2026-06-02T00:00:00Z",
            checkoutSurface: "parent-checkout",
            frameContext: "parent-page",
            frameOwner: "Web Platform",
            risk: "low",
            dataAccess: "checkout-state",
            approvalTicket: "CHG-1002",
        },
    ]);
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        scriptInventoryPath: inventoryPath,
        beaconUrl: "https://b.example/runtime",
        siemAdapter: "splunk-hec",
        now: "2026-06-06T12:30:00Z",
    });
    assert.equal(report.exitCode, 0);
    assert.equal(report.json.scriptInventory.sourceFormat, "json");
    assert.equal(report.json.scriptInventory.count, 2);
    assert.equal(report.json.scriptInventory.authorizedCount, 2);
    assert.equal(report.json.scriptInventory.missingJustificationCount, 0);
    assert.equal(report.json.scriptInventory.withIntegrityReferenceCount, 2);
    assert.equal(report.json.scriptInventory.withRiskRatingCount, 2);
    assert.equal(report.json.scriptInventory.withDataAccessCount, 2);
    assert.equal(report.json.scriptInventory.withApprovalTicketCount, 2);
    assert.equal(report.json.scriptInventory.withCheckoutSurfaceCount, 2);
    assert.equal(report.json.scriptInventory.withFrameContextCount, 2);
    assert.equal(report.json.scriptInventory.iframeScopedCount, 1);
    assert.deepEqual(report.json.scriptInventory.riskCounts, { low: 1, medium: 1 });
    assert.deepEqual(report.json.scriptInventory.dataAccessCounts, { "checkout-state": 1, "payment-tokenization": 1 });
    assert.deepEqual(report.json.scriptInventory.checkoutSurfaceCounts, { "hosted-checkout": 1, "parent-checkout": 1 });
    assert.deepEqual(report.json.scriptInventory.frameContextCounts, { "parent-page": 1, "psp-iframe": 1 });
    assert.deepEqual(report.json.scriptInventory.frameOwnerCounts, { Payments: 1, "Web Platform": 1 });
    assert.deepEqual(report.json.scriptInventory.domains, ["js.stripe.com"]);
    assert.match(report.markdown, /## Payment-page script inventory evidence/);
    assert.match(report.markdown, /\| Export format \| JSON \|/);
    assert.match(report.markdown, /\| With risk rating \| 2 \|/);
    assert.match(report.markdown, /\| Iframe-scoped scripts \| 1 \|/);
    assert.match(report.markdown, /\| Frame contexts \| parent-page: 1, psp-iframe: 1 \|/);
    assert.match(report.markdown, /\| Data access \| checkout-state: 1, payment-tokenization: 1 \|/);
    const inventorySub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.c"; });
    assert.equal(inventorySub.status, "pass");
    assert.match(inventorySub.detail, /with authorization and written justification/);
    assert.match(inventorySub.detail, /Review context coverage: risk ratings 2\/2, data-access scopes 2\/2, approval tickets 2\/2\./);
    assert.match(inventorySub.detail, /Checkout surface context: surfaces hosted-checkout: 1, parent-checkout: 1; frame contexts parent-page: 1, psp-iframe: 1; iframe-scoped scripts 1\./);
    assert.match(inventorySub.evidence[0].artefact, /script inventory JSON/);
});

test("pci-dss-v4: payment-page security header JSON summarizes CSP and baseline evidence", function () {
    const dir = makeBuild("security-headers");
    const key = "test-secret-security-headers";
    const wm1 = writeProtectedFile(dir, "checkout.js", "checkout-security-headers", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "checkout.js", source: wm1 },
    ], { label: "checkout-security-headers", buildId: "build-checkout-security-headers" });
    const headerPath = writeSecurityHeaderJson(dir, [
        {
            pageUrl: "https://shop.example/checkout",
            statusCode: 200,
            observedUtc: "2026-06-06T12:15:00Z",
            checkoutSurface: "parent-checkout",
            frameContext: "parent-page",
            frameOwner: "Web Platform",
            headers: {
                "content-security-policy": "default-src 'self'; script-src 'self' https://js.stripe.com; frame-src https://js.stripe.com; connect-src 'self' https://api.example.test; report-uri https://csp.example.test/report",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-frame-options": "DENY",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "payment=(self)",
            },
            headerSha256: "c".repeat(64),
            baselineSha256: "c".repeat(64),
            matchesBaseline: "match",
            monitor: "checkout-header-smoke",
            alertRoute: "security-response",
        },
        {
            pageUrl: "https://shop.example/checkout/frame",
            statusCode: 200,
            observedUtc: "2026-06-06T12:16:00Z",
            checkoutSurface: "psp-iframe",
            frameContext: "psp-iframe",
            frameOwner: "Payments",
            contentSecurityPolicy: "default-src 'none'; script-src https://js.stripe.com",
            contentSecurityPolicyReportOnly: "default-src 'none'; report-to csp-endpoint",
            reportingEndpoints: "csp-endpoint=\"https://csp.example.test/report\"",
            headerSha256: "d".repeat(64),
            baselineSha256: "c".repeat(64),
            matchesBaseline: "changed",
            monitor: "checkout-header-smoke",
            alertRoute: "security-response",
        },
        {
            pageUrl: "https://shop.example/checkout/new-wallet-frame",
            statusCode: 200,
            observedUtc: "2026-06-06T12:17:00Z",
            checkoutSurface: "wallet-frame",
            frameContext: "embedded-frame",
            frameOwner: "Checkout",
            contentSecurityPolicy: "default-src 'self'; script-src 'self'",
            headerSha256: "e".repeat(64),
            baselineSha256: "",
            matchesBaseline: "missing",
            monitor: "checkout-header-smoke",
            alertRoute: "security-response",
        },
    ]);
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        securityHeadersPath: headerPath,
        beaconUrl: "https://b.example/runtime",
        siemAdapter: "splunk-hec",
        now: "2026-06-06T12:50:00Z",
    });

    assert.equal(report.exitCode, 0);
    assert.equal(report.json.securityHeaders.sourceFormat, "json");
    assert.equal(report.json.securityHeaders.count, 3);
    assert.equal(report.json.securityHeaders.withCspCount, 3);
    assert.equal(report.json.securityHeaders.withScriptSrcCount, 3);
    assert.equal(report.json.securityHeaders.withFrameSrcCount, 1);
    assert.equal(report.json.securityHeaders.withReportEndpointCount, 2);
    assert.equal(report.json.securityHeaders.withHstsCount, 1);
    assert.equal(report.json.securityHeaders.baselineMatchCount, 1);
    assert.equal(report.json.securityHeaders.baselineMismatchCount, 1);
    assert.equal(report.json.securityHeaders.baselineMissingCount, 1);
    assert.equal(report.json.reviewAssistant.questions.some(function (item) { return item.topic === "Header change evidence"; }), true);
    assert.deepEqual(report.json.securityHeaders.checkoutSurfaceCounts, { "parent-checkout": 1, "psp-iframe": 1, "wallet-frame": 1 });
    assert.deepEqual(report.json.securityHeaders.frameContextCounts, { "embedded-frame": 1, "parent-page": 1, "psp-iframe": 1 });
    assert.deepEqual(report.json.securityHeaders.domains, ["shop.example"]);
    assert.equal(report.json.securityHeaders.reviewAssistant.sourceFree, true);
    assert.match(report.json.securityHeaders.reviewAssistant.intendedUse, /BYO AI key/);
    assert.equal(report.json.securityHeaders.reviewAssistant.doNotInclude.includes("raw response headers"), true);
    assert.equal(report.json.securityHeaders.reviewAssistant.questions.some(function (item) { return item.topic === "Baseline drift"; }), true);
    assert.equal(report.json.securityHeaders.reviewAssistant.questions.some(function (item) { return item.topic === "CSP reporting"; }), true);
    assert.match(report.markdown, /## Payment-page security-header evidence/);
    assert.match(report.markdown, /\| With report endpoint \| 2 \|/);
    assert.match(report.markdown, /\| Baseline coverage \| 1 match, 1 mismatch, 1 missing, 0 not stated \|/);
    assert.match(report.markdown, /\| Review assistant packet \| source-free \|/);
    assert.match(report.markdown, /### Security Header Review Assistant/);
    assert.match(report.markdown, /Header change evidence/);
    const changeSub = report.json.controls
        .find(function (c) { return c.id === "11.6.1"; })
        .subRequirements.find(function (s) { return s.id === "11.6.1.a"; });
    assert.match(changeSub.detail, /Payment-page security-header JSON snapshot covers 3 pages/);
    assert.match(changeSub.detail, /1 baseline mismatch/);
    assert.match(changeSub.detail, /1 baseline missing/);
    assert.match(changeSub.detail, /source-free review assistant packet/);
    assert.ok(changeSub.evidence.some(function (e) { return /security-header JSON/.test(e.artefact); }));
});

test("pci-dss-v4: script inventory gaps downgrade authorization and justification evidence", function () {
    const dir = makeBuild("script-inventory-gaps");
    const key = "test-secret-script-inventory-gaps";
    const wm1 = writeProtectedFile(dir, "checkout.js", "checkout-inventory-gaps", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "checkout.js", source: wm1 },
    ], { label: "checkout-inventory-gaps", buildId: "build-checkout-inventory-gaps" });
    const inventoryPath = writeScriptInventoryJson(dir, [
        {
            source: "https://unknown.example/skimmer.js",
            authorized: false,
            justification: "",
            owner: "",
            category: "unknown",
            lastReviewedUtc: "2026-06-03T00:00:00Z",
        },
    ]);
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        scriptInventoryPath: inventoryPath,
        beaconUrl: "https://b.example/runtime",
        siemAdapter: "splunk-hec",
        now: "2026-06-06T12:40:00Z",
    });
    assert.equal(report.exitCode, 1);
    assert.equal(report.json.scriptInventory.unauthorizedCount, 1);
    assert.equal(report.json.scriptInventory.missingJustificationCount, 1);
    const authSub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.a"; });
    const inventorySub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.c"; });
    assert.equal(authSub.status, "partial");
    assert.equal(inventorySub.status, "partial");
    assert.match(authSub.detail, /marked unauthorized/);
    assert.match(inventorySub.detail, /lack written justification/);
});

test("pci-dss-v4: script inventory audit JSON summarizes approved-vs-observed drift", function () {
    const dir = makeBuild("script-inventory-audit");
    const key = "test-secret-script-inventory-audit";
    const wm1 = writeProtectedFile(dir, "checkout.js", "checkout-inventory-audit", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "checkout.js", source: wm1 },
    ], { label: "checkout-inventory-audit", buildId: "build-checkout-inventory-audit" });
    const inventoryPath = writeScriptInventoryJson(dir, [{
        source: "https://js.stripe.com/v3/",
        authorized: true,
        justification: "Card tokenization provider.",
        owner: "Payments",
        category: "payment-provider",
        integrity: "provider-managed",
        lastReviewedUtc: "2026-06-06T08:00:00Z",
    }]);
    const auditPath = writeScriptInventoryAuditJson(dir, {
        approvedScripts: 1,
        observedScripts: 2,
        unknownObserved: 1,
        runtimeViolations: 1,
        blockingIssues: 2,
    });
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        scriptInventoryPath: inventoryPath,
        scriptInventoryAuditPath: auditPath,
        beaconUrl: "https://b.example/runtime",
        siemAdapter: "splunk-hec",
        now: "2026-06-06T12:45:00Z",
    });

    assert.equal(report.exitCode, 1);
    assert.equal(report.json.scriptInventoryAudit.ok, false);
    assert.equal(report.json.scriptInventoryAudit.unknownObserved, 1);
    assert.equal(report.json.scriptInventoryAudit.blockingIssues, 2);
    assert.match(report.markdown, /## Payment-page script inventory audit evidence/);
    assert.match(report.markdown, /\| Audit status \| NEEDS REVIEW \|/);
    const authSub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.a"; });
    const inventorySub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.c"; });
    assert.equal(authSub.status, "partial");
    assert.match(authSub.detail, /audit found 1 unknown observed script/);
    assert.equal(inventorySub.status, "partial");
    assert.match(inventorySub.detail, /Script inventory audit needs review/);
    assert.match(inventorySub.evidence.map(function (e) { return e.artefact; }).join(" "), /script inventory audit JSON/);
});

test("pci-dss-v4: missing watermark key downgrades 6.4.3.a to partial", function () {
    const dir = makeBuild("nowmkey");
    const key = "secret-XYZ";
    const wm1 = writeProtectedFile(dir, "app.js", "vX", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "app.js", source: wm1 },
    ], { label: "vX" });
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        // intentionally no watermarkKey
        beaconUrl: "https://b.example/x",
        siemAdapter: "elasticsearch",
        now: "2026-06-02T12:00:00Z",
    });
    const sub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.a"; });
    assert.equal(sub.status, "partial");
    assert.match(sub.detail, /not validated/);
    assert.equal(report.exitCode, 1);
});

test("pci-dss-v4: tampered file => stage-2 mismatch + 6.4.3.b FAIL", function () {
    const dir = makeBuild("tamper");
    const key = "k1";
    const wm1 = writeProtectedFile(dir, "app.js", "vT", key);
    const { sigPath } = buildSignedManifest(dir, [
        { name: "app.js", source: wm1 },
    ], { label: "vT" });
    // Mutate the file AFTER signing.
    fs.writeFileSync(path.join(dir, "app.js"), wm1 + "\n// tampered\n", "utf8");
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        beaconUrl: "https://b.example",
        siemAdapter: "webhook",
        now: "2026-06-02T12:00:00Z",
    });
    const sub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.b"; });
    assert.equal(sub.status, "fail", "6.4.3.b should fail when stage-2 mismatches");
    assert.equal(report.exitCode, 1);
    // The inventory row must label the tampered file as MISMATCH.
    assert.match(report.markdown, /MISMATCH/);
});

test("pci-dss-v4: unsigned manifest without --allow-unsigned throws", function () {
    const dir = makeBuild("unsigned-strict");
    const bare = {
        buildId: "x", polymorphismFingerprint: "y", label: "z",
        files: [{ name: "a.js", sha256: crypto.createHash("sha256").update("a").digest("hex") }],
    };
    const p = path.join(dir, "build.manifest.json");
    fs.writeFileSync(p, JSON.stringify(bare), "utf8");
    assert.throws(function () {
        compliance.generateReport({ manifestPath: p });
    }, /not a signed envelope/);
});

test("pci-dss-v4: --allow-unsigned produces exit-2 partial report", function () {
    const dir = makeBuild("unsigned-allow");
    const bare = {
        buildId: "x", polymorphismFingerprint: "y", label: "z",
        files: [{ name: "a.js", sha256: crypto.createHash("sha256").update("a").digest("hex") }],
    };
    const p = path.join(dir, "build.manifest.json");
    fs.writeFileSync(p, JSON.stringify(bare), "utf8");
    const report = compliance.generateReport({
        manifestPath: p,
        includeUnsignedManifest: true,
        now: "2026-06-02T12:00:00Z",
    });
    assert.equal(report.exitCode, 2);
    assert.equal(report.summary.signatureKind, "none");
    const sub = report.json.controls
        .find(function (c) { return c.id === "6.4.3"; })
        .subRequirements.find(function (s) { return s.id === "6.4.3.b"; });
    assert.equal(sub.status, "fail");
});

test("pci-dss-v4: missing manifest path throws fast", function () {
    assert.throws(function () {
        compliance.generateReport({ manifestPath: "/nonexistent/path/manifest.sig" });
    }, /manifest not found/);
});

test("pci-dss-v4: beacon URL without SIEM downgrades 11.6.1.c to partial", function () {
    const dir = makeBuild("beacon-no-siem");
    const key = "k";
    const wm1 = writeProtectedFile(dir, "x.js", "v", key);
    const { sigPath } = buildSignedManifest(dir, [{ name: "x.js", source: wm1 }], { label: "v" });
    const report = compliance.generateReport({
        manifestPath: sigPath,
        rootDir: dir,
        watermarkKey: key,
        beaconUrl: "https://beacon",
        // no siemAdapter
        now: "2026-06-02T12:00:00Z",
    });
    const sub = report.json.controls
        .find(function (c) { return c.id === "11.6.1"; })
        .subRequirements.find(function (s) { return s.id === "11.6.1.c"; });
    assert.equal(sub.status, "partial");
});

test("pci-dss-v4 CLI: --json prints valid envelope, exit code propagates", function () {
    const dir = makeBuild("cli-json");
    const key = "k";
    const wm1 = writeProtectedFile(dir, "a.js", "v", key);
    const { sigPath } = buildSignedManifest(dir, [{ name: "a.js", source: wm1 }], { label: "v" });
    const inventoryPath = writeScriptInventoryJson(dir, [{
        source: "https://cdn.example.test/pay.js",
        authorized: true,
        justification: "Payment widget used on checkout.",
        owner: "Payments",
        category: "payment-provider",
        integrity: "provider-managed",
        lastReviewedUtc: "2026-06-06T08:00:00Z",
    }]);
    const auditPath = writeScriptInventoryAuditJson(dir);
    const headerPath = writeSecurityHeaderJson(dir, [{
        pageUrl: "https://example.test/checkout",
        statusCode: 200,
        observedUtc: "2026-06-06T09:00:00Z",
        headers: {
            "content-security-policy": "default-src 'self'; script-src 'self'; frame-src https://pay.example.test",
            "strict-transport-security": "max-age=31536000",
        },
        headerSha256: "e".repeat(64),
        baselineSha256: "e".repeat(64),
        matchesBaseline: "match",
        monitor: "checkout-header-smoke",
    }]);
    const jsonPath = writeRuntimeIncidentJson(dir, [{
        IncidentID: "201",
        Status: "Resolved",
        Severity: "Low",
        Kind: "heartbeat",
        Reason: "release smoke",
        BuildID: "cli-build",
        Fingerprint: "fp-cli",
        PageUrl: "https://example.test/checkout",
        RemoteIP: "198.51.100.8",
        EventUtc: "2026-06-06T09:00:00Z",
        ReceivedUtc: "2026-06-06T09:00:01Z",
        UserAgent: "Node test",
    }]);
    const r = spawnSync(NODE, [
        BIN, "compliance", "pci-dss-v4",
        "--manifest", sigPath,
        "--root", dir,
        "--watermark-key", key,
        "--beacon-url", "https://b.example",
        "--siem", "splunk-hec",
        "--script-inventory", inventoryPath,
        "--script-inventory-audit", auditPath,
        "--payment-page-headers", headerPath,
        "--runtime-incidents", jsonPath,
        "--organization", "ACME",
        "--json",
    ], { encoding: "utf8" });
    assert.equal(r.status, 0, "exit code 0; stderr: " + r.stderr);
    const env = JSON.parse(r.stdout);
    assert.equal(env.v, compliance.REPORT_SCHEMA_VERSION);
    assert.equal(env.standard, "PCI DSS");
    assert.equal(env.organizationName, "ACME");
    assert.equal(env.scriptInventory.count, 1);
    assert.equal(env.scriptInventory.authorizedCount, 1);
    assert.equal(env.scriptInventoryAudit.ok, true);
    assert.equal(env.scriptInventoryAudit.blockingIssues, 0);
    assert.equal(env.securityHeaders.count, 1);
    assert.equal(env.securityHeaders.withCspCount, 1);
    assert.equal(env.runtimeIncidents.sourceFormat, "json");
    assert.equal(env.runtimeIncidents.count, 1);
    assert.equal(env.runtimeIncidents.statusCounts.Resolved, 1);
    assert.equal(env.summary.exitCode, 0);
    assert.equal(env.reviewAssistant.sourceFree, true);
    assert.equal(env.reviewAssistant.questions.some(function (item) { return item.topic === "QSA handoff boundary"; }), true);
});

test("pci-dss-v4 CLI: --output writes Markdown to disk, prints status to stderr", function () {
    const dir = makeBuild("cli-md");
    const key = "k";
    const wm1 = writeProtectedFile(dir, "a.js", "v", key);
    const { sigPath } = buildSignedManifest(dir, [{ name: "a.js", source: wm1 }], { label: "v" });
    const outPath = path.join(dir, "report.md");
    const r = spawnSync(NODE, [
        BIN, "compliance", "pci-dss-v4",
        "--manifest", sigPath,
        "--root", dir,
        "--watermark-key", key,
        "--beacon-url", "https://b.example",
        "--siem", "webhook",
        "--output", outPath,
    ], { encoding: "utf8" });
    assert.equal(r.status, 0, "exit 0; stderr=" + r.stderr);
    assert.ok(fs.existsSync(outPath), "output file should be written");
    const md = fs.readFileSync(outPath, "utf8");
    assert.match(md, /# PCI DSS v/);
    assert.match(md, /## PCI DSS Review Assistant/);
    assert.match(md, /6\.4\.3/);
});

test("pci-dss-v4 CLI: missing --manifest exits 2", function () {
    const r = spawnSync(NODE, [BIN, "compliance", "pci-dss-v4"], { encoding: "utf8" });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--manifest <path> is required/);
});

test("pci-dss-v4 CLI: unknown framework exits 2", function () {
    const r = spawnSync(NODE, [BIN, "compliance", "soc-2-evidence"], { encoding: "utf8" });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /Unknown compliance framework/);
});

test("pci-dss-v4 CLI: --help prints usage and exits 0", function () {
    const r = spawnSync(NODE, [BIN, "compliance", "--help"], { encoding: "utf8" });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /jso-protector compliance <framework>/);
    assert.match(r.stdout, /pci-dss-v4/);
    assert.match(r.stdout, /--runtime-incidents/);
    assert.match(r.stdout, /--script-inventory/);
    assert.match(r.stdout, /--payment-page-headers/);
    assert.match(r.stdout, /<csv\|json>/);
});
