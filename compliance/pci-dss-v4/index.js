"use strict";

// PCI DSS v4.0.1 compliance reporter.
//
// Consumes the manifest + signed envelope produced by --sign-release and
// maps the JSO protection primitives onto the PCI DSS v4 controls JSO
// helps evidence (6.4.3 and 11.6.1). Emits a Markdown report an auditor
// or QSA can read directly, and a parallel JSON envelope for tooling.
//
// The reporter is pure data-shaping: it does NOT call the JSO HTTP API
// and it does NOT phone home. All evidence comes from artefacts already
// on disk (the manifest.json + manifest.json.sig + optional --root dir).
//
// Public API
// ----------
//   generateReport(opts) -> { markdown, json, summary, exitCode }
//
// opts:
//   manifestPath        string (required) -- path to .manifest.json.sig
//                       or to a bare manifest.json (less evidence)
//   rootDir             string (optional) -- if set, re-hash files on
//                       disk and confirm they still match the manifest
//   organizationName    string (optional) -- shown in the report header
//   buildLabel          string (optional) -- override the manifest label
//   watermarkKey        string (optional) -- if set, validate per-file
//                       watermark HMACs against this key (treated as the
//                       same shared secret the customer used at build)
//   beaconUrl           string (optional) -- URL of the configured beacon
//                       callback. If present, the 11.6.1.c evidence row
//                       gets "Wired" status; if absent, "Not configured".
//   siemAdapter         string (optional) -- one of "splunk-hec",
//                       "elasticsearch", "webhook". If set, the report
//                       names the forwarder.
//   scriptInventoryPath string (optional) -- CSV or JSON payment-page script
//                       inventory. The report summarizes authorization,
//                       justification, owner, review-date, and integrity
//                       coverage without embedding every raw script URL.
//   scriptInventoryAuditPath string (optional) -- JSON output from
//                       `jso-protector --script-inventory-audit --json`.
//                       The report summarizes approved-vs-observed drift
//                       without embedding every raw finding row in controls.
//   securityHeadersPath string (optional) -- CSV or JSON payment-page
//                       security-header snapshot. The report summarizes CSP,
//                       frame/HSTS/referrer-policy, baseline hash, monitor,
//                       and alert-route evidence without embedding every URL.
//   runtimeIncidentsPath string (optional) -- CSV or JSON exported from
//                       Dashboard Monitoring. The report summarizes incident
//                       counts, triage status, severity, date range, and
//                       Build IDs without embedding each row's URL/user-agent
//                       data in Markdown.
//   includeUnsignedManifest  bool   -- accept bare manifest.json (no .sig).
//                       Default false. When false, a bare manifest
//                       triggers exitCode=2 (incomplete evidence) and the
//                       6.4.3.b row reads "Not signed".

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const releaseSigner = require("../../release-signer.js");
const watermark = require("../../watermark.js");
const controlsRef = require("./controls.json");

const REPORT_SCHEMA_VERSION = 1;

function generateReport(opts) {
    if (!opts || typeof opts !== "object") {
        throw new Error("generateReport: opts is required");
    }
    if (!opts.manifestPath || typeof opts.manifestPath !== "string") {
        throw new Error("generateReport: opts.manifestPath is required");
    }
    if (!fs.existsSync(opts.manifestPath)) {
        throw new Error("generateReport: manifest not found: " + opts.manifestPath);
    }

    const evidence = collectEvidence(opts);
    const controls = mapControls(evidence, controlsRef);
    const summary = buildSummary(controls, evidence);
    const reviewAssistant = buildPciDssReviewAssistant(summary, controls, evidence);
    const markdown = renderMarkdown({
        organizationName: opts.organizationName || "",
        buildLabel: opts.buildLabel || evidence.manifest.label || "",
        generatedAt: opts.now || new Date().toISOString(),
        evidence: evidence,
        controls: controls,
        summary: summary,
        reviewAssistant: reviewAssistant,
    });
    return {
        markdown: markdown,
        json: {
            v: REPORT_SCHEMA_VERSION,
            standard: controlsRef._meta.standard,
            version: controlsRef._meta.version,
            generatedAt: opts.now || new Date().toISOString(),
            organizationName: opts.organizationName || null,
            buildLabel: opts.buildLabel || evidence.manifest.label || null,
            buildId: evidence.manifest.buildId || null,
            polymorphismFingerprint: evidence.manifest.polymorphismFingerprint || null,
            files: evidence.files,
            scriptInventory: evidence.scriptInventory,
            scriptInventoryAudit: evidence.scriptInventoryAudit,
            securityHeaders: evidence.securityHeaders,
            runtimeIncidents: evidence.runtimeIncidents,
            controls: controls,
            summary: summary,
            reviewAssistant: reviewAssistant,
        },
        summary: summary,
        // exitCode: 0=fully evidenced, 1=evidence gaps that need
        // operator action, 2=manifest is unsigned or unreadable.
        exitCode: summary.exitCode,
    };
}

function collectEvidence(opts) {
    const raw = JSON.parse(fs.readFileSync(opts.manifestPath, "utf8"));

    // Distinguish a signed envelope from a bare manifest.json. The
    // signed envelope has top-level .manifest + .signature + .publicKey.
    const isSignedEnvelope = !!(raw && raw.manifest && raw.signature && raw.publicKey);

    let manifest;
    let signatureStatus;
    let publicKeyDigest = null;

    if (isSignedEnvelope) {
        manifest = raw.manifest;
        // Verify the embedded signature. release-signer.verifyRelease
        // returns { valid, stage1, stage2, mismatches, error }. Stage 2
        // only fires when we pass verifyRoot.
        try {
            // release-signer.verifyRelease() reads opts.fileRoot (not
            // verifyRoot) for the stage-2 on-disk re-hash pass.
            const verifyResult = releaseSigner.verifyRelease(raw, {
                fileRoot: opts.rootDir || null,
            });
            signatureStatus = {
                kind: "ed25519",
                verified: !!verifyResult.valid,
                stage1: !!verifyResult.stage1,
                stage2: !!verifyResult.stage2,
                detail: verifyResult.valid
                    ? "Signature valid; manifest is genuine."
                    : ("Signature INVALID: " + (verifyResult.error || "unknown")),
                mismatches: Array.isArray(verifyResult.mismatches) ? verifyResult.mismatches : [],
            };
        } catch (x) {
            signatureStatus = {
                kind: "ed25519",
                verified: false,
                stage1: false,
                stage2: false,
                detail: "Signature verification threw: " + x.message,
                mismatches: [],
            };
        }
        // Compute a stable identifier for the signing key so the auditor
        // can confirm two reports were signed by the same release key.
        try {
            const pubDer = Buffer.from(raw.publicKey, "base64");
            publicKeyDigest = crypto.createHash("sha256").update(pubDer).digest("hex");
        } catch (x) { publicKeyDigest = null; }
    } else if (opts.includeUnsignedManifest) {
        manifest = raw;
        signatureStatus = {
            kind: "none",
            verified: false,
            stage1: false,
            stage2: false,
            detail: "Manifest is unsigned. PCI DSS v4 req 6.4.3.b cannot be evidenced without --sign-release.",
            mismatches: [],
        };
    } else {
        throw new Error(
            "generateReport: manifest at " + opts.manifestPath + " is not a signed envelope. " +
            "Re-run with --sign-release to produce a .manifest.json.sig, or pass " +
            "{includeUnsignedManifest:true} to allow a partial report."
        );
    }

    if (!manifest || !Array.isArray(manifest.files)) {
        throw new Error("generateReport: manifest is missing files[]");
    }

    // Per-file watermark coverage. If --watermark-key was supplied, we
    // attempt to validate every file's watermark; otherwise we only
    // attempt to detect presence (no signature check). When --root is
    // provided we read the actual file bytes; otherwise the row stays
    // "not inspected".
    const files = manifest.files.map(function (f) {
        const row = {
            name: f.name,
            sha256: f.sha256,
            watermark: { inspected: false, present: false, valid: null, tag: null },
            ondiskSha256: null,
            ondiskMatches: null,
        };
        if (opts.rootDir) {
            const fullPath = path.join(opts.rootDir, f.name);
            if (fs.existsSync(fullPath)) {
                // Read raw bytes (Buffer), not utf8 — otherwise any
                // non-UTF-8 byte in a protected file (BOM, binary
                // asset, lone surrogate) makes the locally computed
                // sha256 disagree with release-signer.sha256OfFile
                // (which hashes raw bytes) and the row would
                // mis-report ondiskMatches=false even when stage-2
                // signature verification passed.
                let buf;
                try { buf = fs.readFileSync(fullPath); } catch (x) { buf = null; }
                if (buf != null) {
                    row.ondiskSha256 = crypto.createHash("sha256").update(buf).digest("hex");
                    row.ondiskMatches = (row.ondiskSha256 === f.sha256);
                    row.watermark.inspected = true;
                    try {
                        // watermark.verify accepts strings; coerce
                        // only here so the hash above stays byte-exact.
                        const r = watermark.verify(buf.toString("utf8"), opts.watermarkKey || undefined);
                        if (r && r.present) {
                            row.watermark.present = true;
                            row.watermark.tag = r.tag || null;
                            row.watermark.valid = opts.watermarkKey ? !!r.valid : null;
                        }
                    } catch (x) { /* swallow; row reports absence */ }
                }
            }
        }
        return row;
    });

    const runtimeIncidents = opts.runtimeIncidentsPath
        ? collectRuntimeIncidentEvidence(opts.runtimeIncidentsPath)
        : null;
    const scriptInventory = opts.scriptInventoryPath
        ? collectScriptInventoryEvidence(opts.scriptInventoryPath)
        : null;
    const scriptInventoryAudit = opts.scriptInventoryAuditPath
        ? collectScriptInventoryAuditEvidence(opts.scriptInventoryAuditPath)
        : null;
    const securityHeaders = opts.securityHeadersPath
        ? collectSecurityHeaderEvidence(opts.securityHeadersPath)
        : null;

    return {
        manifest: manifest,
        signatureStatus: signatureStatus,
        publicKeyDigest: publicKeyDigest,
        files: files,
        beaconUrl: opts.beaconUrl || null,
        siemAdapter: opts.siemAdapter || null,
        scriptInventory: scriptInventory,
        scriptInventoryAudit: scriptInventoryAudit,
        securityHeaders: securityHeaders,
        runtimeIncidents: runtimeIncidents,
    };
}

function mapControls(evidence, ref) {
    const watermarkCoverage = computeWatermarkCoverage(evidence.files);
    return ref.controls.map(function (control) {
        const subRows = control.subRequirements.map(function (sub) {
            const status = evaluateSubRequirement(sub, evidence, watermarkCoverage);
            return Object.assign({}, sub, status);
        });
        const allPass = subRows.every(function (r) { return r.status === "pass"; });
        const anyFail = subRows.some(function (r) { return r.status === "fail"; });
        return {
            id: control.id,
            title: control.title,
            status: anyFail ? "fail" : (allPass ? "pass" : "partial"),
            subRequirements: subRows,
        };
    });
}

function evaluateSubRequirement(sub, evidence, watermarkCoverage) {
    // Pure data lookup; no side effects, no I/O.
    const evidenceRows = [];
    let status = "fail";
    let detail = "";
    switch (sub.id) {
    case "6.4.3.a":
        if (watermarkCoverage.allValid) {
            status = "pass";
            detail = "All " + watermarkCoverage.total + " files carry a watermark with a valid signature under the supplied key.";
        } else if (watermarkCoverage.allPresent) {
            status = "partial";
            detail = "All " + watermarkCoverage.total + " files carry a watermark, but signatures are not validated (pass --watermark-key to verify).";
        } else if (watermarkCoverage.anyPresent) {
            status = "partial";
            detail = watermarkCoverage.withWatermark + "/" + watermarkCoverage.total + " files carry a watermark.";
        } else if (!watermarkCoverage.inspected) {
            status = "not_inspected";
            detail = "Pass --root <dir> to walk the protected files on disk and report watermark coverage.";
        } else {
            status = "fail";
            detail = "No watermarks detected. Re-run jso-protector with --watermark <tag> --watermark-key <secret>.";
        }
        if (hasScriptInventoryRows(evidence)) {
            const si = evidence.scriptInventory;
            if (si.unauthorizedCount > 0 || si.unknownAuthorizationCount > 0) {
                if (status === "pass") status = "partial";
                detail += " " + si.unauthorizedCount + " script(s) are marked unauthorized and " + si.unknownAuthorizationCount + " have unknown authorization in the supplied script inventory.";
            } else {
                detail += " Script inventory marks all " + si.count + " payment-page script(s) as authorized.";
            }
            pushScriptInventoryEvidence(evidenceRows, evidence);
        }
        if (hasScriptInventoryAudit(evidence)) {
            const audit = evidence.scriptInventoryAudit;
            if (audit.unknownObserved > 0 || audit.unauthorizedObserved > 0) {
                if (status === "pass") status = "partial";
                detail += " Script inventory audit found " + audit.unknownObserved + " unknown observed script(s) and " + audit.unauthorizedObserved + " unauthorized observed script(s).";
            } else {
                detail += " Script inventory audit found no unknown or unauthorized observed scripts.";
            }
            pushScriptInventoryAuditEvidence(evidenceRows, evidence);
        }
        evidenceRows.push({
            artefact: "HMAC-SHA256 watermark per file",
            location: "Protected file header comment",
            citation: "jso-protector --watermark / watermark.js",
        });
        break;
    case "6.4.3.b":
        if (evidence.signatureStatus.kind === "ed25519" && evidence.signatureStatus.verified) {
            status = "pass";
            detail = evidence.signatureStatus.detail;
            evidenceRows.push({
                artefact: "Ed25519 release attestation",
                location: ".manifest.json.sig (publicKeyDigest=" + (evidence.publicKeyDigest || "n/a").slice(0, 16) + "...)",
                citation: "jso-protector --sign-release / release-signer.js",
            });
            if (evidence.signatureStatus.stage2) {
                evidenceRows.push({
                    artefact: "Stage-2 on-disk re-hash (all files match manifest sha256)",
                    location: "--root <dir> verification pass",
                    citation: "release-signer.verifyRelease() stage 2",
                });
            }
        } else if (evidence.signatureStatus.kind === "ed25519") {
            status = "fail";
            detail = evidence.signatureStatus.detail;
        } else {
            status = "fail";
            detail = evidence.signatureStatus.detail;
        }
        break;
    case "6.4.3.c":
        if (hasScriptInventoryRows(evidence)) {
            const si = evidence.scriptInventory;
            if (si.missingJustificationCount === 0) {
                status = "pass";
                detail = "Script inventory export records " + si.count + " payment-page script(s) with authorization and written justification. Manifest files[] still provides the protected first-party file inventory (" + evidence.files.length + " files).";
            } else {
                status = "partial";
                detail = "Script inventory export records " + si.count + " payment-page script(s), but " + si.missingJustificationCount + " lack written justification. Fill justification before audit handoff.";
            }
            detail += scriptInventoryReviewContextDetail(si);
            pushScriptInventoryEvidence(evidenceRows, evidence);
            evidenceRows.push({
                artefact: "manifest.json files[] array",
                location: "Path supplied to --manifest",
                citation: "release-signer.signRelease().manifest.files",
            });
        } else if (Array.isArray(evidence.files) && evidence.files.length > 0) {
            status = "pass";
            detail = "Manifest files[] is the technical inventory (" + evidence.files.length + " files). buildId + polymorphismFingerprint trace each entry back to a JSO build run. Pass --script-inventory <csv|json> when a reviewer needs written business justification for every payment-page script.";
            evidenceRows.push({
                artefact: "manifest.json files[] array",
                location: "Path supplied to --manifest",
                citation: "release-signer.signRelease().manifest.files",
            });
        } else {
            status = "fail";
            detail = "Manifest contains no files.";
        }
        if (hasScriptInventoryAudit(evidence)) {
            const audit = evidence.scriptInventoryAudit;
            if (!audit.ok) {
                if (status === "pass") status = "partial";
                detail += scriptInventoryAuditDetail(evidence);
            } else {
                detail += " Script inventory audit reconciles the approved inventory against the observed runtime snapshot with no blocking issues.";
            }
            pushScriptInventoryAuditEvidence(evidenceRows, evidence);
        }
        break;
    case "11.6.1.a":
        // We can't, from a static manifest, prove the protected files
        // actually enable the runtime-defense modules. But we can flag
        // whether SelfDefending / integrity-heartbeat are evidenced by
        // the build options if the customer ran with the recommended
        // config. For now we report "needs_attestation" unless the
        // beacon URL is wired (a strong proxy for the defense suite).
        if (evidence.beaconUrl) {
            status = "pass";
            detail = "Runtime Defense beacon is configured (" + redactUrl(evidence.beaconUrl) + "). Tamper events fire on integrity heartbeat or self-defending checks." + runtimeIncidentDetail(evidence);
            evidenceRows.push({
                artefact: "BeaconUrl + Runtime Defense suite",
                location: "Build option BeaconUrl + runtime/defense.ts",
                citation: "Docs/RuntimeDefense.aspx",
            });
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else if (hasRuntimeIncidentRows(evidence)) {
            status = "partial";
            detail = "Dashboard Monitoring incident evidence was supplied, but no BeaconUrl was supplied to the reporter. Re-run with --beacon-url <url> to tie this build report to the runtime-defense endpoint." + runtimeIncidentDetail(evidence);
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else {
            status = "partial";
            detail = "Runtime Defense modules can be enabled (SelfDefending, integrity heartbeat) but no BeaconUrl was supplied to the reporter. Re-run with --beacon-url <url> to evidence this row.";
        }
        if (hasScriptInventoryAudit(evidence)) {
            detail += scriptInventoryAuditDetail(evidence);
            pushScriptInventoryAuditEvidence(evidenceRows, evidence);
        }
        if (hasSecurityHeaderEvidence(evidence)) {
            detail += securityHeaderDetail(evidence);
            pushSecurityHeaderEvidence(evidenceRows, evidence);
        }
        break;
    case "11.6.1.b":
        if (evidence.beaconUrl) {
            status = "pass";
            detail = "Beacon callback fires per-tamper-event in addition to heartbeat, which is more frequent than the seven-day floor." + runtimeIncidentDetail(evidence);
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else if (hasRuntimeIncidentRows(evidence)) {
            status = "partial";
            detail = "Runtime incident export shows Dashboard Monitoring received browser-side events, but no BeaconUrl was supplied to evidence the configured heartbeat destination." + runtimeIncidentDetail(evidence);
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else {
            status = "partial";
            detail = "Without a BeaconUrl this control is not actively evidenced. Cadence is implementation-defined when the beacon is wired.";
        }
        if (hasSecurityHeaderEvidence(evidence)) {
            detail += securityHeaderDetail(evidence);
            pushSecurityHeaderEvidence(evidenceRows, evidence);
        }
        break;
    case "11.6.1.c":
        if (evidence.siemAdapter) {
            status = "pass";
            detail = "SIEM adapter '" + evidence.siemAdapter + "' is configured. Beacon events route to on-call surface via jso-beacon-slack adapters/" + evidence.siemAdapter + ".js." + runtimeIncidentDetail(evidence);
            evidenceRows.push({
                artefact: "jso-beacon-slack SIEM adapter",
                location: "packages/jso-beacon-slack/adapters/" + evidence.siemAdapter + ".js",
                citation: "Docs/RuntimeDefense.aspx (SIEM forwarding)",
            });
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else if (evidence.beaconUrl) {
            status = "partial";
            detail = "Beacon is wired but no SIEM forwarder is named. Pass --siem splunk-hec | elasticsearch | webhook to evidence personnel alerts." + runtimeIncidentDetail(evidence);
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else if (hasRuntimeIncidentRows(evidence)) {
            status = "partial";
            detail = "Dashboard Monitoring incident evidence was supplied, but no SIEM or on-call forwarder is named. Pass --beacon-url and --siem to evidence personnel alerts end to end." + runtimeIncidentDetail(evidence);
            pushRuntimeIncidentEvidence(evidenceRows, evidence);
        } else if (hasSecurityHeaderEvidence(evidence)) {
            status = "partial";
            detail = "Payment-page security-header evidence was supplied, but no Runtime Defense beacon or SIEM/on-call forwarder is named. Use this as source-free header-monitoring evidence and pass --beacon-url plus --siem when runtime alerts are wired." + securityHeaderDetail(evidence);
            pushSecurityHeaderEvidence(evidenceRows, evidence);
        } else {
            status = "fail";
            detail = "Neither beacon nor SIEM adapter is configured. Personnel alerts are not evidenced.";
        }
        if (hasSecurityHeaderEvidence(evidence) && (evidence.siemAdapter || evidence.beaconUrl || hasRuntimeIncidentRows(evidence))) {
            detail += securityHeaderDetail(evidence);
            pushSecurityHeaderEvidence(evidenceRows, evidence);
        }
        break;
    default:
        status = "not_inspected";
        detail = "No mapping defined.";
    }
    return { status: status, detail: detail, evidence: evidenceRows };
}

function computeWatermarkCoverage(files) {
    let total = 0, inspected = 0, present = 0, valid = 0;
    for (const f of files) {
        total++;
        if (f.watermark.inspected) inspected++;
        if (f.watermark.present) present++;
        if (f.watermark.valid === true) valid++;
    }
    return {
        total: total,
        inspectedCount: inspected,
        inspected: inspected > 0,
        withWatermark: present,
        withValidSignature: valid,
        anyPresent: present > 0,
        allPresent: total > 0 && present === total,
        allValid: total > 0 && valid === total,
    };
}

function collectScriptInventoryEvidence(inventoryPath) {
    if (!fs.existsSync(inventoryPath)) {
        throw new Error("generateReport: script inventory export not found: " + inventoryPath);
    }
    const bytes = fs.readFileSync(inventoryPath);
    const text = stripUtf8Bom(bytes.toString("utf8"));
    const trimmed = text.trimStart();
    if (/\.json$/i.test(inventoryPath) || trimmed[0] === "{") {
        return collectScriptInventoryJsonEvidence(inventoryPath, bytes, text);
    }
    return collectScriptInventoryCsvEvidence(inventoryPath, bytes, text);
}

function collectScriptInventoryCsvEvidence(csvPath, bytes, text) {
    const parsed = parseCsv(text);
    const records = parsed.records.map(normalizeScriptInventoryRecord);
    return summarizeScriptInventoryRecords(csvPath, bytes, "csv", parsed.headers, records);
}

function collectScriptInventoryJsonEvidence(jsonPath, bytes, text) {
    let payload;
    try {
        payload = JSON.parse(text);
    } catch (x) {
        throw new Error("generateReport: script inventory JSON is not valid JSON: " + x.message);
    }
    const rows = payload && typeof payload === "object"
        ? (payload.scripts || payload.inventory || payload.items)
        : null;
    if (!Array.isArray(rows)) {
        throw new Error("generateReport: script inventory JSON is missing scripts[]");
    }
    const records = rows.map(normalizeScriptInventoryRecord);
    return summarizeScriptInventoryRecords(jsonPath, bytes, "json", [
        "Source", "Authorized", "Justification", "Owner", "Category",
        "Integrity", "LastReviewedUtc", "CheckoutSurface", "FrameContext",
        "FrameOwner", "ParentPageHref", "FrameHref", "FrameOrigin",
        "Risk", "DataAccess", "ApprovalTicket",
    ], records);
}

function normalizeScriptInventoryRecord(row) {
    row = row && typeof row === "object" ? row : {};
    return {
        Source: firstJsonValue(row, "Source", "source", "Src", "src", "Url", "URL", "url"),
        Authorized: firstJsonValue(row, "Authorized", "authorized", "Approved", "approved", "Status", "status"),
        Justification: firstJsonValue(row, "Justification", "justification", "Reason", "reason", "BusinessJustification", "businessJustification"),
        Owner: firstJsonValue(row, "Owner", "owner", "Team", "team"),
        Category: firstJsonValue(row, "Category", "category", "Type", "type"),
        Integrity: firstJsonValue(row, "Integrity", "integrity", "Sri", "SRI", "sri", "Sha256", "sha256", "Hash", "hash"),
        LastReviewedUtc: firstJsonValue(row, "LastReviewedUtc", "lastReviewedUtc", "LastReviewed", "lastReviewed", "ReviewedUtc", "reviewedUtc"),
        CheckoutSurface: firstJsonValue(row, "CheckoutSurface", "checkoutSurface", "PaymentSurface", "paymentSurface", "Surface", "surface"),
        FrameContext: firstJsonValue(row, "FrameContext", "frameContext", "FrameRole", "frameRole", "Frame", "frame"),
        FrameOwner: firstJsonValue(row, "FrameOwner", "frameOwner", "IframeOwner", "iframeOwner"),
        ParentPageHref: firstJsonValue(row, "ParentPageHref", "parentPageHref", "ParentHref", "parentHref"),
        FrameHref: firstJsonValue(row, "FrameHref", "frameHref", "IframeHref", "iframeHref"),
        FrameOrigin: firstJsonValue(row, "FrameOrigin", "frameOrigin", "IframeOrigin", "iframeOrigin"),
        Risk: firstJsonValue(row, "Risk", "risk", "RiskRating", "riskRating", "RiskLevel", "riskLevel"),
        DataAccess: firstJsonValue(row, "DataAccess", "dataAccess", "DataAccessScope", "dataAccessScope", "DataCategory", "dataCategory", "SensitiveDataAccess", "sensitiveDataAccess"),
        ApprovalTicket: firstJsonValue(row, "ApprovalTicket", "approvalTicket", "Ticket", "ticket", "ChangeTicket", "changeTicket", "ApprovalId", "approvalId"),
    };
}

function summarizeScriptInventoryRecords(inventoryPath, bytes, sourceFormat, columns, records) {
    records = Array.isArray(records) ? records : [];
    const authStates = records.map(function (r) { return authorizationState(r.Authorized); });
    const authorizedCount = authStates.filter(function (s) { return s === "authorized"; }).length;
    const unauthorizedCount = authStates.filter(function (s) { return s === "unauthorized"; }).length;
    const unknownAuthorizationCount = authStates.filter(function (s) { return s === "unknown"; }).length;
    const withJustificationCount = records.filter(function (r) { return normalizeCsvCell(r.Justification) !== ""; }).length;
    const withOwnerCount = records.filter(function (r) { return normalizeCsvCell(r.Owner) !== ""; }).length;
    const withIntegrityReferenceCount = records.filter(function (r) { return normalizeCsvCell(r.Integrity) !== ""; }).length;
    const withRiskRatingCount = records.filter(function (r) { return normalizeCsvCell(r.Risk) !== ""; }).length;
    const withDataAccessCount = records.filter(function (r) { return normalizeCsvCell(r.DataAccess) !== ""; }).length;
    const withApprovalTicketCount = records.filter(function (r) { return normalizeCsvCell(r.ApprovalTicket) !== ""; }).length;
    const withCheckoutSurfaceCount = records.filter(function (r) { return normalizeCsvCell(r.CheckoutSurface) !== ""; }).length;
    const withFrameContextCount = records.filter(function (r) { return normalizeCsvCell(r.FrameContext) !== ""; }).length;
    const reviewRange = dateRange(records, "LastReviewedUtc");
    const domains = uniqueScriptDomains(records);
    const inlineCount = records.filter(function (r) { return isInlineScriptSource(r.Source); }).length;
    const iframeScopedCount = records.filter(isIframeScopedScriptInventoryRecord).length;

    return {
        source: path.basename(inventoryPath),
        sourceFormat: sourceFormat,
        sourceSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
        columns: columns,
        count: records.length,
        authorizedCount: authorizedCount,
        unauthorizedCount: unauthorizedCount,
        unknownAuthorizationCount: unknownAuthorizationCount,
        withJustificationCount: withJustificationCount,
        missingJustificationCount: Math.max(0, records.length - withJustificationCount),
        withOwnerCount: withOwnerCount,
        withIntegrityReferenceCount: withIntegrityReferenceCount,
        withRiskRatingCount: withRiskRatingCount,
        withDataAccessCount: withDataAccessCount,
        withApprovalTicketCount: withApprovalTicketCount,
        withCheckoutSurfaceCount: withCheckoutSurfaceCount,
        withFrameContextCount: withFrameContextCount,
        iframeScopedCount: iframeScopedCount,
        inlineCount: inlineCount,
        externalCount: Math.max(0, records.length - inlineCount),
        categoryCounts: countByField(records, "Category"),
        ownerCounts: countByField(records, "Owner"),
        riskCounts: countByField(records, "Risk"),
        dataAccessCounts: countByField(records, "DataAccess"),
        checkoutSurfaceCounts: countByField(records, "CheckoutSurface"),
        frameContextCounts: countByField(records, "FrameContext"),
        frameOwnerCounts: countByField(records, "FrameOwner"),
        uniqueDomainCount: domains.length,
        domains: domains.slice(0, 20),
        oldestReviewedUtc: reviewRange.oldest,
        newestReviewedUtc: reviewRange.newest,
    };
}

function collectScriptInventoryAuditEvidence(auditPath) {
    if (!fs.existsSync(auditPath)) {
        throw new Error("generateReport: script inventory audit export not found: " + auditPath);
    }
    const bytes = fs.readFileSync(auditPath);
    const text = stripUtf8Bom(bytes.toString("utf8"));
    let payload;
    try {
        payload = JSON.parse(text);
    } catch (x) {
        throw new Error("generateReport: script inventory audit JSON is not valid JSON: " + x.message);
    }
    if (!payload || typeof payload !== "object" || payload.format !== "jso-payment-script-inventory-audit") {
        throw new Error("generateReport: script inventory audit JSON must be generated by --script-inventory-audit --json");
    }
    const summary = payload.summary && typeof payload.summary === "object" ? payload.summary : {};
    const runtimeSnapshot = payload.runtimeSnapshot && typeof payload.runtimeSnapshot === "object" ? payload.runtimeSnapshot : {};
    const approvedInventory = payload.approvedInventory && typeof payload.approvedInventory === "object" ? payload.approvedInventory : {};
    return {
        source: path.basename(auditPath),
        sourceFormat: "json",
        sourceSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
        ok: payload.ok === true,
        generatedAt: normalizeCsvCell(payload.generatedAt),
        approvedInventorySource: normalizeCsvCell(approvedInventory.source),
        runtimeSnapshotSource: normalizeCsvCell(runtimeSnapshot.source),
        runtimeSnapshotCount: numericSummaryValue(runtimeSnapshot.snapshotCount),
        approvedScripts: numericSummaryValue(summary.approvedScripts),
        observedScripts: numericSummaryValue(summary.observedScripts),
        unknownObserved: numericSummaryValue(summary.unknownObserved),
        unauthorizedObserved: numericSummaryValue(summary.unauthorizedObserved),
        integrityMismatches: numericSummaryValue(summary.integrityMismatches),
        missingApproved: numericSummaryValue(summary.missingApproved),
        injectedAfterLoad: numericSummaryValue(summary.injectedAfterLoad),
        runtimeViolations: numericSummaryValue(summary.runtimeViolations),
        observedWithoutIntegrityReference: numericSummaryValue(summary.observedWithoutIntegrityReference),
        inventoryGaps: numericSummaryValue(summary.inventoryGaps),
        duplicateApproved: numericSummaryValue(summary.duplicateApproved),
        authorizedApprovedScripts: numericSummaryValue(summary.authorizedApprovedScripts),
        withRiskRating: numericSummaryValue(summary.withRiskRating),
        withDataAccess: numericSummaryValue(summary.withDataAccess),
        withApprovalTicket: numericSummaryValue(summary.withApprovalTicket),
        missingRiskRating: numericSummaryValue(summary.missingRiskRating),
        missingDataAccess: numericSummaryValue(summary.missingDataAccess),
        missingApprovalTicket: numericSummaryValue(summary.missingApprovalTicket),
        reviewMetadataGaps: numericSummaryValue(summary.reviewMetadataGaps),
        approvedCheckoutSurfaces: countSummaryObject(summary.approvedCheckoutSurfaces),
        observedCheckoutSurfaces: countSummaryObject(summary.observedCheckoutSurfaces),
        approvedFrameContexts: countSummaryObject(summary.approvedFrameContexts),
        observedFrameContexts: countSummaryObject(summary.observedFrameContexts),
        approvedFrameOwners: countSummaryObject(summary.approvedFrameOwners),
        observedFrameOwners: countSummaryObject(summary.observedFrameOwners),
        approvedIframeScopedScripts: numericSummaryValue(summary.approvedIframeScopedScripts),
        observedIframeScopedScripts: numericSummaryValue(summary.observedIframeScopedScripts),
        blockingIssues: numericSummaryValue(summary.blockingIssues),
    };
}

function countSummaryObject(value) {
    const out = {};
    if (!value || typeof value !== "object" || Array.isArray(value)) return out;
    Object.keys(value).sort().forEach(function (key) {
        const text = normalizeCsvCell(key);
        const n = Number(value[key]);
        if (text && Number.isFinite(n) && n > 0) out[text] = Math.floor(n);
    });
    return out;
}

function numericSummaryValue(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function collectSecurityHeaderEvidence(headerPath) {
    if (!fs.existsSync(headerPath)) {
        throw new Error("generateReport: payment-page security-header snapshot not found: " + headerPath);
    }
    const bytes = fs.readFileSync(headerPath);
    const text = stripUtf8Bom(bytes.toString("utf8"));
    const trimmed = text.trimStart();
    if (/\.json$/i.test(headerPath) || trimmed[0] === "{") {
        return collectSecurityHeaderJsonEvidence(headerPath, bytes, text);
    }
    return collectSecurityHeaderCsvEvidence(headerPath, bytes, text);
}

function collectSecurityHeaderCsvEvidence(csvPath, bytes, text) {
    const parsed = parseCsv(text);
    const records = parsed.records.map(normalizeSecurityHeaderRecord);
    return summarizeSecurityHeaderRecords(csvPath, bytes, "csv", parsed.headers, records, null, null);
}

function collectSecurityHeaderJsonEvidence(jsonPath, bytes, text) {
    let payload;
    try {
        payload = JSON.parse(text);
    } catch (x) {
        throw new Error("generateReport: payment-page security-header JSON is not valid JSON: " + x.message);
    }
    const rows = payload && typeof payload === "object"
        ? (payload.pages || payload.snapshots || payload.headers || payload.items)
        : null;
    if (!Array.isArray(rows)) {
        throw new Error("generateReport: payment-page security-header JSON is missing pages[]");
    }
    const records = rows.map(normalizeSecurityHeaderRecord);
    const generatedUtc = firstJsonValue(payload, "generatedUtc", "generatedAt", "observedUtc", "ObservedUtc");
    const reviewAssistant = payload && typeof payload === "object" ? payload.reviewAssistant : null;
    return summarizeSecurityHeaderRecords(jsonPath, bytes, "json", [
        "PageUrl", "StatusCode", "ObservedUtc", "CheckoutSurface", "FrameContext",
        "ContentSecurityPolicy", "ContentSecurityPolicyReportOnly",
        "StrictTransportSecurity", "XFrameOptions", "ReferrerPolicy",
        "PermissionsPolicy", "ReportingEndpoints", "Nel", "HeaderSha256",
        "BaselineSha256", "MatchesBaseline", "Monitor", "AlertRoute",
    ], records, generatedUtc, reviewAssistant);
}

function normalizeSecurityHeaderRecord(row) {
    row = row && typeof row === "object" ? row : {};
    return {
        PageUrl: firstJsonValue(row, "PageUrl", "PageURL", "pageUrl", "url", "Url", "URL", "href", "Href"),
        StatusCode: firstJsonValue(row, "StatusCode", "statusCode", "Status", "status", "httpStatus", "HttpStatus"),
        ObservedUtc: firstJsonValue(row, "ObservedUtc", "observedUtc", "CapturedUtc", "capturedUtc", "checkedUtc", "CheckedUtc", "timestamp", "Timestamp"),
        CheckoutSurface: firstJsonValue(row, "CheckoutSurface", "checkoutSurface", "PaymentSurface", "paymentSurface", "Surface", "surface"),
        FrameContext: firstJsonValue(row, "FrameContext", "frameContext", "FrameRole", "frameRole", "Frame", "frame"),
        FrameOwner: firstJsonValue(row, "FrameOwner", "frameOwner", "IframeOwner", "iframeOwner"),
        ContentSecurityPolicy: securityHeaderValue(row, "content-security-policy", "ContentSecurityPolicy", "contentSecurityPolicy", "CSP", "csp"),
        ContentSecurityPolicyReportOnly: securityHeaderValue(row, "content-security-policy-report-only", "ContentSecurityPolicyReportOnly", "contentSecurityPolicyReportOnly", "CSPReportOnly", "cspReportOnly"),
        StrictTransportSecurity: securityHeaderValue(row, "strict-transport-security", "StrictTransportSecurity", "strictTransportSecurity", "HSTS", "hsts"),
        XFrameOptions: securityHeaderValue(row, "x-frame-options", "XFrameOptions", "xFrameOptions"),
        ReferrerPolicy: securityHeaderValue(row, "referrer-policy", "ReferrerPolicy", "referrerPolicy"),
        PermissionsPolicy: securityHeaderValue(row, "permissions-policy", "PermissionsPolicy", "permissionsPolicy"),
        CrossOriginOpenerPolicy: securityHeaderValue(row, "cross-origin-opener-policy", "CrossOriginOpenerPolicy", "crossOriginOpenerPolicy"),
        CrossOriginResourcePolicy: securityHeaderValue(row, "cross-origin-resource-policy", "CrossOriginResourcePolicy", "crossOriginResourcePolicy"),
        CrossOriginEmbedderPolicy: securityHeaderValue(row, "cross-origin-embedder-policy", "CrossOriginEmbedderPolicy", "crossOriginEmbedderPolicy"),
        ReportingEndpoints: securityHeaderValue(row, "reporting-endpoints", "ReportingEndpoints", "reportingEndpoints"),
        Nel: securityHeaderValue(row, "nel", "NEL", "nel"),
        HeaderSha256: firstJsonValue(row, "HeaderSha256", "headerSha256", "HeadersSha256", "headersSha256", "SnapshotSha256", "snapshotSha256"),
        BaselineSha256: firstJsonValue(row, "BaselineSha256", "baselineSha256", "ExpectedSha256", "expectedSha256"),
        MatchesBaseline: firstJsonValue(row, "MatchesBaseline", "matchesBaseline", "BaselineMatch", "baselineMatch", "MatchesExpected", "matchesExpected"),
        Monitor: firstJsonValue(row, "Monitor", "monitor", "Watcher", "watcher", "Scanner", "scanner", "Job", "job"),
        AlertRoute: firstJsonValue(row, "AlertRoute", "alertRoute", "Notify", "notify", "NotificationRoute", "notificationRoute", "EscalationRoute", "escalationRoute"),
    };
}

function securityHeaderValue(row) {
    const names = Array.prototype.slice.call(arguments, 2);
    const direct = firstJsonValue.apply(null, [row].concat(names));
    if (direct) return direct;
    const headers = firstJsonObject(row, "headers", "Headers", "responseHeaders", "ResponseHeaders", "securityHeaders", "SecurityHeaders");
    if (!headers) return "";
    const wanted = normalizeHeaderName(arguments[1]);
    for (const key of Object.keys(headers)) {
        if (normalizeHeaderName(key) === wanted && headers[key] != null) {
            return normalizeCsvCell(headers[key]);
        }
    }
    return "";
}

function firstJsonObject(row) {
    row = row && typeof row === "object" ? row : {};
    for (let i = 1; i < arguments.length; i++) {
        const name = arguments[i];
        if (Object.prototype.hasOwnProperty.call(row, name) &&
            row[name] && typeof row[name] === "object" &&
            !Array.isArray(row[name])) {
            return row[name];
        }
    }
    return null;
}

function normalizeHeaderName(name) {
    return normalizeCsvCell(name).toLowerCase().replace(/_/g, "-");
}

function summarizeSecurityHeaderRecords(headerPath, bytes, sourceFormat, columns, records, generatedUtc, reviewAssistant) {
    records = Array.isArray(records) ? records : [];
    const observedRange = dateRange(records, "ObservedUtc");
    const pageDomains = uniqueSecurityHeaderPageDomains(records);
    const baselineStates = records.map(function (r) { return baselineMatchState(r.MatchesBaseline); });
    const baselineKnownCount = records.filter(function (r, index) {
        return normalizeCsvCell(r.BaselineSha256) !== "" || baselineStates[index] !== "unknown";
    }).length;
    const baselineMatchCount = baselineStates.filter(function (s) { return s === "match"; }).length;
    const baselineMismatchCount = baselineStates.filter(function (s) { return s === "mismatch"; }).length;
    const baselineMissingCount = baselineStates.filter(function (s) { return s === "missing"; }).length;

    const summary = {
        source: path.basename(headerPath),
        sourceFormat: sourceFormat,
        sourceSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
        columns: columns,
        generatedUtc: generatedUtc || null,
        count: records.length,
        statusCounts: countByField(records, "StatusCode"),
        checkoutSurfaceCounts: countByField(records, "CheckoutSurface"),
        frameContextCounts: countByField(records, "FrameContext"),
        frameOwnerCounts: countByField(records, "FrameOwner"),
        withCspCount: records.filter(function (r) { return normalizeCsvCell(r.ContentSecurityPolicy) !== ""; }).length,
        withReportOnlyCspCount: records.filter(function (r) { return normalizeCsvCell(r.ContentSecurityPolicyReportOnly) !== ""; }).length,
        withScriptSrcCount: records.filter(function (r) { return cspHasDirective(r.ContentSecurityPolicy, ["script-src", "script-src-elem", "default-src"]); }).length,
        withFrameSrcCount: records.filter(function (r) { return cspHasDirective(r.ContentSecurityPolicy, ["frame-src", "child-src"]); }).length,
        withConnectSrcCount: records.filter(function (r) { return cspHasDirective(r.ContentSecurityPolicy, ["connect-src", "default-src"]); }).length,
        withReportEndpointCount: records.filter(hasSecurityHeaderReportEndpoint).length,
        withHstsCount: records.filter(function (r) { return normalizeCsvCell(r.StrictTransportSecurity) !== ""; }).length,
        withXFrameOptionsCount: records.filter(function (r) { return normalizeCsvCell(r.XFrameOptions) !== ""; }).length,
        withReferrerPolicyCount: records.filter(function (r) { return normalizeCsvCell(r.ReferrerPolicy) !== ""; }).length,
        withPermissionsPolicyCount: records.filter(function (r) { return normalizeCsvCell(r.PermissionsPolicy) !== ""; }).length,
        withMonitorCount: records.filter(function (r) { return normalizeCsvCell(r.Monitor) !== ""; }).length,
        withAlertRouteCount: records.filter(function (r) { return normalizeCsvCell(r.AlertRoute) !== ""; }).length,
        baselineKnownCount: baselineKnownCount,
        baselineMatchCount: baselineMatchCount,
        baselineMismatchCount: baselineMismatchCount,
        baselineMissingCount: baselineMissingCount,
        uniqueDomainCount: pageDomains.length,
        domains: pageDomains.slice(0, 20),
        oldestObservedUtc: observedRange.oldest,
        newestObservedUtc: observedRange.newest,
    };
    summary.reviewAssistant = normalizeSecurityHeaderReviewAssistant(reviewAssistant) || buildSecurityHeaderReviewAssistant(summary);
    return summary;
}

function normalizeSecurityHeaderReviewAssistant(assistant) {
    if (!assistant || typeof assistant !== "object" || Array.isArray(assistant)) return null;
    const safeInputs = normalizeSecurityHeaderReviewList(assistant.safeInputs);
    const doNotInclude = normalizeSecurityHeaderReviewList(assistant.doNotInclude);
    const questions = Array.isArray(assistant.questions)
        ? assistant.questions.map(function (item) {
            item = item && typeof item === "object" ? item : {};
            return {
                topic: normalizeCsvCell(item.topic),
                prompt: normalizeCsvCell(item.prompt),
                ownerAction: normalizeCsvCell(item.ownerAction),
            };
        }).filter(function (item) {
            return item.topic !== "" || item.prompt !== "" || item.ownerAction !== "";
        })
        : [];
    return {
        sourceFree: assistant.sourceFree !== false,
        intendedUse: normalizeCsvCell(assistant.intendedUse) || "Use with a BYO AI key or internal reviewer to triage payment-page security-header evidence without sending source code, cookies, raw response headers, or secrets.",
        reviewerPrompt: normalizeCsvCell(assistant.reviewerPrompt) || "Review this JSO payment-page security-header packet using only source-free summary fields and produce checkout-owner actions without claiming this replaces a QSA assessment.",
        safeInputs: safeInputs,
        doNotInclude: doNotInclude,
        questions: questions,
    };
}

function normalizeSecurityHeaderReviewList(values) {
    if (!Array.isArray(values)) return [];
    return values.map(function (value) {
        return normalizeCsvCell(value);
    }).filter(function (value, index, arr) {
        return value !== "" && arr.indexOf(value) === index;
    });
}

function buildSecurityHeaderReviewAssistant(summary) {
    summary = summary || {};
    const count = summary.count || 0;
    const questions = [];
    if ((summary.baselineMismatchCount || 0) > 0 || (summary.baselineMissingCount || 0) > 0) {
        questions.push({
            topic: "Baseline drift",
            prompt: "Identify each checkout page or frame whose security-header snapshot changed or is missing from the approved baseline. Confirm whether the change maps to an approved release, provider update, or required rollback.",
            ownerAction: "Attach the release ticket, provider notice, or remediation owner before reviewer handoff.",
        });
    }
    if (count > 0 && (summary.withCspCount || 0) < count) {
        questions.push({
            topic: "CSP coverage",
            prompt: "List every checkout page or frame without an enforced Content-Security-Policy header and decide whether a report-only phase, provider constraint, or missing deployment step explains the gap.",
            ownerAction: "Name the checkout owner and target date for enforced CSP coverage.",
        });
    }
    if (count > 0 && (summary.withScriptSrcCount || 0) < count) {
        questions.push({
            topic: "Script policy",
            prompt: "Review pages or frames without script-src, script-src-elem, or default-src coverage. Confirm how payment-page script loading is constrained for those surfaces.",
            ownerAction: "Record the approved script-loading policy or add a CSP directive before release approval.",
        });
    }
    if (count > 0 && (summary.withFrameSrcCount || 0) < count) {
        questions.push({
            topic: "Frame policy",
            prompt: "Review pages or frames without frame-src or child-src coverage. Confirm hosted checkout, PSP iframe, wallet frame, and embedded payment-frame boundaries are intentional.",
            ownerAction: "Document the approved frame providers or tighten the frame directive.",
        });
    }
    if (count > 0 && (summary.withReportEndpointCount || 0) < count) {
        questions.push({
            topic: "CSP reporting",
            prompt: "Find checkout pages or frames without report-uri, report-to, Reporting-Endpoints, or NEL coverage. Decide where CSP/header violations should be routed.",
            ownerAction: "Wire the missing reporting endpoint or record why the surface is intentionally monitor-only.",
        });
    }
    if (count > 0 && (summary.withHstsCount || 0) < count) {
        questions.push({
            topic: "HSTS coverage",
            prompt: "Identify checkout hosts without Strict-Transport-Security in the snapshot and confirm whether HTTPS enforcement is handled upstream or missing from the response.",
            ownerAction: "Attach the platform or CDN control evidence, or add HSTS before release approval.",
        });
    }
    if (questions.length === 0) {
        questions.push({
            topic: "Clean review",
            prompt: "Confirm the approved security-header baseline still matches the checkout scope, CSP reporting reaches the right owner, and the snapshot is ready for PCI evidence handoff.",
            ownerAction: "Attach this source-free packet next to the header snapshot and release evidence.",
        });
    }
    return {
        sourceFree: true,
        intendedUse: "Use with a BYO AI key or internal reviewer to triage payment-page security-header evidence without sending source code, cookies, raw response headers, or secrets.",
        reviewerPrompt: "Review this JSO payment-page security-header packet. Use only the source-free summary, domains, baseline states, header-presence counts, frame context, monitor, and alert-route fields. Produce checkout-owner actions for baseline drift, CSP/reporting, HSTS, and frame-policy gaps without claiming this replaces a QSA assessment.",
        safeInputs: [
            "summary counts",
            "page domains",
            "baseline match, mismatch, and missing counts",
            "checkout surface, iframe context, and frame owner metadata",
            "CSP, reporting, HSTS, frame-policy, monitor, and alert-route coverage counts",
            "header snapshot SHA-256 values",
        ],
        doNotInclude: [
            "raw response headers",
            "cookies",
            "authorization headers",
            "raw source code",
            "payment-card data",
            "customer personal data",
            "provider API keys",
            "collector tokens",
            "session tokens or secrets",
        ],
        questions: questions,
    };
}

function cspHasDirective(value, directives) {
    const csp = normalizeCsvCell(value).toLowerCase();
    if (!csp) return false;
    return directives.some(function (directive) {
        return new RegExp("(^|;)\\s*" + directive.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&") + "\\b").test(csp);
    });
}

function hasSecurityHeaderReportEndpoint(record) {
    if (normalizeCsvCell(record.ReportingEndpoints) !== "" || normalizeCsvCell(record.Nel) !== "") return true;
    const csp = normalizeCsvCell(record.ContentSecurityPolicy).toLowerCase() + ";" +
        normalizeCsvCell(record.ContentSecurityPolicyReportOnly).toLowerCase();
    return /(^|;)\s*(report-uri|report-to)\b/.test(csp);
}

function baselineMatchState(value) {
    const v = normalizeCsvCell(value).toLowerCase();
    if (/^(true|yes|y|1|match|matched|ok|pass|same)$/.test(v)) return "match";
    if (/^(false|no|n|0|mismatch|changed|drift|fail|different)$/.test(v)) return "mismatch";
    if (/^(missing|not-found|not found|new|absent|unmatched)$/.test(v)) return "missing";
    return "unknown";
}

function uniqueSecurityHeaderPageDomains(records) {
    const seen = new Set();
    for (const r of records) {
        const pageUrl = normalizeCsvCell(r.PageUrl);
        if (!pageUrl) continue;
        try {
            const u = new URL(pageUrl, "https://example.invalid/");
            if (u.hostname && u.hostname !== "example.invalid") seen.add(u.hostname.toLowerCase());
        } catch (x) {
            // Non-URL page labels remain valid evidence rows; they do not
            // contribute to the domain summary.
        }
    }
    return Array.from(seen).sort();
}

function authorizationState(value) {
    const v = normalizeCsvCell(value).toLowerCase();
    if (/^(true|yes|y|1|approved|authorized|allowed|active)$/.test(v)) return "authorized";
    if (/^(false|no|n|0|rejected|blocked|denied|unauthorized|not authorized)$/.test(v)) return "unauthorized";
    return "unknown";
}

function isInlineScriptSource(source) {
    const s = normalizeCsvCell(source).toLowerCase();
    return s === "" || s.indexOf("inline") === 0 || s.indexOf("sha256:") === 0;
}

function uniqueScriptDomains(records) {
    const seen = new Set();
    for (const r of records) {
        const source = normalizeCsvCell(r.Source);
        if (!source || isInlineScriptSource(source)) continue;
        try {
            const u = new URL(source, "https://example.invalid/");
            if (u.hostname && u.hostname !== "example.invalid") seen.add(u.hostname.toLowerCase());
        } catch (x) {
            // Non-URL sources are still valid inventory entries; they just do
            // not contribute to the domain summary.
        }
    }
    return Array.from(seen).sort();
}

function isIframeScopedScriptInventoryRecord(record) {
    const context = normalizeCsvCell(record && record.FrameContext).toLowerCase();
    if (context.indexOf("iframe") >= 0 || context.indexOf("frame") >= 0) return true;
    return normalizeCsvCell(record && record.FrameHref) !== "";
}

function collectRuntimeIncidentEvidence(exportPath) {
    if (!fs.existsSync(exportPath)) {
        throw new Error("generateReport: runtime incident export not found: " + exportPath);
    }
    const bytes = fs.readFileSync(exportPath);
    const text = stripUtf8Bom(bytes.toString("utf8"));
    const trimmed = text.trimStart();
    if (/\.json$/i.test(exportPath) || trimmed[0] === "{") {
        return collectRuntimeIncidentJsonEvidence(exportPath, bytes, text);
    }
    return collectRuntimeIncidentCsvEvidence(exportPath, bytes, text);
}

function collectRuntimeIncidentCsvEvidence(csvPath, bytes, text) {
    const parsed = parseCsv(text);
    const requiredColumns = ["IncidentID", "Status", "Severity", "BuildID", "ReceivedUtc"];
    const missingColumns = requiredColumns.filter(function (name) {
        return parsed.headers.indexOf(name) < 0;
    });
    if (missingColumns.length > 0) {
        throw new Error("generateReport: runtime incident CSV is missing columns: " + missingColumns.join(", "));
    }

    const records = parsed.records;
    return summarizeRuntimeIncidentRecords(csvPath, bytes, "csv", parsed.headers, records, null, null, null, null, null, null, null);
}

function collectRuntimeIncidentJsonEvidence(jsonPath, bytes, text) {
    let payload;
    try {
        payload = JSON.parse(text);
    } catch (x) {
        throw new Error("generateReport: runtime incident JSON is not valid JSON: " + x.message);
    }
    if (!payload || typeof payload !== "object" || !Array.isArray(payload.incidents)) {
        throw new Error("generateReport: runtime incident JSON is missing incidents[]");
    }
    const records = payload.incidents.map(normalizeRuntimeIncidentJsonRecord);
    const filters = normalizeRuntimeIncidentExportFilters(payload.filters);
    const routing = normalizeRuntimeIncidentExportRouting(payload.routing);
    const responseWindow = normalizeRuntimeIncidentExportResponseWindow(payload.responseWindow);
    const responseChecklist = normalizeRuntimeIncidentExportResponseChecklist(payload.responseChecklist);
    const dashboardActions = normalizeRuntimeIncidentDashboardActions(payload.dashboardActions);
    const correlation = normalizeRuntimeIncidentExportCorrelation(payload.correlation);
    const generatedUtc = firstJsonValue(payload, "generatedUtc", "generatedAt");
    return summarizeRuntimeIncidentRecords(jsonPath, bytes, "json", [
        "IncidentID", "Status", "Severity", "Kind", "Reason", "BuildID",
        "Fingerprint", "PageUrl", "RemoteIP", "EventUtc", "ReceivedUtc", "UserAgent",
    ], records, filters, routing, responseChecklist, responseWindow, generatedUtc, dashboardActions, correlation);
}

function summarizeRuntimeIncidentRecords(exportPath, bytes, sourceFormat, columns, records, filters, routing, responseChecklist, responseWindow, generatedUtc, dashboardActions, correlation) {
    const receivedRange = dateRange(records, "ReceivedUtc");
    const eventRange = dateRange(records, "EventUtc");
    const buildIds = uniqueValues(records, "BuildID");
    const unresolved = records.filter(function (r) { return isUnresolvedStatus(r.Status); });
    const unresolvedHighCritical = unresolved.filter(function (r) { return isHighOrCriticalSeverity(r.Severity); });
    const activeReceivedRange = dateRange(unresolved, "ReceivedUtc");
    const highCriticalActiveReceivedRange = dateRange(unresolvedHighCritical, "ReceivedUtc");
    const summary = {
        source: path.basename(exportPath),
        sourceFormat: sourceFormat,
        sourceSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
        columns: columns,
        filters: filters || {},
        generatedUtc: generatedUtc || null,
        dashboardActions: Array.isArray(dashboardActions) ? dashboardActions : [],
        correlation: correlation || buildRuntimeIncidentCorrelation(records),
        count: records.length,
        statusCounts: countByField(records, "Status"),
        severityCounts: countByField(records, "Severity"),
        routing: routing || {},
        unresolvedCount: unresolved.length,
        unresolvedHighCriticalCount: unresolvedHighCritical.length,
        uniqueBuildIdCount: buildIds.length,
        buildIds: buildIds.slice(0, 20),
        oldestReceivedUtc: receivedRange.oldest,
        newestReceivedUtc: receivedRange.newest,
        oldestActiveReceivedUtc: activeReceivedRange.oldest,
        newestActiveReceivedUtc: activeReceivedRange.newest,
        oldestHighOrCriticalActiveReceivedUtc: highCriticalActiveReceivedRange.oldest,
        newestHighOrCriticalActiveReceivedUtc: highCriticalActiveReceivedRange.newest,
        oldestEventUtc: eventRange.oldest,
        newestEventUtc: eventRange.newest,
    };
    summary.actionPlanSummary = buildRuntimeIncidentActionPlanSummary(records);
    summary.responseWindow = responseWindow || buildRuntimeIncidentResponseWindow(summary);
    summary.responseChecklist = responseChecklist || buildRuntimeIncidentResponseChecklist(summary);
    return summary;
}

function buildRuntimeIncidentResponseChecklist(runtimeIncidents) {
    const routing = runtimeIncidents.routing || {};
    const destinations = Array.isArray(routing.routeConfirmedIncidentsTo) && routing.routeConfirmedIncidentsTo.length
        ? routing.routeConfirmedIncidentsTo
        : ["customer-owned SIEM or on-call workflow"];
    const queue = routing.recommendedQueue || (runtimeIncidents.unresolvedHighCriticalCount > 0
        ? "security response owner"
        : "checkout owner");
    const target = routing.responseTargetLabel || (runtimeIncidents.unresolvedHighCriticalCount > 0
        ? "same day"
        : "next business day");
    const steps = [];

    if (runtimeIncidents.count === 0) {
        steps.push({
            id: "archive-empty-export",
            owner: "release owner",
            target: "release evidence window",
            action: "Attach this empty Dashboard Monitoring export to the release packet and keep monitoring routed to the customer-owned alerting path.",
        });
    } else if (runtimeIncidents.unresolvedHighCriticalCount > 0) {
        steps.push({
            id: "acknowledge-active-high-critical",
            owner: queue,
            target: target,
            action: routing.statusAction || "Move matching Open high/critical incidents to Reviewing and confirm whether the affected BuildID is currently serving payment traffic.",
        });
    }

    if (runtimeIncidents.unresolvedCount > 0) {
        steps.push({
            id: "triage-open-reviewing",
            owner: queue,
            target: target,
            action: "Review Open and Reviewing incidents by fingerprint, reason, BuildID, and severity; mark each one Resolved or Ignored only after the checkout owner records the decision.",
        });
    }

    if (runtimeIncidents.uniqueBuildIdCount > 0) {
        steps.push({
            id: "confirm-export-scope",
            owner: "release owner",
            target: "before reviewer handoff",
            action: "Confirm the BuildID and filter scope before treating this packet as full incident history; filtered exports are evidence for the selected queue, not the entire account.",
        });
    }

    steps.push({
        id: "route-confirmed-incidents",
        owner: "security response owner",
        target: target,
        action: "Route confirmed production incidents to " + destinations.join(", ") + " and keep the Dashboard Monitoring export SHA-256 with the incident ticket.",
    });
    steps.push({
        id: "preserve-source-free-boundary",
        owner: "review coordinator",
        target: "before external review",
        action: "Share this source-free summary, its SHA-256, and the export attachment; do not add source code, payment-card data, customer personal data, tokens, provider keys, or secrets.",
    });

    return {
        sourceFree: true,
        filterScope: formatRuntimeIncidentFilters(runtimeIncidents),
        routingScope: formatRuntimeIncidentRouting(runtimeIncidents),
        steps: steps,
    };
}

function buildRuntimeIncidentResponseWindow(runtimeIncidents) {
    const routing = runtimeIncidents.routing || {};
    const targetMinutes = runtimeIncidentResponseTargetMinutes(runtimeIncidents);
    const targetLabel = routing.responseTargetLabel || (runtimeIncidents.unresolvedHighCriticalCount > 0
        ? "15 minutes"
        : (runtimeIncidents.unresolvedCount > 0 ? "4 hours" : "No active incident"));
    let basis = "no active incident";
    let basisUtc = null;
    if (runtimeIncidents.unresolvedHighCriticalCount > 0) {
        basis = "oldest active high/critical receivedUtc";
        basisUtc = runtimeIncidents.oldestHighOrCriticalActiveReceivedUtc;
    } else if (runtimeIncidents.unresolvedCount > 0) {
        basis = "oldest active receivedUtc";
        basisUtc = runtimeIncidents.oldestActiveReceivedUtc;
    }
    const dueUtc = basisUtc && targetMinutes > 0 ? addUtcMinutes(basisUtc, targetMinutes) : null;
    const generatedUtc = runtimeIncidents.generatedUtc || "";
    const overdue = dueUtc && generatedUtc && Number.isFinite(Date.parse(generatedUtc))
        ? Date.parse(generatedUtc) > Date.parse(dueUtc)
        : null;
    return {
        sourceFree: true,
        basis: basis,
        generatedUtc: generatedUtc,
        targetMinutes: targetMinutes,
        targetLabel: targetLabel,
        recommendedQueue: routing.recommendedQueue || "",
        statusAction: routing.statusAction || "",
        oldestActiveReceivedUtc: runtimeIncidents.oldestActiveReceivedUtc || null,
        oldestHighOrCriticalActiveReceivedUtc: runtimeIncidents.oldestHighOrCriticalActiveReceivedUtc || null,
        responseDueUtc: dueUtc,
        overdue: overdue,
        windowState: dueUtc
            ? (overdue === true ? "overdue" : (overdue === false ? "within-target" : "due-time-recorded"))
            : "no-active-incident",
    };
}

function runtimeIncidentResponseTargetMinutes(runtimeIncidents) {
    const routing = runtimeIncidents.routing || {};
    if (Number.isFinite(routing.responseTargetMinutes) && routing.responseTargetMinutes >= 0) {
        return routing.responseTargetMinutes;
    }
    if (runtimeIncidents.unresolvedHighCriticalCount > 0) return 15;
    if (runtimeIncidents.unresolvedCount > 0) return 240;
    if (runtimeIncidents.count > 0) return 1440;
    return 0;
}

function buildRuntimeIncidentActionPlanSummary(records) {
    const plans = [];
    const nextOwnerCounts = {};
    const escalationCounts = {};
    let overdueCount = 0;
    let acknowledgementRequiredCount = 0;

    function increment(counts, key) {
        key = normalizeCsvCell(key) || "unknown";
        counts[key] = (counts[key] || 0) + 1;
    }

    for (const record of records || []) {
        const plan = record && (record.ActionPlan || normalizeRuntimeIncidentActionPlan(null, record));
        if (!plan) continue;
        const row = {
            incidentId: normalizeCsvCell(record.IncidentID),
            escalationLevel: normalizeCsvCell(plan.escalationLevel),
            nextOwner: normalizeCsvCell(plan.nextOwner),
            nextAction: normalizeCsvCell(plan.nextAction),
            evidence: normalizeCsvCell(plan.evidence),
            responseTargetLabel: normalizeCsvCell(plan.responseTargetLabel),
            responseDueUtc: normalizeCsvCell(plan.responseDueUtc),
            windowState: normalizeCsvCell(plan.windowState),
            statusTransition: normalizeCsvCell(plan.statusTransition),
            requiresAcknowledgement: plan.requiresAcknowledgement === true,
            overdue: plan.overdue === true,
        };
        plans.push(row);
        increment(nextOwnerCounts, row.nextOwner);
        increment(escalationCounts, row.escalationLevel);
        if (row.overdue) overdueCount += 1;
        if (row.requiresAcknowledgement) acknowledgementRequiredCount += 1;
    }

    return {
        sourceFree: true,
        incidentsWithActionPlan: plans.length,
        nextOwnerCounts: nextOwnerCounts,
        escalationCounts: escalationCounts,
        overdueCount: overdueCount,
        acknowledgementRequiredCount: acknowledgementRequiredCount,
        topActions: plans.slice(0, 10),
    };
}

function normalizeRuntimeIncidentExportCorrelation(correlation) {
    if (!correlation || typeof correlation !== "object" || Array.isArray(correlation)) return null;
    const fingerprintGroups = normalizeRuntimeIncidentCorrelationGroups(
        Array.isArray(correlation.topFingerprintGroups) ? correlation.topFingerprintGroups :
        (Array.isArray(correlation.TopFingerprintGroups) ? correlation.TopFingerprintGroups : [])
    );
    const reasonGroups = normalizeRuntimeIncidentCorrelationGroups(
        Array.isArray(correlation.topReasonGroups) ? correlation.topReasonGroups :
        (Array.isArray(correlation.TopReasonGroups) ? correlation.TopReasonGroups : [])
    );
    const repeatedFingerprintGroupCount = parseInt(firstJsonValue(correlation, "repeatedFingerprintGroupCount", "RepeatedFingerprintGroupCount"), 10);
    const repeatedReasonGroupCount = parseInt(firstJsonValue(correlation, "repeatedReasonGroupCount", "RepeatedReasonGroupCount"), 10);
    return {
        sourceFree: firstJsonValue(correlation, "sourceFree", "SourceFree") !== "false",
        groupBy: ["fingerprint", "reason"],
        repeatedFingerprintGroupCount: Number.isFinite(repeatedFingerprintGroupCount) ? repeatedFingerprintGroupCount : fingerprintGroups.length,
        repeatedReasonGroupCount: Number.isFinite(repeatedReasonGroupCount) ? repeatedReasonGroupCount : reasonGroups.length,
        topFingerprintGroups: fingerprintGroups,
        topReasonGroups: reasonGroups,
        safeSharingBoundary: firstJsonValue(correlation, "safeSharingBoundary", "SafeSharingBoundary") || "Correlation groups include source-free counts, statuses, BuildIDs, timestamps, fingerprints, and reasons only."
    };
}

function normalizeRuntimeIncidentCorrelationGroups(groups) {
    return groups.map(function (group) {
        group = group && typeof group === "object" ? group : {};
        const count = parseInt(firstJsonValue(group, "count", "Count"), 10);
        const activeCount = parseInt(firstJsonValue(group, "activeCount", "ActiveCount"), 10);
        const highOrCriticalActiveCount = parseInt(firstJsonValue(group, "highOrCriticalActiveCount", "HighOrCriticalActiveCount"), 10);
        const buildIds = Array.isArray(group.buildIds) ? group.buildIds :
            (Array.isArray(group.BuildIds) ? group.BuildIds : []);
        return {
            groupBy: firstJsonValue(group, "groupBy", "GroupBy") || "fingerprint",
            key: firstJsonValue(group, "key", "Key", "fingerprint", "reason"),
            count: Number.isFinite(count) ? count : 0,
            activeCount: Number.isFinite(activeCount) ? activeCount : 0,
            highOrCriticalActiveCount: Number.isFinite(highOrCriticalActiveCount) ? highOrCriticalActiveCount : 0,
            highestSeverity: firstJsonValue(group, "highestSeverity", "HighestSeverity"),
            statusCounts: normalizeRuntimeIncidentCorrelationCounts(group.statusCounts || group.StatusCounts),
            buildIds: buildIds.map(function (item) { return normalizeCsvCell(item); }).filter(Boolean).slice(0, 8),
            firstReceivedUtc: firstJsonValue(group, "firstReceivedUtc", "FirstReceivedUtc"),
            lastReceivedUtc: firstJsonValue(group, "lastReceivedUtc", "LastReceivedUtc"),
            recommendedAction: firstJsonValue(group, "recommendedAction", "RecommendedAction")
        };
    }).filter(function (group) {
        return group.key && group.count > 1;
    }).slice(0, 10);
}

function normalizeRuntimeIncidentCorrelationCounts(counts) {
    const out = {};
    if (!counts || typeof counts !== "object" || Array.isArray(counts)) return out;
    for (const key of Object.keys(counts)) {
        const value = parseInt(counts[key], 10);
        if (Number.isFinite(value) && value > 0) out[normalizeCsvCell(key) || "Unknown"] = value;
    }
    return out;
}

function buildRuntimeIncidentCorrelation(records) {
    const fingerprint = buildRuntimeIncidentCorrelationGroups(records, "Fingerprint", "fingerprint");
    const reason = buildRuntimeIncidentCorrelationGroups(records, "Reason", "reason");
    return {
        sourceFree: true,
        groupBy: ["fingerprint", "reason"],
        repeatedFingerprintGroupCount: fingerprint.totalRepeatedGroups,
        repeatedReasonGroupCount: reason.totalRepeatedGroups,
        topFingerprintGroups: fingerprint.groups,
        topReasonGroups: reason.groups,
        safeSharingBoundary: "Correlation groups include source-free counts, statuses, BuildIDs, timestamps, fingerprints, and reasons only."
    };
}

function buildRuntimeIncidentCorrelationGroups(records, fieldName, groupBy) {
    const groups = new Map();
    for (const record of records || []) {
        const key = normalizeCsvCell(record && record[fieldName]);
        if (!key) continue;
        let group = groups.get(key);
        if (!group) {
            group = {
                groupBy: groupBy,
                key: key,
                count: 0,
                activeCount: 0,
                highOrCriticalActiveCount: 0,
                highestSeverityRank: 0,
                statusCounts: {},
                buildIds: new Set(),
                receivedTimes: []
            };
            groups.set(key, group);
        }
        group.count += 1;
        if (isUnresolvedStatus(record.Status)) group.activeCount += 1;
        if (isUnresolvedStatus(record.Status) && isHighOrCriticalSeverity(record.Severity)) group.highOrCriticalActiveCount += 1;
        group.highestSeverityRank = Math.max(group.highestSeverityRank, runtimeIncidentSeverityRank(record.Severity));
        const status = normalizeCsvCell(record.Status) || "Unknown";
        group.statusCounts[status] = (group.statusCounts[status] || 0) + 1;
        const buildId = normalizeCsvCell(record.BuildID);
        if (buildId) group.buildIds.add(buildId);
        const received = Date.parse(normalizeCsvCell(record.ReceivedUtc));
        if (Number.isFinite(received)) group.receivedTimes.push(received);
    }

    const repeated = Array.from(groups.values()).filter(function (group) { return group.count > 1; });
    repeated.sort(function (a, b) {
        return b.highOrCriticalActiveCount - a.highOrCriticalActiveCount ||
            b.activeCount - a.activeCount ||
            b.count - a.count ||
            Math.max.apply(null, b.receivedTimes.concat([0])) - Math.max.apply(null, a.receivedTimes.concat([0])) ||
            a.key.localeCompare(b.key);
    });

    return {
        totalRepeatedGroups: repeated.length,
        groups: repeated.slice(0, 5).map(function (group) {
            const sortedTimes = group.receivedTimes.slice().sort(function (a, b) { return a - b; });
            return {
                groupBy: group.groupBy,
                key: group.key,
                count: group.count,
                activeCount: group.activeCount,
                highOrCriticalActiveCount: group.highOrCriticalActiveCount,
                highestSeverity: runtimeIncidentSeverityLabel(group.highestSeverityRank),
                statusCounts: group.statusCounts,
                buildIds: Array.from(group.buildIds).sort().slice(0, 8),
                firstReceivedUtc: sortedTimes.length ? new Date(sortedTimes[0]).toISOString() : "",
                lastReceivedUtc: sortedTimes.length ? new Date(sortedTimes[sortedTimes.length - 1]).toISOString() : "",
                recommendedAction: runtimeIncidentCorrelationAction(group)
            };
        })
    };
}

function runtimeIncidentSeverityRank(severity) {
    const value = normalizeCsvCell(severity).toLowerCase();
    if (value === "critical") return 4;
    if (value === "high") return 3;
    if (value === "medium") return 2;
    if (value === "low") return 1;
    return 0;
}

function runtimeIncidentSeverityLabel(rank) {
    if (rank >= 4) return "critical";
    if (rank === 3) return "high";
    if (rank === 2) return "medium";
    if (rank === 1) return "low";
    return "unknown";
}

function runtimeIncidentCorrelationAction(group) {
    if (group.highOrCriticalActiveCount > 0) {
        return "Prioritize this repeated high/critical signal before reviewer handoff, then route confirmed production incidents to the customer-owned alerting path.";
    }
    if (group.activeCount > 0) {
        return "Review this repeated active signal by BuildID, URL, and runtime fingerprint before closing the filtered packet.";
    }
    return "Keep this repeated signal with the export as resolved or ignored evidence for the selected filter.";
}

function normalizeRuntimeIncidentExportRouting(routing) {
    if (!routing || typeof routing !== "object" || Array.isArray(routing)) return {};
    const out = {};
    const escalationLevel = firstJsonValue(routing, "escalationLevel", "EscalationLevel", "severityLevel");
    const recommendedQueue = firstJsonValue(routing, "recommendedQueue", "RecommendedQueue", "queue");
    const preferredEvidence = firstJsonValue(routing, "preferredEvidence", "PreferredEvidence", "evidence");
    const recommendedAction = firstJsonValue(routing, "recommendedAction", "RecommendedAction", "action");
    const responseTargetMinutesRaw = firstJsonValue(routing, "responseTargetMinutes", "ResponseTargetMinutes", "targetMinutes");
    const responseTargetLabel = firstJsonValue(routing, "responseTargetLabel", "ResponseTargetLabel", "targetLabel");
    const statusAction = firstJsonValue(routing, "statusAction", "StatusAction", "statusNextStep");
    const filterContext = firstJsonValue(routing, "filterContext", "FilterContext");
    const buildId = firstJsonValue(routing, "buildId", "BuildID", "BuildId", "buildID");
    const responseTargetMinutes = parseInt(responseTargetMinutesRaw, 10);
    if (escalationLevel) out.escalationLevel = escalationLevel;
    if (recommendedQueue) out.recommendedQueue = recommendedQueue;
    if (preferredEvidence) out.preferredEvidence = preferredEvidence;
    if (recommendedAction) out.recommendedAction = recommendedAction;
    if (Number.isFinite(responseTargetMinutes) && responseTargetMinutes >= 0) out.responseTargetMinutes = responseTargetMinutes;
    if (responseTargetLabel) out.responseTargetLabel = responseTargetLabel;
    if (statusAction) out.statusAction = statusAction;
    if (filterContext) out.filterContext = filterContext;
    if (buildId) out.buildId = buildId;
    if (Array.isArray(routing.routeConfirmedIncidentsTo)) {
        out.routeConfirmedIncidentsTo = routing.routeConfirmedIncidentsTo
            .map(function (item) { return normalizeCsvCell(item); })
            .filter(Boolean)
            .slice(0, 10);
    }
    const alertRoutingPlaybook = normalizeRuntimeIncidentAlertRoutingPlaybook(routing);
    if (alertRoutingPlaybook.length > 0) out.alertRoutingPlaybook = alertRoutingPlaybook;
    return out;
}

function normalizeRuntimeIncidentAlertRoutingPlaybook(routing) {
    const raw = routing && (
        Array.isArray(routing.alertRoutingPlaybook) ? routing.alertRoutingPlaybook :
        Array.isArray(routing.AlertRoutingPlaybook) ? routing.AlertRoutingPlaybook :
        Array.isArray(routing.playbook) ? routing.playbook :
        Array.isArray(routing.routingPlaybook) ? routing.routingPlaybook :
        null
    );
    if (!raw) return [];
    return raw.map(function (step) {
        step = step && typeof step === "object" ? step : {};
        return {
            id: firstJsonValue(step, "id", "ID", "stepId"),
            lane: firstJsonValue(step, "lane", "Lane", "name"),
            owner: firstJsonValue(step, "owner", "Owner", "queue"),
            trigger: firstJsonValue(step, "trigger", "Trigger", "condition"),
            target: firstJsonValue(step, "target", "Target", "responseTarget"),
            evidence: firstJsonValue(step, "evidence", "Evidence", "artifact", "artefact"),
            action: firstJsonValue(step, "action", "Action", "description"),
            boundary: firstJsonValue(step, "boundary", "Boundary", "safeSharingBoundary"),
        };
    }).filter(function (step) {
        return step.id || step.lane || step.action;
    }).slice(0, 12);
}

function normalizeRuntimeIncidentDashboardActions(actions) {
    if (!Array.isArray(actions)) return [];
    return actions.map(function (action) {
        action = action && typeof action === "object" ? action : {};
        const enabledRaw = firstJsonValue(action, "enabled", "Enabled", "available");
        const matchingOpenRaw = firstJsonValue(action, "matchingOpenIncidentCount", "MatchingOpenIncidentCount", "openCount");
        const matchingReviewingRaw = firstJsonValue(action, "matchingReviewingIncidentCount", "MatchingReviewingIncidentCount", "reviewingCount");
        const matchingOpenIncidentCount = parseInt(matchingOpenRaw, 10);
        const matchingReviewingIncidentCount = parseInt(matchingReviewingRaw, 10);
        const preserves = Array.isArray(action.preserves) ? action.preserves
            : (Array.isArray(action.Preserves) ? action.Preserves : []);
        const filters = normalizeRuntimeIncidentExportFilters(
            action.filters && typeof action.filters === "object" ? action.filters :
            (action.Filters && typeof action.Filters === "object" ? action.Filters : {})
        );
        const row = {
            id: firstJsonValue(action, "id", "ID", "actionId"),
            label: firstJsonValue(action, "label", "Label", "name"),
            dashboardAction: firstJsonValue(action, "dashboardAction", "DashboardAction", "action"),
            formFieldName: firstJsonValue(action, "formFieldName", "FormFieldName"),
            formFieldValue: firstJsonValue(action, "formFieldValue", "FormFieldValue"),
            method: firstJsonValue(action, "method", "Method"),
            sourceFree: firstJsonValue(action, "sourceFree", "SourceFree") !== "false",
            requiresDashboardLogin: firstJsonValue(action, "requiresDashboardLogin", "RequiresDashboardLogin") !== "false",
            statusFrom: firstJsonValue(action, "statusFrom", "StatusFrom", "fromStatus"),
            statusTo: firstJsonValue(action, "statusTo", "StatusTo", "targetStatus", "toStatus"),
            scope: firstJsonValue(action, "scope", "Scope"),
            filterContext: firstJsonValue(action, "filterContext", "FilterContext"),
            safety: firstJsonValue(action, "safety", "Safety", "safeSharingBoundary"),
            filters: filters,
            preserves: preserves.map(function (item) { return normalizeCsvCell(item); }).filter(Boolean).slice(0, 8),
        };
        if (/^(true|yes|1)$/i.test(enabledRaw)) row.enabled = true;
        else if (/^(false|no|0)$/i.test(enabledRaw)) row.enabled = false;
        if (Number.isFinite(matchingOpenIncidentCount) && matchingOpenIncidentCount >= 0) {
            row.matchingOpenIncidentCount = matchingOpenIncidentCount;
        }
        if (Number.isFinite(matchingReviewingIncidentCount) && matchingReviewingIncidentCount >= 0) {
            row.matchingReviewingIncidentCount = matchingReviewingIncidentCount;
        }
        return row;
    }).filter(function (action) {
        return action.id || action.label || action.dashboardAction;
    }).slice(0, 10);
}

function normalizeRuntimeIncidentExportResponseWindow(window) {
    if (!window || typeof window !== "object" || Array.isArray(window)) return null;
    const out = { sourceFree: firstJsonValue(window, "sourceFree", "SourceFree") !== "false" };
    const targetMinutesRaw = firstJsonValue(window, "targetMinutes", "TargetMinutes", "responseTargetMinutes", "ResponseTargetMinutes");
    const targetMinutes = parseInt(targetMinutesRaw, 10);
    if (Number.isFinite(targetMinutes) && targetMinutes >= 0) out.targetMinutes = targetMinutes;
    const stringFields = [
        ["basis", "basis", "Basis"],
        ["generatedUtc", "generatedUtc", "GeneratedUtc", "generatedAt"],
        ["targetLabel", "targetLabel", "TargetLabel", "responseTargetLabel", "ResponseTargetLabel"],
        ["recommendedQueue", "recommendedQueue", "RecommendedQueue"],
        ["statusAction", "statusAction", "StatusAction"],
        ["oldestActiveReceivedUtc", "oldestActiveReceivedUtc", "OldestActiveReceivedUtc"],
        ["oldestHighOrCriticalActiveReceivedUtc", "oldestHighOrCriticalActiveReceivedUtc", "OldestHighOrCriticalActiveReceivedUtc"],
        ["responseDueUtc", "responseDueUtc", "ResponseDueUtc", "dueUtc", "dueByUtc"],
        ["windowState", "windowState", "WindowState", "state"],
    ];
    for (const spec of stringFields) {
        const name = spec[0];
        const value = firstJsonValue.apply(null, [window].concat(spec.slice(1)));
        if (value) out[name] = value;
    }
    const overdueRaw = firstJsonValue(window, "overdue", "Overdue", "isOverdue");
    if (/^(true|yes|1)$/i.test(overdueRaw)) out.overdue = true;
    else if (/^(false|no|0)$/i.test(overdueRaw)) out.overdue = false;
    return Object.keys(out).length > 1 ? out : null;
}

function normalizeRuntimeIncidentExportResponseChecklist(checklist) {
    if (!checklist || typeof checklist !== "object" || Array.isArray(checklist)) return null;
    const rawSteps = Array.isArray(checklist.steps) ? checklist.steps : [];
    const steps = rawSteps.map(function (step) {
        step = step && typeof step === "object" ? step : {};
        return {
            id: firstJsonValue(step, "id", "ID", "stepId"),
            owner: firstJsonValue(step, "owner", "Owner", "queue"),
            target: firstJsonValue(step, "target", "Target", "responseTarget"),
            action: firstJsonValue(step, "action", "Action", "description"),
        };
    }).filter(function (step) {
        return step.id || step.action;
    }).slice(0, 12);
    if (steps.length === 0) return null;
    return {
        sourceFree: firstJsonValue(checklist, "sourceFree", "SourceFree") !== "false",
        filterScope: firstJsonValue(checklist, "filterScope", "FilterScope"),
        routingScope: firstJsonValue(checklist, "routingScope", "RoutingScope"),
        steps: steps,
    };
}

function normalizeRuntimeIncidentExportFilters(filters) {
    if (!filters || typeof filters !== "object" || Array.isArray(filters)) return {};
    const out = {};
    const status = firstJsonValue(filters, "status", "Status", "runtimeStatus", "runtime_status");
    const severity = firstJsonValue(filters, "severity", "Severity", "runtimeSeverity", "runtime_severity");
    const buildId = firstJsonValue(filters, "buildId", "BuildID", "BuildId", "buildID", "runtimeBuild", "runtime_build");
    if (status) out.status = status;
    if (severity) out.severity = severity;
    if (buildId) out.buildId = buildId;
    return out;
}

function normalizeRuntimeIncidentJsonRecord(row) {
    row = row && typeof row === "object" ? row : {};
    const record = {
        IncidentID: firstJsonValue(row, "IncidentID", "incidentId", "id"),
        Status: firstJsonValue(row, "Status", "status"),
        Severity: firstJsonValue(row, "Severity", "severity"),
        Kind: firstJsonValue(row, "Kind", "kind"),
        Reason: firstJsonValue(row, "Reason", "reason"),
        BuildID: firstJsonValue(row, "BuildID", "BuildId", "buildID", "buildId"),
        Fingerprint: firstJsonValue(row, "Fingerprint", "fingerprint"),
        PageUrl: firstJsonValue(row, "PageUrl", "PageURL", "pageUrl", "url"),
        RemoteIP: firstJsonValue(row, "RemoteIP", "RemoteIp", "remoteIP", "remoteIp"),
        EventUtc: firstJsonValue(row, "EventUtc", "eventUtc"),
        ReceivedUtc: firstJsonValue(row, "ReceivedUtc", "receivedUtc"),
        UserAgent: firstJsonValue(row, "UserAgent", "userAgent"),
    };
    const actionPlan = normalizeRuntimeIncidentActionPlan(row.actionPlan || row.ActionPlan, row);
    if (actionPlan) record.ActionPlan = actionPlan;
    return record;
}

function normalizeRuntimeIncidentActionPlan(raw, row) {
    const source = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : (row || {});
    const nextOwner = firstJsonValue(source, "nextOwner", "NextOwner", "owner", "Owner");
    const nextAction = firstJsonValue(source, "nextAction", "NextAction", "action", "Action");
    const escalationLevel = firstJsonValue(source, "escalationLevel", "EscalationLevel", "level", "Level");
    const evidence = firstJsonValue(source, "evidence", "Evidence", "preferredEvidence", "PreferredEvidence");
    const responseTargetLabel = firstJsonValue(source, "responseTargetLabel", "ResponseTargetLabel", "targetLabel", "TargetLabel");
    const responseDueUtc = firstJsonValue(source, "responseDueUtc", "ResponseDueUtc", "dueUtc", "DueUtc");
    const windowState = firstJsonValue(source, "windowState", "WindowState", "responseWindowState", "ResponseWindowState", "state", "State");
    const statusTransition = firstJsonValue(source, "statusTransition", "StatusTransition", "statusMove", "StatusMove");
    const responseTargetMinutesRaw = firstJsonValue(source, "responseTargetMinutes", "ResponseTargetMinutes", "targetMinutes", "TargetMinutes");
    const responseTargetMinutes = parseInt(responseTargetMinutesRaw, 10);
    const overdueRaw = firstJsonValue(source, "overdue", "Overdue", "isOverdue", "IsOverdue");
    const acknowledgementRaw = firstJsonValue(source, "requiresAcknowledgement", "RequiresAcknowledgement", "acknowledgementRequired", "AcknowledgementRequired");

    if (!nextOwner && !nextAction && !escalationLevel && !responseDueUtc && !statusTransition) return null;

    const out = {
        sourceFree: firstJsonValue(source, "sourceFree", "SourceFree") !== "false",
        escalationLevel: escalationLevel,
        nextOwner: nextOwner,
        nextAction: nextAction,
        evidence: evidence,
        responseTargetLabel: responseTargetLabel,
        responseDueUtc: responseDueUtc,
        windowState: windowState,
        statusTransition: statusTransition,
    };
    if (Number.isFinite(responseTargetMinutes) && responseTargetMinutes >= 0) out.responseTargetMinutes = responseTargetMinutes;
    if (/^(true|yes|1)$/i.test(overdueRaw)) out.overdue = true;
    else if (/^(false|no|0)$/i.test(overdueRaw)) out.overdue = false;
    if (/^(true|yes|1)$/i.test(acknowledgementRaw)) out.requiresAcknowledgement = true;
    else if (/^(false|no|0)$/i.test(acknowledgementRaw)) out.requiresAcknowledgement = false;
    return out;
}

function firstJsonValue(row) {
    for (let i = 1; i < arguments.length; i++) {
        const name = arguments[i];
        if (Object.prototype.hasOwnProperty.call(row, name) && row[name] != null) {
            return normalizeCsvCell(row[name]);
        }
    }
    return "";
}

function stripUtf8Bom(text) {
    return text && text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
}

function parseCsv(text) {
    text = stripUtf8Bom(text);
    const rows = [];
    let row = [];
    let field = "";
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (inQuotes) {
            if (ch === "\"") {
                if (text[i + 1] === "\"") {
                    field += "\"";
                    i++;
                } else {
                    inQuotes = false;
                }
            } else {
                field += ch;
            }
        } else if (ch === "\"") {
            inQuotes = true;
        } else if (ch === ",") {
            row.push(field);
            field = "";
        } else if (ch === "\r" || ch === "\n") {
            row.push(field);
            rows.push(row);
            row = [];
            field = "";
            if (ch === "\r" && text[i + 1] === "\n") i++;
        } else {
            field += ch;
        }
    }
    if (field.length > 0 || row.length > 0) {
        row.push(field);
        rows.push(row);
    }
    if (rows.length === 0) {
        throw new Error("generateReport: runtime incident CSV is empty");
    }
    const headers = rows[0].map(function (h) { return normalizeCsvCell(h); });
    const records = rows.slice(1).filter(function (r) {
        return r.some(function (cell) { return normalizeCsvCell(cell) !== ""; });
    }).map(function (r) {
        const obj = {};
        for (let i = 0; i < headers.length; i++) {
            obj[headers[i]] = normalizeCsvCell(r[i] || "");
        }
        return obj;
    });
    return { headers: headers, records: records };
}

function normalizeCsvCell(value) {
    return value == null ? "" : String(value).trim();
}

function countByField(records, fieldName) {
    const counts = {};
    for (const r of records) {
        const key = normalizeCsvCell(r[fieldName]) || "Unknown";
        counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
}

function uniqueValues(records, fieldName) {
    const seen = new Set();
    for (const r of records) {
        const value = normalizeCsvCell(r[fieldName]);
        if (value) seen.add(value);
    }
    return Array.from(seen).sort();
}

function dateRange(records, fieldName) {
    const times = [];
    for (const r of records) {
        const value = normalizeCsvCell(r[fieldName]);
        if (!value) continue;
        const ms = Date.parse(value);
        if (Number.isFinite(ms)) times.push(ms);
    }
    if (times.length === 0) return { oldest: null, newest: null };
    times.sort(function (a, b) { return a - b; });
    return {
        oldest: new Date(times[0]).toISOString(),
        newest: new Date(times[times.length - 1]).toISOString(),
    };
}

function addUtcMinutes(value, minutes) {
    const ms = Date.parse(value);
    if (!Number.isFinite(ms) || !Number.isFinite(minutes)) return null;
    return new Date(ms + minutes * 60 * 1000).toISOString();
}

function isUnresolvedStatus(status) {
    return /^(open|reviewing)$/i.test(normalizeCsvCell(status));
}

function isHighOrCriticalSeverity(severity) {
    return /^(high|critical)$/i.test(normalizeCsvCell(severity));
}

function hasScriptInventoryRows(evidence) {
    return !!(evidence && evidence.scriptInventory && evidence.scriptInventory.count > 0);
}

function hasScriptInventoryAudit(evidence) {
    return !!(evidence && evidence.scriptInventoryAudit);
}

function hasRuntimeIncidentRows(evidence) {
    return !!(evidence && evidence.runtimeIncidents && evidence.runtimeIncidents.count > 0);
}

function pushScriptInventoryEvidence(evidenceRows, evidence) {
    const si = evidence && evidence.scriptInventory;
    if (!si) return;
    evidenceRows.push({
        artefact: "Payment-page script inventory " + scriptInventoryFormatLabel(si) + " summary",
        location: si.source + " (sha256=" + si.sourceSha256.slice(0, 12) + "...)",
        citation: "jso-protector compliance pci-dss-v4 --script-inventory",
    });
}

function scriptInventoryFormatLabel(scriptInventory) {
    return scriptInventory && scriptInventory.sourceFormat === "json" ? "JSON" : "CSV";
}

function scriptInventoryReviewContextDetail(scriptInventory) {
    if (!scriptInventory || scriptInventory.count <= 0) return "";
    let detail = " Review context coverage: risk ratings " + scriptInventory.withRiskRatingCount + "/" + scriptInventory.count +
        ", data-access scopes " + scriptInventory.withDataAccessCount + "/" + scriptInventory.count +
        ", approval tickets " + scriptInventory.withApprovalTicketCount + "/" + scriptInventory.count + ".";
    const surfaces = formatCounts(scriptInventory.checkoutSurfaceCounts);
    const frames = formatCounts(scriptInventory.frameContextCounts);
    if (surfaces !== "none" || frames !== "none") {
        detail += " Checkout surface context: surfaces " + surfaces + "; frame contexts " + frames +
            "; iframe-scoped scripts " + scriptInventory.iframeScopedCount + ".";
    }
    return detail;
}

function scriptInventoryAuditDetail(evidence) {
    const audit = evidence && evidence.scriptInventoryAudit;
    if (!audit) return "";
    const bits = [];
    bits.push("Script inventory audit " + (audit.ok ? "passed" : "needs review"));
    bits.push(audit.approvedScripts + " approved");
    bits.push(audit.observedScripts + " observed");
    bits.push(audit.blockingIssues + " blocking issue" + (audit.blockingIssues === 1 ? "" : "s"));
    if (audit.unknownObserved > 0) bits.push(audit.unknownObserved + " unknown observed");
    if (audit.unauthorizedObserved > 0) bits.push(audit.unauthorizedObserved + " unauthorized observed");
    if (audit.integrityMismatches > 0) bits.push(audit.integrityMismatches + " integrity mismatch");
    if (audit.missingApproved > 0) bits.push(audit.missingApproved + " missing approved");
    if (audit.injectedAfterLoad > 0) bits.push(audit.injectedAfterLoad + " late injected");
    if (audit.runtimeViolations > 0) bits.push(audit.runtimeViolations + " runtime violation");
    if (audit.reviewMetadataGaps > 0) bits.push(audit.reviewMetadataGaps + " optional review metadata gap");
    if (audit.approvedIframeScopedScripts > 0 || audit.observedIframeScopedScripts > 0) {
        bits.push(audit.approvedIframeScopedScripts + " approved iframe-scoped / " + audit.observedIframeScopedScripts + " observed iframe-scoped");
    }
    return " " + bits.join("; ") + ".";
}

function pushScriptInventoryAuditEvidence(evidenceRows, evidence) {
    const audit = evidence && evidence.scriptInventoryAudit;
    if (!audit) return;
    evidenceRows.push({
        artefact: "Payment-page script inventory audit JSON summary",
        location: audit.source + " (sha256=" + audit.sourceSha256.slice(0, 12) + "...)",
        citation: "jso-protector --script-inventory-audit --json",
    });
}

function runtimeIncidentDetail(evidence) {
    const ri = evidence && evidence.runtimeIncidents;
    if (!ri) return "";
    if (ri.count === 0) {
        return " Runtime incident export was supplied and contains no incidents.";
    }
    const bits = [];
    bits.push("Runtime incident " + runtimeIncidentFormatLabel(ri) + " export summarizes " + ri.count + " Dashboard Monitoring incident" + (ri.count === 1 ? "" : "s"));
    const filters = formatRuntimeIncidentFilters(ri);
    if (filters !== "none") bits.push("filters: " + filters);
    if (ri.oldestReceivedUtc && ri.newestReceivedUtc) {
        bits.push("received " + ri.oldestReceivedUtc + " to " + ri.newestReceivedUtc);
    }
    const routing = formatRuntimeIncidentRouting(ri);
    if (routing !== "none") bits.push("routing: " + routing);
    const responseWindow = formatRuntimeIncidentResponseWindow(ri);
    if (responseWindow !== "none") bits.push("response window: " + responseWindow);
    const actionPlan = formatRuntimeIncidentActionPlan(ri);
    if (actionPlan !== "none") bits.push("action plan: " + actionPlan);
    const alertPlaybook = formatRuntimeIncidentAlertRoutingPlaybook(ri);
    if (alertPlaybook !== "none") bits.push("alert routing playbook: " + alertPlaybook);
    const dashboardActions = formatRuntimeIncidentDashboardActions(ri);
    if (dashboardActions !== "none") bits.push("dashboard actions: " + dashboardActions);
    bits.push(ri.unresolvedCount + " open/reviewing");
    bits.push(ri.unresolvedHighCriticalCount + " open/reviewing high-or-critical");
    return " " + bits.join("; ") + ".";
}

function pushRuntimeIncidentEvidence(evidenceRows, evidence) {
    const ri = evidence && evidence.runtimeIncidents;
    if (!ri) return;
    evidenceRows.push({
        artefact: "Dashboard Monitoring runtime incident " + runtimeIncidentFormatLabel(ri) + " summary",
        location: ri.source + " (sha256=" + ri.sourceSha256.slice(0, 12) + "...)",
        citation: ri.sourceFormat === "json"
            ? "dashboard/monitoring.aspx?runtime_export=incidents-json"
            : "dashboard/monitoring.aspx?runtime_export=incidents",
    });
}

function hasSecurityHeaderEvidence(evidence) {
    return !!(evidence && evidence.securityHeaders && evidence.securityHeaders.count > 0);
}

function securityHeaderDetail(evidence) {
    const sh = evidence && evidence.securityHeaders;
    if (!sh) return "";
    if (sh.count === 0) {
        return " Payment-page security-header snapshot was supplied and contains no page rows.";
    }
    const bits = [];
    bits.push("Payment-page security-header " + securityHeaderFormatLabel(sh) + " snapshot covers " + sh.count + " page" + (sh.count === 1 ? "" : "s"));
    bits.push("CSP " + sh.withCspCount + "/" + sh.count);
    bits.push("script-src " + sh.withScriptSrcCount + "/" + sh.count);
    bits.push("frame-src " + sh.withFrameSrcCount + "/" + sh.count);
    if (sh.withReportEndpointCount > 0) bits.push("report endpoint " + sh.withReportEndpointCount + "/" + sh.count);
    if (sh.withMonitorCount > 0) bits.push("monitor " + sh.withMonitorCount + "/" + sh.count);
    if (sh.withAlertRouteCount > 0) bits.push("alert route " + sh.withAlertRouteCount + "/" + sh.count);
    if (sh.baselineMismatchCount > 0) bits.push(sh.baselineMismatchCount + " baseline mismatch");
    if (sh.baselineMissingCount > 0) bits.push(sh.baselineMissingCount + " baseline missing");
    if (sh.baselineMismatchCount === 0 && sh.baselineMissingCount === 0 && sh.baselineMatchCount > 0) bits.push(sh.baselineMatchCount + " baseline match");
    if (sh.reviewAssistant && sh.reviewAssistant.sourceFree) bits.push("source-free review assistant packet");
    const surfaces = formatCounts(sh.checkoutSurfaceCounts);
    const frames = formatCounts(sh.frameContextCounts);
    if (surfaces !== "none" || frames !== "none") {
        bits.push("surfaces " + surfaces + "; frame contexts " + frames);
    }
    if (sh.oldestObservedUtc && sh.newestObservedUtc) {
        bits.push("observed " + formatRange(sh.oldestObservedUtc, sh.newestObservedUtc));
    }
    return " " + bits.join("; ") + ".";
}

function pushSecurityHeaderEvidence(evidenceRows, evidence) {
    const sh = evidence && evidence.securityHeaders;
    if (!sh) return;
    evidenceRows.push({
        artefact: "Payment-page security-header " + securityHeaderFormatLabel(sh) + " snapshot summary",
        location: sh.source + " (sha256=" + sh.sourceSha256.slice(0, 12) + "...)",
        citation: "jso-protector compliance pci-dss-v4 --payment-page-headers",
    });
}

function runtimeIncidentFormatLabel(runtimeIncidents) {
    return runtimeIncidents && runtimeIncidents.sourceFormat === "json" ? "JSON" : "CSV";
}

function securityHeaderFormatLabel(securityHeaders) {
    return securityHeaders && securityHeaders.sourceFormat === "json" ? "JSON" : "CSV";
}

function formatRuntimeIncidentFilters(runtimeIncidents) {
    const filters = runtimeIncidents && runtimeIncidents.filters;
    if (!filters || typeof filters !== "object") return "none";
    const parts = [];
    if (filters.status) parts.push("status=" + filters.status);
    if (filters.severity) parts.push("severity=" + filters.severity);
    if (filters.buildId) parts.push("buildId=" + filters.buildId);
    return parts.length ? parts.join(", ") : "none";
}

function formatRuntimeIncidentRouting(runtimeIncidents) {
    const routing = runtimeIncidents && runtimeIncidents.routing;
    if (!routing || typeof routing !== "object") return "none";
    const parts = [];
    if (routing.escalationLevel) parts.push("level=" + routing.escalationLevel);
    if (routing.recommendedQueue) parts.push("queue=" + routing.recommendedQueue);
    if (routing.preferredEvidence) parts.push("evidence=" + routing.preferredEvidence);
    if (routing.responseTargetLabel) parts.push("target=" + routing.responseTargetLabel);
    return parts.length ? parts.join(", ") : "none";
}

function formatRuntimeIncidentResponseWindow(runtimeIncidents) {
    const window = runtimeIncidents && runtimeIncidents.responseWindow;
    if (!window || typeof window !== "object") return "none";
    const parts = [];
    if (window.windowState) parts.push("state=" + window.windowState);
    if (window.targetLabel) parts.push("target=" + window.targetLabel);
    if (window.responseDueUtc) parts.push("due=" + window.responseDueUtc);
    if (typeof window.overdue === "boolean") {
        parts.push("overdue=" + (window.overdue ? "yes" : "no"));
    } else if (window.responseDueUtc) {
        parts.push("overdue=not evaluated");
    }
    if (window.basis) parts.push("basis=" + window.basis);
    return parts.length ? parts.join(", ") : "none";
}

function formatRuntimeIncidentActionPlan(runtimeIncidents) {
    const actionPlan = runtimeIncidents && runtimeIncidents.actionPlanSummary;
    if (!actionPlan || !actionPlan.incidentsWithActionPlan) return "none";
    const parts = ["plans=" + actionPlan.incidentsWithActionPlan];
    if (actionPlan.overdueCount) parts.push("overdue=" + actionPlan.overdueCount);
    if (actionPlan.acknowledgementRequiredCount) parts.push("acknowledgement-required=" + actionPlan.acknowledgementRequiredCount);
    const ownerCounts = formatCounts(actionPlan.nextOwnerCounts);
    if (ownerCounts !== "none") parts.push("owners " + ownerCounts);
    const escalationCounts = formatCounts(actionPlan.escalationCounts);
    if (escalationCounts !== "none") parts.push("levels " + escalationCounts);
    return parts.join("; ");
}

function formatRuntimeIncidentAlertRoutingPlaybook(runtimeIncidents) {
    const routing = runtimeIncidents && runtimeIncidents.routing;
    const playbook = routing && routing.alertRoutingPlaybook;
    if (!Array.isArray(playbook) || playbook.length === 0) return "none";
    return playbook.map(function (step) {
        const id = normalizeCsvCell(step && step.id);
        const lane = normalizeCsvCell(step && step.lane);
        if (id && lane) return id + " (" + lane + ")";
        return id || lane;
    }).filter(Boolean).join(", ") || "none";
}

function formatRuntimeIncidentDashboardActions(runtimeIncidents) {
    const actions = runtimeIncidents && runtimeIncidents.dashboardActions;
    if (!Array.isArray(actions) || actions.length === 0) return "none";
    return actions.map(function (action) {
        const id = normalizeCsvCell(action && action.id);
        const label = normalizeCsvCell(action && action.label);
        const enabled = action && action.enabled === true ? "enabled" : (action && action.enabled === false ? "not enabled" : "unknown");
        const openCount = Number.isFinite(action && action.matchingOpenIncidentCount) ? ", open=" + action.matchingOpenIncidentCount : "";
        const reviewingCount = Number.isFinite(action && action.matchingReviewingIncidentCount) ? ", reviewing=" + action.matchingReviewingIncidentCount : "";
        const name = id && label ? id + " (" + label + ")" : (id || label);
        return name ? name + " " + enabled + openCount + reviewingCount : "";
    }).filter(Boolean).join(", ") || "none";
}

function formatRuntimeIncidentCorrelation(runtimeIncidents) {
    const correlation = runtimeIncidents && runtimeIncidents.correlation;
    if (!correlation || typeof correlation !== "object") return "none";
    const fingerprintCount = correlation.repeatedFingerprintGroupCount || 0;
    const reasonCount = correlation.repeatedReasonGroupCount || 0;
    const groups = [].concat(
        Array.isArray(correlation.topFingerprintGroups) ? correlation.topFingerprintGroups : [],
        Array.isArray(correlation.topReasonGroups) ? correlation.topReasonGroups : []
    );
    const top = groups.slice(0, 3).map(function (group) {
        const key = normalizeCsvCell(group.key);
        const label = normalizeCsvCell(group.groupBy) || "signal";
        return key ? label + "=" + key + " (" + group.count + "x)" : "";
    }).filter(Boolean);
    const prefix = "fingerprints=" + fingerprintCount + ", reasons=" + reasonCount;
    return top.length ? prefix + "; top " + top.join(", ") : prefix;
}

function buildSummary(controls, evidence) {
    const total = controls.reduce(function (acc, c) { return acc + c.subRequirements.length; }, 0);
    let pass = 0, partial = 0, fail = 0, notInspected = 0;
    for (const c of controls) {
        for (const s of c.subRequirements) {
            if (s.status === "pass") pass++;
            else if (s.status === "partial") partial++;
            else if (s.status === "not_inspected") notInspected++;
            else fail++;
        }
    }
    const exitCode =
        evidence.signatureStatus.kind === "none" ? 2 :
        fail > 0 ? 1 :
        (partial > 0 || notInspected > 0) ? 1 :
        0;
    return {
        controls: controls.length,
        subRequirements: total,
        pass: pass,
        partial: partial,
        fail: fail,
        not_inspected: notInspected,
        signatureKind: evidence.signatureStatus.kind,
        signatureVerified: !!evidence.signatureStatus.verified,
        exitCode: exitCode,
    };
}

function buildPciDssReviewAssistant(summary, controls, evidence) {
    summary = summary || {};
    controls = Array.isArray(controls) ? controls : [];
    evidence = evidence || {};
    const questions = [];
    const scriptInventory = evidence.scriptInventory;
    const scriptInventoryAudit = evidence.scriptInventoryAudit;
    const securityHeaders = evidence.securityHeaders;
    const runtimeIncidents = evidence.runtimeIncidents;

    if ((summary.fail || 0) > 0 || (summary.partial || 0) > 0 || (summary.not_inspected || 0) > 0) {
        questions.push({
            topic: "Evidence gaps",
            prompt: "Review every failed, partial, or not-inspected PCI evidence row and decide which release owner must resolve it before checkout handoff.",
            ownerAction: "Attach the corrected evidence artifact or document the accepted customer-owned gap before reviewer delivery.",
        });
    }

    if (!summary.signatureVerified) {
        questions.push({
            topic: "Signed release proof",
            prompt: "Confirm the checkout artifact was signed with the release key and verified against the same files that will ship.",
            ownerAction: "Regenerate the protected release with --sign-release and rerun the PCI report with --root before relying on the packet.",
        });
    }

    if (!scriptInventory) {
        questions.push({
            topic: "Script authorization",
            prompt: "Confirm whether the checkout review needs a business-owned script inventory with authorization, justification, owner, risk, data-access, and approval-ticket fields.",
            ownerAction: "Attach --script-inventory evidence when reviewers need payment-page script authorization beyond the technical manifest.",
        });
    } else if ((scriptInventory.unauthorizedCount || 0) > 0 ||
        (scriptInventory.unknownAuthorizationCount || 0) > 0 ||
        (scriptInventory.missingJustificationCount || 0) > 0 ||
        (scriptInventory.withOwnerCount || 0) < (scriptInventory.count || 0)) {
        questions.push({
            topic: "Script authorization",
            prompt: "Review unauthorized, unknown-authorization, missing-justification, or owner-missing script inventory entries.",
            ownerAction: "Assign checkout owners and approval tickets before sharing the PCI packet.",
        });
    }

    if (scriptInventoryAudit && (scriptInventoryAudit.blockingIssues || 0) > 0) {
        questions.push({
            topic: "Observed script drift",
            prompt: "Review unknown, unauthorized, missing, changed, late-injected, or runtime-violation scripts from the approved-vs-observed audit summary.",
            ownerAction: "Resolve blocking drift or document the approved provider/release change before QSA handoff.",
        });
    }

    if (securityHeaders && (
        (securityHeaders.baselineMismatchCount || 0) > 0 ||
        (securityHeaders.baselineMissingCount || 0) > 0 ||
        (securityHeaders.withCspCount || 0) < (securityHeaders.count || 0) ||
        (securityHeaders.withScriptSrcCount || 0) < (securityHeaders.count || 0) ||
        (securityHeaders.withFrameSrcCount || 0) < (securityHeaders.count || 0) ||
        (securityHeaders.withReportEndpointCount || 0) < (securityHeaders.count || 0))) {
        questions.push({
            topic: "Header change evidence",
            prompt: "Review checkout pages or frames with security-header baseline drift, missing baselines, missing CSP coverage, or missing reporting routes.",
            ownerAction: "Attach the approved header change, provider notice, or remediation owner before reviewer delivery.",
        });
    }

    if (!evidence.beaconUrl || !evidence.siemAdapter ||
        (runtimeIncidents && ((runtimeIncidents.unresolvedCount || 0) > 0 ||
        (runtimeIncidents.unresolvedHighCriticalCount || 0) > 0))) {
        questions.push({
            topic: "Runtime incident routing",
            prompt: "Confirm browser-side checkout events have a Runtime Defense beacon, customer-owned alert route, response target, and current incident status.",
            ownerAction: "Wire --beacon-url and --siem or attach the filtered Dashboard Monitoring export with response owner and status action.",
        });
    }

    questions.push({
        topic: "QSA handoff boundary",
        prompt: "Confirm the packet is used as source-free evidence support, not as a Report on Compliance or a replacement for QSA-led assessment.",
        ownerAction: "Share only the generated packet and named attachments; keep raw source, protected output, raw incident rows, raw headers, card data, and secrets out of the handoff.",
    });

    return {
        sourceFree: true,
        title: "PCI DSS Review Assistant",
        intendedUse: "Use with a BYO AI key or internal reviewer to turn PCI DSS v4 checkout evidence into owner actions without sending source code, protected output, raw script rows, raw response headers, runtime incident payloads, payment-card data, provider keys, customer data, or secrets.",
        reviewerPrompt: "Review this JSO PCI DSS v4 evidence packet. Use only source-free summary counts, control statuses, attachment names and SHA-256 values, build identity, signed-release status, payment-page script inventory summaries, script-drift summaries, security-header summaries, runtime incident summaries, response-window labels, and customer-owned out-of-scope notes. Produce checkout-owner actions without claiming this replaces a QSA-led assessment.",
        safeInputs: [
            "control IDs, statuses, and summary counts",
            "build label, BuildID, polymorphism fingerprint, and signing-key digest",
            "file names and SHA-256 prefixes already shown in the report",
            "script inventory summary counts, domains, checkout surfaces, frame context, and source SHA-256",
            "script inventory audit summary counts and source SHA-256",
            "security-header summary counts, domains, baseline states, and source SHA-256",
            "runtime incident summary counts, status/severity counts, BuildIDs, routing labels, response-window labels, and source SHA-256",
            "customer-owned out-of-scope notes",
        ],
        doNotInclude: [
            "raw source code",
            "protected JavaScript output",
            "raw script inventory rows",
            "complete script URLs",
            "raw page URLs",
            "raw response headers",
            "cookies",
            "runtime incident payloads",
            "user agents",
            "IP addresses",
            "payment-card data",
            "customer personal data",
            "provider API keys",
            "collector tokens",
            "Web.config contents",
            "secrets",
        ],
        questions: questions,
    };
}

function redactUrl(u) {
    // Hide query string; keep scheme + host + path so the auditor knows
    // the destination class without leaking embedded tokens.
    try {
        const parsed = new URL(u);
        return parsed.protocol + "//" + parsed.host + parsed.pathname;
    } catch (x) { return "(unparseable URL)"; }
}

function renderScriptInventoryMarkdown(out, scriptInventory) {
    const formatLabel = scriptInventoryFormatLabel(scriptInventory);
    out.push("## Payment-page script inventory evidence");
    out.push("");
    out.push("Payment-page script inventory " + formatLabel + " export is summarized below. Keep the export as the attachment named in the artifact row; the report includes its SHA-256 so reviewers can verify they are looking at the same file.");
    out.push("");
    out.push("| Metric | Value |");
    out.push("|---|---|");
    out.push("| Export format | " + formatLabel + " |");
    out.push("| Export artifact | `" + mdCell(scriptInventory.source) + "` |");
    out.push("| Export sha256 | `" + scriptInventory.sourceSha256 + "` |");
    out.push("| Scripts | " + scriptInventory.count + " |");
    out.push("| Authorized | " + scriptInventory.authorizedCount + " |");
    out.push("| Unauthorized | " + scriptInventory.unauthorizedCount + " |");
    out.push("| Unknown authorization | " + scriptInventory.unknownAuthorizationCount + " |");
    out.push("| With justification | " + scriptInventory.withJustificationCount + " |");
    out.push("| Missing justification | " + scriptInventory.missingJustificationCount + " |");
    out.push("| With owner | " + scriptInventory.withOwnerCount + " |");
    out.push("| With integrity reference | " + scriptInventory.withIntegrityReferenceCount + " |");
    out.push("| With risk rating | " + scriptInventory.withRiskRatingCount + " |");
    out.push("| With data-access scope | " + scriptInventory.withDataAccessCount + " |");
    out.push("| With approval ticket | " + scriptInventory.withApprovalTicketCount + " |");
    out.push("| With checkout surface | " + scriptInventory.withCheckoutSurfaceCount + " |");
    out.push("| With frame context | " + scriptInventory.withFrameContextCount + " |");
    out.push("| Iframe-scoped scripts | " + scriptInventory.iframeScopedCount + " |");
    out.push("| External / inline | " + scriptInventory.externalCount + " / " + scriptInventory.inlineCount + " |");
    out.push("| Categories | " + mdCell(formatCounts(scriptInventory.categoryCounts)) + " |");
    out.push("| Owners | " + mdCell(formatCounts(scriptInventory.ownerCounts)) + " |");
    out.push("| Risk ratings | " + mdCell(formatCounts(scriptInventory.riskCounts)) + " |");
    out.push("| Data access | " + mdCell(formatCounts(scriptInventory.dataAccessCounts)) + " |");
    out.push("| Checkout surfaces | " + mdCell(formatCounts(scriptInventory.checkoutSurfaceCounts)) + " |");
    out.push("| Frame contexts | " + mdCell(formatCounts(scriptInventory.frameContextCounts)) + " |");
    out.push("| Frame owners | " + mdCell(formatCounts(scriptInventory.frameOwnerCounts)) + " |");
    out.push("| Domains | " + mdCell(formatScriptDomains(scriptInventory)) + " |");
    out.push("| Review range | " + mdCell(formatRange(scriptInventory.oldestReviewedUtc, scriptInventory.newestReviewedUtc)) + " |");
    out.push("");
}

function renderScriptInventoryAuditMarkdown(out, audit) {
    out.push("## Payment-page script inventory audit evidence");
    out.push("");
    out.push("Payment-page script inventory audit JSON is summarized below. Keep the JSON export as the attachment named in the artifact row; the report includes its SHA-256 so reviewers can verify they are looking at the same file.");
    out.push("");
    out.push("| Metric | Value |");
    out.push("|---|---|");
    out.push("| Export artifact | `" + mdCell(audit.source) + "` |");
    out.push("| Export sha256 | `" + audit.sourceSha256 + "` |");
    out.push("| Audit status | " + (audit.ok ? "PASS" : "NEEDS REVIEW") + " |");
    out.push("| Generated | " + mdCell(audit.generatedAt || "not available") + " |");
    out.push("| Approved inventory | " + mdCell(audit.approvedInventorySource || "not available") + " |");
    out.push("| Runtime snapshot | " + mdCell(audit.runtimeSnapshotSource || "not available") + " |");
    out.push("| Approved / observed scripts | " + audit.approvedScripts + " / " + audit.observedScripts + " |");
    out.push("| Unknown observed | " + audit.unknownObserved + " |");
    out.push("| Unauthorized observed | " + audit.unauthorizedObserved + " |");
    out.push("| Integrity mismatches | " + audit.integrityMismatches + " |");
    out.push("| Missing approved | " + audit.missingApproved + " |");
    out.push("| Late injected | " + audit.injectedAfterLoad + " |");
    out.push("| Runtime violations | " + audit.runtimeViolations + " |");
    out.push("| Inventory metadata gaps | " + audit.inventoryGaps + " |");
    out.push("| Review metadata gaps | " + audit.reviewMetadataGaps + " |");
    out.push("| Checkout surfaces | " + mdCell(formatCounts(audit.approvedCheckoutSurfaces)) + " approved / " + mdCell(formatCounts(audit.observedCheckoutSurfaces)) + " observed |");
    out.push("| Frame contexts | " + mdCell(formatCounts(audit.approvedFrameContexts)) + " approved / " + mdCell(formatCounts(audit.observedFrameContexts)) + " observed |");
    out.push("| Iframe-scoped scripts | " + audit.approvedIframeScopedScripts + " approved / " + audit.observedIframeScopedScripts + " observed |");
    out.push("| Risk ratings | " + audit.withRiskRating + " / " + audit.authorizedApprovedScripts + " |");
    out.push("| Data-access scopes | " + audit.withDataAccess + " / " + audit.authorizedApprovedScripts + " |");
    out.push("| Approval tickets | " + audit.withApprovalTicket + " / " + audit.authorizedApprovedScripts + " |");
    out.push("| Blocking issues | " + audit.blockingIssues + " |");
    out.push("");
}

function renderSecurityHeaderMarkdown(out, securityHeaders) {
    const formatLabel = securityHeaderFormatLabel(securityHeaders);
    out.push("## Payment-page security-header evidence");
    out.push("");
    out.push("Payment-page security-header " + formatLabel + " snapshot is summarized below. Keep the snapshot as the attachment named in the artifact row; the report includes its SHA-256 so reviewers can verify they are looking at the same file.");
    out.push("");
    out.push("| Metric | Value |");
    out.push("|---|---|");
    out.push("| Export format | " + formatLabel + " |");
    out.push("| Export artifact | `" + mdCell(securityHeaders.source) + "` |");
    out.push("| Export sha256 | `" + securityHeaders.sourceSha256 + "` |");
    out.push("| Pages | " + securityHeaders.count + " |");
    out.push("| Status counts | " + mdCell(formatCounts(securityHeaders.statusCounts)) + " |");
    out.push("| With CSP | " + securityHeaders.withCspCount + " |");
    out.push("| CSP report-only | " + securityHeaders.withReportOnlyCspCount + " |");
    out.push("| With script-src/default-src | " + securityHeaders.withScriptSrcCount + " |");
    out.push("| With frame-src/child-src | " + securityHeaders.withFrameSrcCount + " |");
    out.push("| With connect-src/default-src | " + securityHeaders.withConnectSrcCount + " |");
    out.push("| With report endpoint | " + securityHeaders.withReportEndpointCount + " |");
    out.push("| With HSTS | " + securityHeaders.withHstsCount + " |");
    out.push("| With X-Frame-Options | " + securityHeaders.withXFrameOptionsCount + " |");
    out.push("| With Referrer-Policy | " + securityHeaders.withReferrerPolicyCount + " |");
    out.push("| With Permissions-Policy | " + securityHeaders.withPermissionsPolicyCount + " |");
    out.push("| With monitor | " + securityHeaders.withMonitorCount + " |");
    out.push("| With alert route | " + securityHeaders.withAlertRouteCount + " |");
    out.push("| Baseline coverage | " + mdCell(formatSecurityHeaderBaseline(securityHeaders)) + " |");
    out.push("| Checkout surfaces | " + mdCell(formatCounts(securityHeaders.checkoutSurfaceCounts)) + " |");
    out.push("| Frame contexts | " + mdCell(formatCounts(securityHeaders.frameContextCounts)) + " |");
    out.push("| Frame owners | " + mdCell(formatCounts(securityHeaders.frameOwnerCounts)) + " |");
    out.push("| Domains | " + mdCell(formatSecurityHeaderDomains(securityHeaders)) + " |");
    out.push("| Observed range | " + mdCell(formatRange(securityHeaders.oldestObservedUtc, securityHeaders.newestObservedUtc)) + " |");
    out.push("| Review assistant packet | " + (securityHeaders.reviewAssistant && securityHeaders.reviewAssistant.sourceFree ? "source-free" : "not included") + " |");
    out.push("");
    renderSecurityHeaderReviewAssistantMarkdown(out, securityHeaders.reviewAssistant);
}

function renderSecurityHeaderReviewAssistantMarkdown(out, assistant) {
    if (!assistant) return;
    out.push("### Security Header Review Assistant");
    out.push("");
    out.push(mdCell(assistant.intendedUse));
    out.push("");
    out.push("**Reviewer prompt:** " + mdCell(assistant.reviewerPrompt));
    out.push("");
    out.push("Safe inputs:");
    for (const item of assistant.safeInputs || []) out.push("- " + mdCell(item));
    out.push("");
    out.push("Do not include:");
    for (const item of assistant.doNotInclude || []) out.push("- " + mdCell(item));
    out.push("");
    out.push("| Topic | Question | Owner action |");
    out.push("|---|---|---|");
    for (const item of assistant.questions || []) {
        out.push("| " + mdCell(item.topic) + " | " + mdCell(item.prompt) + " | " + mdCell(item.ownerAction) + " |");
    }
    out.push("");
}

function renderRuntimeIncidentMarkdown(out, runtimeIncidents) {
    const formatLabel = runtimeIncidentFormatLabel(runtimeIncidents);
    out.push("## Runtime incident evidence");
    out.push("");
    out.push("Dashboard Monitoring " + formatLabel + " export is summarized below. Keep the export as the attachment named in the artifact row; the report includes its SHA-256 so reviewers can verify they are looking at the same file.");
    out.push("");
    out.push("| Metric | Value |");
    out.push("|---|---|");
    out.push("| Export format | " + formatLabel + " |");
    out.push("| Export artifact | `" + mdCell(runtimeIncidents.source) + "` |");
    out.push("| Export sha256 | `" + runtimeIncidents.sourceSha256 + "` |");
    out.push("| Filters | " + mdCell(formatRuntimeIncidentFilters(runtimeIncidents)) + " |");
    out.push("| Routing | " + mdCell(formatRuntimeIncidentRouting(runtimeIncidents)) + " |");
    out.push("| Repeated-signal correlation | " + mdCell(formatRuntimeIncidentCorrelation(runtimeIncidents)) + " |");
    out.push("| Alert routing playbook | " + mdCell(formatRuntimeIncidentAlertRoutingPlaybook(runtimeIncidents)) + " |");
    out.push("| Dashboard actions | " + mdCell(formatRuntimeIncidentDashboardActions(runtimeIncidents)) + " |");
    out.push("| Response window | " + mdCell(formatRuntimeIncidentResponseWindow(runtimeIncidents)) + " |");
    out.push("| Incident action plan | " + mdCell(formatRuntimeIncidentActionPlan(runtimeIncidents)) + " |");
    out.push("| Incidents | " + runtimeIncidents.count + " |");
    out.push("| Status counts | " + mdCell(formatCounts(runtimeIncidents.statusCounts)) + " |");
    out.push("| Severity counts | " + mdCell(formatCounts(runtimeIncidents.severityCounts)) + " |");
    out.push("| Open/reviewing | " + runtimeIncidents.unresolvedCount + " |");
    out.push("| Open/reviewing high-or-critical | " + runtimeIncidents.unresolvedHighCriticalCount + " |");
    out.push("| Build IDs | " + mdCell(formatBuildIds(runtimeIncidents)) + " |");
    out.push("| Received range | " + mdCell(formatRange(runtimeIncidents.oldestReceivedUtc, runtimeIncidents.newestReceivedUtc)) + " |");
    out.push("| Event range | " + mdCell(formatRange(runtimeIncidents.oldestEventUtc, runtimeIncidents.newestEventUtc)) + " |");
    out.push("");
    renderRuntimeIncidentActionPlanMarkdown(out, runtimeIncidents.actionPlanSummary);
    renderRuntimeIncidentDashboardActionsMarkdown(out, runtimeIncidents.dashboardActions);
    renderRuntimeIncidentAlertRoutingPlaybookMarkdown(out, runtimeIncidents);
    renderRuntimeIncidentResponseChecklistMarkdown(out, runtimeIncidents.responseChecklist);
}

function renderRuntimeIncidentActionPlanMarkdown(out, actionPlan) {
    if (!actionPlan || !Array.isArray(actionPlan.topActions) || actionPlan.topActions.length === 0) return;
    out.push("### Runtime incident action plan");
    out.push("");
    out.push("These source-free row actions name the next owner, response due state, evidence packet, and status move for each exported incident.");
    out.push("");
    out.push("| Incident | Level | Next owner | Due | State | Status move | Evidence | Next action |");
    out.push("|---|---|---|---|---|---|---|---|");
    for (const row of actionPlan.topActions) {
        out.push("| " + [
            row.incidentId || "",
            row.escalationLevel || "",
            row.nextOwner || "",
            row.responseDueUtc || row.responseTargetLabel || "",
            row.windowState || "",
            row.statusTransition || "",
            row.evidence || "",
            row.nextAction || "",
        ].map(mdCell).join(" | ") + " |");
    }
    out.push("");
}

function renderRuntimeIncidentDashboardActionsMarkdown(out, actions) {
    if (!Array.isArray(actions) || actions.length === 0) return;
    out.push("### Runtime incident dashboard actions");
    out.push("");
    out.push("These actions are source-free dashboard workflow hints. They describe account-scoped status actions available in Dashboard Monitoring and do not replace the customer's long-term incident system.");
    out.push("");
    out.push("| Action | Enabled | Scope | Status change | Safety |");
    out.push("|---|---|---|---|---|");
    for (const action of actions) {
        const enabled = action.enabled === true ? "yes" : (action.enabled === false ? "no" : "n/a");
        const statusChange = (action.statusFrom || "") && (action.statusTo || "")
            ? action.statusFrom + " -> " + action.statusTo
            : "";
        out.push("| " + mdCell(action.label || action.id) + " | " + mdCell(enabled) + " | " + mdCell(action.scope || action.filterContext || "") + " | " + mdCell(statusChange) + " | " + mdCell(action.safety || "") + " |");
    }
    out.push("");
}

function renderRuntimeIncidentAlertRoutingPlaybookMarkdown(out, runtimeIncidents) {
    const playbook = runtimeIncidents && runtimeIncidents.routing && runtimeIncidents.routing.alertRoutingPlaybook;
    if (!Array.isArray(playbook) || playbook.length === 0) return;
    out.push("### Runtime incident alert routing playbook");
    out.push("");
    out.push("This playbook is source-free and customer-owned. It keeps Dashboard Monitoring as first-triage evidence while naming the owner, target, evidence, and boundary for each handoff lane.");
    out.push("");
    out.push("| Lane | Owner | Target | Evidence | Action | Boundary |");
    out.push("|---|---|---|---|---|---|");
    for (const step of playbook) {
        out.push("| " + mdCell(step.lane || step.id) + " | " + mdCell(step.owner) + " | " + mdCell(step.target) + " | " + mdCell(step.evidence) + " | " + mdCell(step.action) + " | " + mdCell(step.boundary) + " |");
    }
    out.push("");
}

function renderRuntimeIncidentResponseChecklistMarkdown(out, checklist) {
    if (!checklist || !Array.isArray(checklist.steps) || checklist.steps.length === 0) return;
    out.push("### Runtime incident response checklist");
    out.push("");
    out.push("This checklist is source-free and customer-owned. It turns the export summary into reviewer and on-call actions without replacing a managed security-operations console.");
    out.push("");
    out.push("| Step | Owner | Target | Action |");
    out.push("|---|---|---|---|");
    for (const step of checklist.steps) {
        out.push("| " + mdCell(step.id) + " | " + mdCell(step.owner) + " | " + mdCell(step.target) + " | " + mdCell(step.action) + " |");
    }
    out.push("");
}

function renderPciDssReviewAssistantMarkdown(out, assistant) {
    if (!assistant) return;
    out.push("## PCI DSS Review Assistant");
    out.push("");
    out.push(mdCell(assistant.intendedUse));
    out.push("");
    out.push("**Reviewer prompt:** " + mdCell(assistant.reviewerPrompt));
    out.push("");
    out.push("Safe inputs:");
    for (const item of assistant.safeInputs || []) out.push("- " + mdCell(item));
    out.push("");
    out.push("Do not include:");
    for (const item of assistant.doNotInclude || []) out.push("- " + mdCell(item));
    out.push("");
    out.push("| Topic | Question | Owner action |");
    out.push("|---|---|---|");
    for (const item of assistant.questions || []) {
        out.push("| " + mdCell(item.topic || "") + " | " + mdCell(item.prompt || "") + " | " + mdCell(item.ownerAction || "") + " |");
    }
    out.push("");
}

function formatCounts(counts) {
    const keys = Object.keys(counts || {}).sort();
    if (keys.length === 0) return "none";
    return keys.map(function (k) { return k + ": " + counts[k]; }).join(", ");
}

function formatBuildIds(runtimeIncidents) {
    if (!runtimeIncidents || runtimeIncidents.uniqueBuildIdCount === 0) return "none";
    const suffix = runtimeIncidents.uniqueBuildIdCount > runtimeIncidents.buildIds.length
        ? " +" + (runtimeIncidents.uniqueBuildIdCount - runtimeIncidents.buildIds.length) + " more"
        : "";
    return runtimeIncidents.buildIds.join(", ") + suffix;
}

function formatScriptDomains(scriptInventory) {
    if (!scriptInventory || scriptInventory.uniqueDomainCount === 0) return "none";
    const suffix = scriptInventory.uniqueDomainCount > scriptInventory.domains.length
        ? " +" + (scriptInventory.uniqueDomainCount - scriptInventory.domains.length) + " more"
        : "";
    return scriptInventory.domains.join(", ") + suffix;
}

function formatSecurityHeaderDomains(securityHeaders) {
    if (!securityHeaders || securityHeaders.uniqueDomainCount === 0) return "none";
    const suffix = securityHeaders.uniqueDomainCount > securityHeaders.domains.length
        ? " +" + (securityHeaders.uniqueDomainCount - securityHeaders.domains.length) + " more"
        : "";
    return securityHeaders.domains.join(", ") + suffix;
}

function formatSecurityHeaderBaseline(securityHeaders) {
    if (!securityHeaders || securityHeaders.baselineKnownCount === 0) return "none";
    const missing = securityHeaders.baselineMissingCount || 0;
    const unknown = Math.max(0, securityHeaders.baselineKnownCount - securityHeaders.baselineMatchCount - securityHeaders.baselineMismatchCount - missing);
    return securityHeaders.baselineMatchCount + " match, " +
        securityHeaders.baselineMismatchCount + " mismatch, " +
        missing + " missing, " +
        unknown + " not stated";
}

function formatRange(oldest, newest) {
    if (!oldest || !newest) return "not available";
    return oldest === newest ? oldest : (oldest + " to " + newest);
}

function mdCell(value) {
    return String(value == null ? "" : value)
        .replace(/\r?\n/g, " ")
        .replace(/\|/g, "\\|");
}

function renderMarkdown(view) {
    const out = [];
    out.push("# PCI DSS v" + controlsRef._meta.version + " Compliance Evidence Report");
    out.push("");
    if (view.organizationName) out.push("**Organization:** " + view.organizationName);
    if (view.buildLabel) out.push("**Build label:** " + view.buildLabel);
    if (view.evidence.manifest.buildId) out.push("**Build ID:** `" + view.evidence.manifest.buildId + "`");
    if (view.evidence.manifest.polymorphismFingerprint) {
        out.push("**Polymorphism fingerprint:** `" + view.evidence.manifest.polymorphismFingerprint + "`");
    }
    if (view.evidence.publicKeyDigest) {
        out.push("**Signing-key SHA-256:** `" + view.evidence.publicKeyDigest + "`");
    }
    out.push("**Generated:** " + view.generatedAt);
    out.push("");
    out.push("## Summary");
    out.push("");
    out.push("| Metric | Value |");
    out.push("|---|---|");
    out.push("| Controls evaluated | " + view.summary.controls + " |");
    out.push("| Sub-requirements evaluated | " + view.summary.subRequirements + " |");
    out.push("| Pass | " + view.summary.pass + " |");
    out.push("| Partial | " + view.summary.partial + " |");
    out.push("| Fail | " + view.summary.fail + " |");
    out.push("| Not inspected | " + view.summary.not_inspected + " |");
    out.push("| Signature kind | " + view.summary.signatureKind + " |");
    out.push("| Signature verified | " + (view.summary.signatureVerified ? "yes" : "no") + " |");
    out.push("");
    out.push("Overall exit code: **" + view.summary.exitCode + "**  ");
    out.push("(0 = fully evidenced; 1 = gaps; 2 = manifest unsigned)");
    out.push("");
    renderPciDssReviewAssistantMarkdown(out, view.reviewAssistant);
    if (view.evidence.scriptInventory) {
        renderScriptInventoryMarkdown(out, view.evidence.scriptInventory);
    }
    if (view.evidence.scriptInventoryAudit) {
        renderScriptInventoryAuditMarkdown(out, view.evidence.scriptInventoryAudit);
    }
    if (view.evidence.securityHeaders) {
        renderSecurityHeaderMarkdown(out, view.evidence.securityHeaders);
    }
    if (view.evidence.runtimeIncidents) {
        renderRuntimeIncidentMarkdown(out, view.evidence.runtimeIncidents);
    }
    out.push("## Controls");
    out.push("");
    for (const c of view.controls) {
        out.push("### " + c.id + " - " + c.title);
        out.push("");
        out.push("Overall status: **" + c.status.toUpperCase() + "**");
        out.push("");
        for (const s of c.subRequirements) {
            out.push("- **" + s.id + "** *(" + s.status + ")* - " + s.title);
            if (s.detail) out.push("  - " + s.detail);
            if (s.evidence && s.evidence.length > 0) {
                for (const e of s.evidence) {
                    out.push("  - Evidence: " + e.artefact + " (" + e.location + ") - cite: " + e.citation);
                }
            }
        }
        out.push("");
    }
    out.push("## File inventory");
    out.push("");
    out.push("| File | sha256 | Watermark | On-disk |");
    out.push("|---|---|---|---|");
    for (const f of view.evidence.files) {
        const wm = !f.watermark.inspected
            ? "(not inspected)"
            : (!f.watermark.present
                ? "absent"
                : (f.watermark.valid === true
                    ? "valid"
                    : (f.watermark.valid === false
                        ? "INVALID"
                        : "present (unverified)")));
        const ondisk = f.ondiskMatches === true ? "match" :
            f.ondiskMatches === false ? "MISMATCH" :
            "(not inspected)";
        out.push("| `" + f.name + "` | `" + (f.sha256 || "").slice(0, 12) + "...` | " + wm + " | " + ondisk + " |");
    }
    out.push("");
    out.push("## Out-of-scope (customer-owned)");
    out.push("");
    for (const oos of controlsRef.out_of_scope_customer_owns) {
        out.push("- **" + oos.id + "**: " + oos.note);
    }
    out.push("");
    out.push("---");
    out.push("");
    out.push("Generated by `jso-protector compliance pci-dss-v4`. This report aggregates evidence that JSO directly contributes; it is not a Report on Compliance (ROC) and does not substitute for a QSA-led assessment. See [PCI DSS v" + controlsRef._meta.version + "](" + controlsRef._meta.spec_url + ") for the full standard.");
    out.push("");
    return out.join("\n");
}

module.exports = {
    REPORT_SCHEMA_VERSION: REPORT_SCHEMA_VERSION,
    generateReport: generateReport,
    // Exposed for tests:
    _collectEvidence: collectEvidence,
    _collectScriptInventoryEvidence: collectScriptInventoryEvidence,
    _collectSecurityHeaderEvidence: collectSecurityHeaderEvidence,
    _collectRuntimeIncidentEvidence: collectRuntimeIncidentEvidence,
    _mapControls: mapControls,
    _renderMarkdown: renderMarkdown,
    _buildSummary: buildSummary,
    _buildPciDssReviewAssistant: buildPciDssReviewAssistant,
};
