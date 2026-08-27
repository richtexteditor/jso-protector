"use strict";

// `jso-protector compliance <framework>` CLI dispatch.
//
// Today the only framework is pci-dss-v4. The structure is open-ended
// so SOC 2 evidence / ISO 27001 / EU DSA reports can be added as
// peer subcommands without re-shuffling the layout.
//
// jso-protector.js intercepts argv[0] === "compliance" and forwards
// the remaining argv here.

const fs   = require("node:fs");
const path = require("node:path");

const FRAMEWORKS = {
    "pci-dss-v4": require("./pci-dss-v4/index.js"),
};

function printHelp(stream) {
    stream = stream || process.stdout;
    stream.write(
`jso-protector compliance <framework> [options]

Frameworks:
  pci-dss-v4    PCI DSS v4.0.1 evidence report (controls 6.4.3, 11.6.1).

Common options (any framework):
  --manifest <path>          Path to .manifest.json.sig (signed) or
                             .manifest.json (with --allow-unsigned).
                             REQUIRED.
  --root <dir>               Re-hash files on disk and inspect watermarks.
  --watermark-key <key>      HMAC key used at build time. With this, the
                             reporter validates every per-file watermark
                             signature; without, presence-only.
  --beacon-url <url>         BeaconUrl that runtime defense events post
                             to. Wired => 11.6.1.a/b can be evidenced.
  --siem <name>              SIEM adapter wired downstream of the beacon.
                             splunk-hec | elasticsearch | webhook
  --runtime-incidents <csv|json>
                             Dashboard Monitoring incident CSV or JSON export.
                             Summarized as source-free 11.6.1 evidence.
  --script-inventory <csv|json>
                             Payment-page script inventory export with
                             authorization and justification fields.
  --script-inventory-audit <json>
                             JSON output from --script-inventory-audit --json.
                             Summarized as source-free inventory reconciliation evidence.
  --payment-page-headers <csv|json>
                             Payment-page security-header snapshot with CSP,
                             frame, HSTS, referrer-policy, monitor, alert-route,
                             and baseline-hash metadata. Summarized as source-free
                             11.6.1 evidence.
  --organization <name>      Customer name to embed in the report header.
  --build-label <label>      Override the manifest's label field.
  --output <path>            Write Markdown to this path; otherwise stdout.
  --json                     Emit JSON envelope to stdout (overrides Markdown).
  --json-output <path>       Write JSON envelope to this path.
  --allow-unsigned           Accept a bare manifest.json (partial report
                             only; req 6.4.3.b will FAIL).
  --push <profile>           After generating, push the report to a GRC
                             platform as evidence. profile: generic | drata | vanta.
  --push-endpoint <url>      GRC evidence endpoint (or env JSO_GRC_ENDPOINT).
                             Tenant-specific; you supply it.
  --push-token <token>       Bearer token for the GRC API (or env JSO_GRC_TOKEN).
  --push-secret <secret>     HMAC secret for the generic profile (or env
                             JSO_GRC_SECRET); signs the body like the
                             jso-beacon-slack webhook adapter.
  -h, --help                 Show this help.

Exit codes:
  0    Every PCI DSS sub-requirement passes.
  1    Evidence gaps (partial or fail) that need operator action.
  2    Manifest is unsigned or unreadable.

Examples:

  # Smoke a freshly-built signed manifest.
  jso-protector compliance pci-dss-v4 \\
    --manifest dist/build.manifest.json.sig \\
    --root dist \\
    --watermark-key "\${JSO_WATERMARK_KEY}" \\
    --beacon-url "https://beacon.example.com/v1/jso" \\
    --siem splunk-hec \\
    --script-inventory reports/payment-script-inventory.json \\
    --script-inventory-audit reports/payment-script-inventory-audit.json \\
    --payment-page-headers reports/payment-page-headers.json \\
    --runtime-incidents reports/runtime-incidents.csv \\
    --organization "Example Corp" \\
    --output reports/pci-dss-v4.md

  # JSON for tooling.
  jso-protector compliance pci-dss-v4 \\
    --manifest dist/build.manifest.json.sig --json | jq .summary
`);
}

async function main(argv) {
    if (!Array.isArray(argv)) argv = [];
    if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
        printHelp();
        return 0;
    }
    const framework = argv[0];
    const generator = FRAMEWORKS[framework];
    if (!generator) {
        process.stderr.write("Unknown compliance framework: " + framework + "\n");
        process.stderr.write("Supported: " + Object.keys(FRAMEWORKS).join(", ") + "\n");
        return 2;
    }
    const opts = parseArgs(argv.slice(1));
    if (opts.help) { printHelp(); return 0; }
    if (!opts.manifest) {
        process.stderr.write("--manifest <path> is required\n");
        return 2;
    }
    const result = generator.generateReport({
        manifestPath: opts.manifest,
        rootDir: opts.root || null,
        watermarkKey: opts.watermarkKey || process.env.JSO_WATERMARK_KEY || null,
        beaconUrl: opts.beaconUrl || null,
        siemAdapter: opts.siem || null,
        runtimeIncidentsPath: opts.runtimeIncidents || null,
        scriptInventoryPath: opts.scriptInventory || null,
        scriptInventoryAuditPath: opts.scriptInventoryAudit || null,
        securityHeadersPath: opts.paymentPageHeaders || null,
        organizationName: opts.organization || null,
        buildLabel: opts.buildLabel || null,
        includeUnsignedManifest: !!opts.allowUnsigned,
    });

    if (opts.jsonOutput) {
        fs.writeFileSync(opts.jsonOutput, JSON.stringify(result.json, null, 2) + "\n", "utf8");
    }
    if (opts.json) {
        process.stdout.write(JSON.stringify(result.json, null, 2) + "\n");
    } else {
        if (opts.output) {
            fs.writeFileSync(opts.output, result.markdown, "utf8");
            process.stderr.write("compliance report written: " + opts.output + " (exit " + result.exitCode + ")\n");
        } else {
            process.stdout.write(result.markdown);
        }
    }

    // Optional: push the generated report to a GRC platform as evidence.
    // Transport failure is reported but does NOT change the compliance
    // exit code — the report's own verdict is the authority; forwarding
    // is a side channel.
    if (opts.push) {
        const { createEvidenceForwarder } = require("./evidence-forwarder.js");
        const forward = createEvidenceForwarder({
            profile: opts.push,
            endpoint: opts.pushEndpoint || process.env.JSO_GRC_ENDPOINT,
            token: opts.pushToken || process.env.JSO_GRC_TOKEN,
            secret: opts.pushSecret || process.env.JSO_GRC_SECRET,
            organizationName: opts.organization || null,
        });
        const res = await forward(result.json);
        if (res.ok) {
            process.stderr.write("evidence pushed to " + opts.push + " (status " + res.status + ", artifact " + (res.artifactSha256 || "").slice(0, 12) + "...)\n");
        } else {
            process.stderr.write("evidence push to " + opts.push + " FAILED: " + (res.error || ("status " + res.status)) + "\n");
        }
    }
    return result.exitCode;
}

function parseArgs(argv) {
    const out = { help: false };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        switch (a) {
        case "-h": case "--help": out.help = true; break;
        case "--manifest":         out.manifest = argv[++i]; break;
        case "--root":             out.root = argv[++i]; break;
        case "--watermark-key":    out.watermarkKey = argv[++i]; break;
        case "--beacon-url":       out.beaconUrl = argv[++i]; break;
        case "--siem":             out.siem = argv[++i]; break;
        case "--runtime-incidents": out.runtimeIncidents = argv[++i]; break;
        case "--script-inventory": out.scriptInventory = argv[++i]; break;
        case "--script-inventory-audit": out.scriptInventoryAudit = argv[++i]; break;
        case "--payment-page-headers": out.paymentPageHeaders = argv[++i]; break;
        case "--organization":     out.organization = argv[++i]; break;
        case "--build-label":      out.buildLabel = argv[++i]; break;
        case "--output":           out.output = argv[++i]; break;
        case "--json":             out.json = true; break;
        case "--json-output":      out.jsonOutput = argv[++i]; break;
        case "--allow-unsigned":   out.allowUnsigned = true; break;
        case "--push":             out.push = argv[++i]; break;
        case "--push-endpoint":    out.pushEndpoint = argv[++i]; break;
        case "--push-token":       out.pushToken = argv[++i]; break;
        case "--push-secret":      out.pushSecret = argv[++i]; break;
        default:
            if (a.startsWith("--")) {
                process.stderr.write("Unknown flag: " + a + "\n");
                throw new Error("usage error: " + a);
            }
            // ignore positional after subcommand
        }
    }
    return out;
}

module.exports = { main: main, printHelp: printHelp, FRAMEWORKS: FRAMEWORKS };
