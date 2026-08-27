"use strict";

// `jso ai <subcommand>` CLI.
//
// The main jso-protector.js CLI intercepts argv[0] === "ai" at the top of
// main() and delegates here. Keeps the AI surface out of the giant
// parseArgs switch and lets each subcommand have its own flag set.
//
// Subcommands:
//   jso ai usage                              # current-month quota counters
//   jso ai preset-suggest <description...>    # describe app → jso.config
//   jso ai compat-check <file>                # scan a JS file
//   jso ai explain-error <error...>           # diagnose a runtime error
//
// All output is JSON by default (machine-friendly, easy to pipe to jq).
// `--pretty` re-renders the same data in a human-readable form for the
// terminal.
//
// Exit codes:
//   0  -- ok (request succeeded, no business-logic error)
//   1  -- business-logic error (ok: false) or HTTP error
//   2  -- argument / usage error

const fs   = require("node:fs");
const path = require("node:path");
const ai   = require("./ai.js");

function printHelp(stream = process.stdout) {
    stream.write(
`jso ai <subcommand> [options]

Subcommands:
  usage                                Current-month AI quota counters.
  preset-suggest <description...>      Generate jso.config from a description.
  compat-check <file> [--framework F]  Scan a single JS file for obfuscation pitfalls.
  compat-scan [--config jso.config]    Pre-obfuscation gate: AI-scan every input
                                       file in your jso.config. Exits non-zero on
                                       errors. Drop into CI before jso-protector.
  explain-error <error...>             Diagnose a protected-output runtime error.

Authentication:
  Either pass --api-key / --api-password, or set the JSO_API_KEY and
  JSO_API_PASSWORD environment variables. Same credentials as the
  obfuscation API.

Options (all subcommands):
  --api-key VALUE        Base64 APIKey from /dashboard/apikeys.aspx.
  --api-password VALUE   Base64 APIPwd from /dashboard/apikeys.aspx.
  --endpoint URL         Override the JSO base URL (default: production).
  --pretty               Human-readable output instead of JSON.
  --timeout MS           Request timeout in milliseconds (default: 30000).
  -h, --help             Show this help.

Examples:
  jso ai usage --pretty
  jso ai preset-suggest "React SaaS, balanced, lock to example.com" > jso.config.json
  jso ai compat-check src/app.js --framework react --pretty
  jso ai explain-error "Uncaught TypeError: api.charge is not a function"
`);
}

function parseFlags(argv) {
    const opts = {};
    const positional = [];
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        switch (a) {
            case "--api-key":      opts.apiKey      = argv[++i]; break;
            case "--api-password": opts.apiPassword = argv[++i]; break;
            case "--endpoint":     opts.endpoint    = argv[++i]; break;
            case "--framework":    opts.framework   = argv[++i]; break;
            case "--timeout":      opts.timeoutMs   = parseInt(argv[++i], 10); break;
            case "--pretty":       opts.pretty      = true; break;
            case "--config":       opts.config      = argv[++i]; break;
            case "--max-files":    opts.maxFiles    = parseInt(argv[++i], 10); break;
            case "--fail-on":      opts.failOn      = argv[++i]; break;   // "error" (default) | "warning" | "never"
            case "-h": case "--help": opts.help = true; break;
            default:
                if (a.startsWith("--")) {
                    throw Object.assign(new Error("Unknown flag: " + a), { exitCode: 2 });
                }
                positional.push(a);
        }
    }
    return { opts, positional };
}

function jsonOut(value) {
    process.stdout.write(JSON.stringify(value, null, 2) + "\n");
}

// Per-subcommand "pretty" formatters. Each receives the parsed envelope.

function prettyProviderKeyHealth(providerKey) {
    if (!providerKey || typeof providerKey !== "object") return "";
    const status = providerKey.status ? " [" + providerKey.status + "]" : "";
    const provider = providerKey.provider ? " (" + providerKey.provider + ")" : "";
    let s = "";
    s += "AI key health:      " + (providerKey.label || providerKey.status || "Unknown") + provider + status + "\n";
    if (providerKey.nextTestDueUtc) s += "next key test:      " + providerKey.nextTestDueUtc + "\n";
    if (providerKey.rotationDueUtc) s += "rotation review:    " + providerKey.rotationDueUtc + "\n";
    if (providerKey.recommendedAction) s += "key action:         " + providerKey.recommendedAction + "\n";
    return s;
}

function prettyUsage(r) {
    if (!r.ok) return "[" + r.error + "] " + r.message + "\n";
    let s = "";
    s += "tier:               " + r.tier + (r.previewMode ? " (preview mode)" : "") + "\n";
    s += "billing month:      " + r.billingMonth + "\n";
    s += "actions:            " + r.actionsUsed + " / " + r.actionsCap + "   (" + r.actionsRemaining + " remaining)\n";
    s += "tokens:             " + r.tokensUsed + " / " + r.tokensCap + "   (" + r.tokensRemaining + " remaining)\n";
    s += "cost (cents):       " + r.approxCostCents + " / " + r.costCapCents + "   (" + r.costRemainingCents + " remaining)\n";
    s += "quota rejections:   " + r.quotaRejections + "\n";
    s += prettyProviderKeyHealth(r.providerKey);
    s += "as of:              " + r.asOfUtc + "\n";
    return s;
}

function prettyPreset(r) {
    if (!r.ok) return "[" + r.error + "] " + r.message + "\n";
    let s = "";
    s += "# Signals\n";
    for (const sig of r.suggestion.signals) s += "  - " + sig + "\n";
    s += "\n# Suggested jso.config.json\n";
    s += JSON.stringify(r.suggestion.config, null, 2) + "\n";
    return s;
}

function prettyCompat(r) {
    if (!r.ok) return "[" + r.error + "] " + r.message + "\n";
    const sum = r.report.summary;
    let s = "Summary:  " + sum.errors + " error(s)  " + sum.warnings + " warning(s)  " + sum.infos + " info(s)\n\n";
    for (const f of r.report.findings) {
        s += "[" + f.severity.toUpperCase() + "] " + f.category + " at line " + f.line + ":" + f.column + "\n";
        s += "  " + f.message + "\n";
        s += "  fix: " + f.suggestedFix + "\n\n";
    }
    return s;
}

function prettyExplain(r) {
    if (!r.ok) return "[" + r.error + "] " + r.message + "\n";
    const e = r.explanation;
    let s = "";
    s += "Cause:       " + e.cause + " (confidence: " + e.confidence + ")\n";
    s += "Transform:   " + e.transform + "\n\n";
    s += "What happened:\n  " + e.explanation + "\n\n";
    s += "Fix:\n  " + e.fix + "\n\n";
    s += "Docs:        " + e.docsUrl + "\n";
    return s;
}

// Subcommand runners. Each resolves to the envelope; main() handles
// JSON/pretty + exit-code based on the envelope's `ok` field.

async function runUsage(opts) {
    return ai.usage({
        apiKey: opts.apiKey, apiPassword: opts.apiPassword,
        endpoint: opts.endpoint, timeoutMs: opts.timeoutMs,
    });
}

async function runPresetSuggest(opts, positional) {
    if (positional.length === 0) {
        throw Object.assign(new Error("preset-suggest: description is required"), { exitCode: 2 });
    }
    return ai.presetSuggest({
        apiKey: opts.apiKey, apiPassword: opts.apiPassword,
        endpoint: opts.endpoint, timeoutMs: opts.timeoutMs,
        description: positional.join(" "),
    });
}

async function runCompatCheck(opts, positional) {
    if (positional.length === 0) {
        throw Object.assign(new Error("compat-check: <file> is required"), { exitCode: 2 });
    }
    const file = positional[0];
    if (!fs.existsSync(file)) {
        throw Object.assign(new Error("compat-check: file not found: " + file), { exitCode: 2 });
    }
    const source = fs.readFileSync(file, "utf8");
    return ai.compatCheck({
        apiKey: opts.apiKey, apiPassword: opts.apiPassword,
        endpoint: opts.endpoint, timeoutMs: opts.timeoutMs,
        source: source,
        framework: opts.framework,
    });
}

// compat-scan: read jso.config.json, run ai.compatCheck on every input file,
// aggregate findings, exit non-zero per --fail-on. Designed as a CI gate to
// run before `jso-protector` so customers catch obfuscation pitfalls (eval,
// Function-constructor, this-binding tricks, framework reflection) before
// they ship a broken protected build.
async function runCompatScan(opts, _positional) {
    const configPath = path.resolve(opts.config || "jso.config.json");
    if (!fs.existsSync(configPath)) {
        throw Object.assign(new Error("compat-scan: config not found: " + configPath), { exitCode: 2 });
    }
    let config;
    try {
        config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    } catch (e) {
        throw Object.assign(new Error("compat-scan: invalid JSON in " + configPath + ": " + e.message), { exitCode: 2 });
    }

    // Resolve input files. Honor either `files: [...]` (explicit list) or
    // `input: <dir>` + `extensions: [".js"]` (directory walk). Exclusions
    // match by substring against the relative path.
    const baseDir = path.dirname(configPath);
    const exts = (config.extensions && config.extensions.length) ? config.extensions : [".js", ".mjs", ".cjs"];
    const excludes = config.exclude || [];
    function isExcluded(rel) {
        return excludes.some(p => rel.includes(p));
    }
    function walk(dir, out) {
        for (const name of fs.readdirSync(dir)) {
            const full = path.join(dir, name);
            const stat = fs.statSync(full);
            if (stat.isDirectory()) {
                if (name === "node_modules" || name === ".git") continue;
                walk(full, out);
            } else if (exts.some(e => name.endsWith(e))) {
                out.push(full);
            }
        }
    }

    let files = [];
    if (Array.isArray(config.files) && config.files.length) {
        files = config.files.map(f => path.resolve(baseDir, f));
    } else if (config.input) {
        const inDir = path.resolve(baseDir, config.input);
        if (!fs.existsSync(inDir)) {
            throw Object.assign(new Error("compat-scan: input dir not found: " + inDir), { exitCode: 2 });
        }
        walk(inDir, files);
    } else {
        throw Object.assign(new Error("compat-scan: jso.config must have `files` or `input`"), { exitCode: 2 });
    }

    files = files
        .map(f => ({ abs: f, rel: path.relative(baseDir, f) }))
        .filter(f => !isExcluded(f.rel));

    if (opts.maxFiles && files.length > opts.maxFiles) {
        files = files.slice(0, opts.maxFiles);
    }

    const framework = opts.framework || config.framework;
    const results = [];
    let totErr = 0, totWarn = 0, totInfo = 0;
    let firstErrorEnvelope = null;

    for (const f of files) {
        const source = fs.readFileSync(f.abs, "utf8");
        let env;
        try {
            env = await ai.compatCheck({
                apiKey: opts.apiKey, apiPassword: opts.apiPassword,
                endpoint: opts.endpoint, timeoutMs: opts.timeoutMs,
                source: source, framework: framework,
            });
        } catch (err) {
            // Network / HTTP / auth — abort the whole scan; one bad call
            // usually means all subsequent will fail too.
            if (!firstErrorEnvelope) firstErrorEnvelope = err;
            results.push({ file: f.rel, ok: false, error: err.code || "internal_error", message: err.message });
            break;
        }
        if (!env.ok) {
            results.push({ file: f.rel, ok: false, error: env.error, message: env.message });
            continue;
        }
        const sum = env.report.summary;
        totErr  += sum.errors   || 0;
        totWarn += sum.warnings || 0;
        totInfo += sum.infos    || 0;
        results.push({ file: f.rel, ok: true, summary: sum, findings: env.report.findings });
    }

    const failOn = (opts.failOn || "error").toLowerCase();
    let gateOk = true;
    if (failOn === "error"   && totErr  > 0) gateOk = false;
    if (failOn === "warning" && (totErr + totWarn) > 0) gateOk = false;
    // failOn === "never" → always ok

    return {
        ok: gateOk && !firstErrorEnvelope,
        summary: { files: files.length, errors: totErr, warnings: totWarn, infos: totInfo, failOn: failOn },
        results: results,
    };
}

function prettyCompatScan(r) {
    let s = "";
    s += "Scanned " + r.summary.files + " file(s):  "
       + r.summary.errors + " error(s)  "
       + r.summary.warnings + " warning(s)  "
       + r.summary.infos + " info(s)   (gate: fail-on=" + r.summary.failOn + ")\n\n";
    for (const res of r.results) {
        if (!res.ok) {
            s += "[ERR] " + res.file + ": [" + res.error + "] " + res.message + "\n";
            continue;
        }
        const sum = res.summary;
        if ((sum.errors + sum.warnings + sum.infos) === 0) {
            s += "[OK]  " + res.file + "\n";
            continue;
        }
        s += "[" + (sum.errors > 0 ? "FAIL" : "WARN") + "] " + res.file
           + "   (" + sum.errors + "e " + sum.warnings + "w " + sum.infos + "i)\n";
        for (const f of res.findings) {
            s += "   [" + f.severity.toUpperCase() + "] " + f.category
               + " at " + f.line + ":" + f.column + " — " + f.message + "\n";
            if (f.suggestedFix) s += "        fix: " + f.suggestedFix + "\n";
        }
    }
    s += "\nGate: " + (r.ok ? "PASS" : "FAIL") + "\n";
    return s;
}

async function runExplainError(opts, positional) {
    if (positional.length === 0) {
        throw Object.assign(new Error("explain-error: error message is required"), { exitCode: 2 });
    }
    return ai.explainError({
        apiKey: opts.apiKey, apiPassword: opts.apiPassword,
        endpoint: opts.endpoint, timeoutMs: opts.timeoutMs,
        error: positional.join(" "),
    });
}

const SUBCOMMANDS = {
    "usage":          { run: runUsage,          pretty: prettyUsage },
    "preset-suggest": { run: runPresetSuggest,  pretty: prettyPreset },
    "compat-check":   { run: runCompatCheck,    pretty: prettyCompat },
    "compat-scan":    { run: runCompatScan,     pretty: prettyCompatScan },
    "explain-error":  { run: runExplainError,   pretty: prettyExplain },
};

async function main(argv) {
    if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
        printHelp();
        return 0;
    }
    const sub = argv[0];
    const def = SUBCOMMANDS[sub];
    if (!def) {
        process.stderr.write("Unknown subcommand: " + sub + "\n\n");
        printHelp(process.stderr);
        return 2;
    }
    let parsed;
    try {
        parsed = parseFlags(argv.slice(1));
    } catch (err) {
        process.stderr.write(err.message + "\n");
        return err.exitCode || 2;
    }
    if (parsed.opts.help) {
        printHelp();
        return 0;
    }
    let envelope;
    try {
        envelope = await def.run(parsed.opts, parsed.positional);
    } catch (err) {
        // auth_missing / input_invalid / network errors / HTTP 4xx
        // (HTTP 4xx carries .status and .body).
        const out = { ok: false, error: err.code || "internal_error", message: err.message };
        if (err.status) out.httpStatus = err.status;
        if (err.body)   out.body       = err.body;
        if (parsed.opts.pretty) {
            process.stderr.write("[" + out.error + "] " + out.message + "\n");
        } else {
            process.stdout.write(JSON.stringify(out, null, 2) + "\n");
        }
        return err.exitCode || 1;
    }

    if (parsed.opts.pretty) {
        process.stdout.write(def.pretty(envelope));
    } else {
        jsonOut(envelope);
    }
    return envelope.ok ? 0 : 1;
}

module.exports = { main };
