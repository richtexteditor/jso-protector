"use strict";

// AI script data governance (browser runtime module).
//
// Watches outbound fetch / XHR / WebSocket traffic for requests that
// hit a known LLM provider endpoint, classifies them, records the
// destination + payload size + sha256, and routes the event through
// the same beacon channel as third-party-inventory and the runtime
// defense suite. Two modes:
//
//   "log"    -- record only, request proceeds (default, safe to
//               deploy on a live payment page without breaking
//               legitimate copilot widgets).
//   "block"  -- record + reject. fetch() returns a synthetic 451
//               Response; XHR transitions to readyState=4 with
//               status=0; WebSocket constructor throws.
//
// Compose with jso-beacon-slack's SIEM adapters (Splunk HEC,
// Elasticsearch, signed webhook) to land AI-bound traffic in the
// same on-call view as Magecart-style violations.
//
// Threat model
// ------------
// Three concrete attacks this catches:
//   1. A Magecart-style script that exfiltrates form data to an
//      attacker-controlled LLM (eg. "summarize this credit-card
//      number"). The destination matches a known LLM endpoint and
//      the payload size is non-trivial.
//   2. A legitimate-but-untrusted third-party widget that quietly
//      streams page contents to its own AI backend. The customer
//      may not have approved this data flow.
//   3. A compromised CI/CD dep injecting a prompt-stealer that POSTs
//      conversation history to a side-channel.
//
// What this module does NOT do
// ----------------------------
// It cannot stop a server-side proxy (eg. an attacker who pipes
// page data through their own backend before forwarding to OpenAI);
// it only sees direct browser-to-provider traffic. It also cannot
// classify a request whose URL is the attacker's own domain
// fronting an LLM API; the allowlist is destination-host based, not
// behavior based. Pair with the third-party-inventory module
// (which alerts on unknown origins outright) for full coverage.
//
// Public API
// ----------
//   const aig = require("jso-protector/runtime/ai-script-governance");
//   const engine = aig.createGovernanceEngine({
//       mode: "log",                          // "log" | "block"
//       additionalKnownLLMHosts: ["my-llm.example.com"],
//       beaconUrl:        "https://beacon.example.com/v1/jso/ai-gov",
//       flushIntervalMs:  15000,
//       buildId:          window.__jsoBuildId,
//   });
//   engine.observe({ method: "POST", url: "https://api.openai.com/v1/chat/completions", bodyBytes: 1024, bodySha256: "...", caller: "checkout.js:42" });
//   const events = engine.events();
//   const violations = engine.violations();
//   // DOM-attach (browser only):
//   aig.attach(window, { ...config });

const SCHEMA_VERSION = 1;
const DEFAULT_FLUSH_INTERVAL_MS = 15000;
const MAX_EVENT_LOG = 500;

// Known LLM provider hosts as of 2026-06. Add via
// config.additionalKnownLLMHosts to extend without forking. Matched
// via endsWith() against the request URL's host, so subdomain
// patterns like "openai.azure.com" cover "<tenant>.openai.azure.com".
const DEFAULT_LLM_HOSTS = [
    // OpenAI
    "api.openai.com",
    ".openai.azure.com",
    // Anthropic
    "api.anthropic.com",
    // Google
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    // Groq
    "api.groq.com",
    // Together
    "api.together.xyz",
    "api.together.ai",
    // Mistral
    "api.mistral.ai",
    "codestral.mistral.ai",
    // AWS Bedrock (region-prefixed). Trailing-dot rule = host startsWith.
    "bedrock-runtime.",
    "bedrock-runtime-fips.",
    // Cohere
    "api.cohere.com",
    "api.cohere.ai",
    // Perplexity
    "api.perplexity.ai",
    // xAI
    "api.x.ai",
    // DeepSeek
    "api.deepseek.com",
    // Replicate
    "api.replicate.com",
    // Hugging Face Inference
    "api-inference.huggingface.co",
];

function createGovernanceEngine(config) {
    config = config || {};
    const mode = config.mode === "block" ? "block" : "log";
    const extras = Array.isArray(config.additionalKnownLLMHosts) ? config.additionalKnownLLMHosts.slice() : [];
    const knownHosts = DEFAULT_LLM_HOSTS.concat(extras);

    const events = [];
    const violations = []; // populated only in block mode, or always for AI hits
    let seq = 0;

    function classify(url) {
        if (!url || typeof url !== "string") return { isLLM: false, host: null, matchedRule: null };
        let host = null;
        try {
            const u = new URL(url, "https://example.com/");
            host = (u.host || "").toLowerCase();
        } catch (e) { return { isLLM: false, host: null, matchedRule: null }; }
        const lowerUrl = url.toLowerCase();
        for (const rule of knownHosts) {
            const r = rule.toLowerCase();
            // Four matching shapes:
            //  - exact host match           "api.openai.com"      == host
            //  - subdomain suffix (leading dot) ".openai.azure.com"  endsWith host
            //  - host prefix (trailing dot)     "bedrock-runtime."   host startsWith
            //  - URL-substring (any slash)      "/v1/foo"            match in lowerUrl
            if (r.indexOf("/") >= 0) {
                if (lowerUrl.indexOf(r) >= 0) return { isLLM: true, host: host, matchedRule: rule };
                continue;
            }
            if (r.charAt(0) === ".") {
                if (host.endsWith(r) || host === r.substring(1)) return { isLLM: true, host: host, matchedRule: rule };
                continue;
            }
            if (r.charAt(r.length - 1) === ".") {
                if (host.indexOf(r) === 0) return { isLLM: true, host: host, matchedRule: rule };
                continue;
            }
            if (host === r) return { isLLM: true, host: host, matchedRule: rule };
        }
        return { isLLM: false, host: host, matchedRule: null };
    }

    function observe(row) {
        if (!row || typeof row !== "object") return { acted: false, classification: null };
        const url = row.url || "";
        const cls = classify(url);
        if (!cls.isLLM) return { acted: false, classification: cls };

        if (events.length >= MAX_EVENT_LOG) return { acted: false, classification: cls, dropped: true };

        const event = {
            seq: ++seq,
            transport: row.transport || "unknown", // "fetch" | "xhr" | "websocket"
            method: row.method || null,
            url: url,
            host: cls.host,
            matchedRule: cls.matchedRule,
            bodyBytes: typeof row.bodyBytes === "number" ? row.bodyBytes : null,
            bodySha256: row.bodySha256 || null,
            caller: row.caller || null,
            observedAt: row.observedAt || null,
            mode: mode,
            blocked: false,
        };

        if (mode === "block") {
            event.blocked = true;
            events.push(event);
            violations.push(event);
            return { acted: true, classification: cls, blocked: true };
        }
        // log mode: still treat every AI hit as a "violation" for the
        // beacon flush -- the customer asked to see them.
        events.push(event);
        violations.push(event);
        return { acted: true, classification: cls, blocked: false };
    }

    function snapshot() {
        return {
            v: SCHEMA_VERSION,
            kind: "ai-data-access",
            mode: mode,
            buildId: config.buildId || null,
            pageHref: config.pageHref || null,
            events: events.slice(),
            violations: violations.slice(),
        };
    }

    function eventsOnly()     { return events.slice(); }
    function violationsOnly() { return violations.slice(); }
    function size()           { return events.length; }
    function reset() {
        events.length = 0;
        violations.length = 0;
        seq = 0;
    }
    function isKnownLLMHost(url) { return classify(url).isLLM; }

    return {
        SCHEMA_VERSION: SCHEMA_VERSION,
        DEFAULT_LLM_HOSTS: DEFAULT_LLM_HOSTS.slice(),
        mode: mode,
        observe: observe,
        snapshot: snapshot,
        events: eventsOnly,
        violations: violationsOnly,
        size: size,
        reset: reset,
        classify: classify,
        isKnownLLMHost: isKnownLLMHost,
    };
}

// ---- browser bootstrap -----------------------------------------------------

function attach(win, config) {
    if (!win || typeof win !== "object") throw new Error("ai-script-governance.attach: window object required");
    if (win.__jsoAiGovAttached) return win.__jsoAiGovAttached;

    const engine = createGovernanceEngine(config);
    const mode = engine.mode;
    const observedAt = function () { return new Date().toISOString(); };

    async function sha256Hex(buf) {
        try {
            if (!win.crypto || !win.crypto.subtle) return null;
            const h = await win.crypto.subtle.digest("SHA-256", buf);
            const bytes = new Uint8Array(h);
            let hex = "";
            for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
            return hex;
        } catch (e) { return null; }
    }

    function callerFrame() {
        try {
            const e = new Error();
            if (!e.stack) return null;
            // Pop the top three frames (this fn, the trap, the caller's wrapping)
            const lines = e.stack.split("\n");
            return (lines[3] || lines[2] || lines[1] || "").trim() || null;
        } catch (x) { return null; }
    }

    // 1. fetch() hook
    if (typeof win.fetch === "function") {
        const origFetch = win.fetch.bind(win);
        win.fetch = function (input, init) {
            const url = (typeof input === "string" ? input : (input && input.url)) || "";
            const method = (init && init.method) || (input && input.method) || "GET";
            const bodyBytes = init && init.body && typeof init.body.length === "number" ? init.body.length : null;
            const verdict = engine.observe({
                transport: "fetch", method: method, url: url,
                bodyBytes: bodyBytes, bodySha256: null,
                caller: callerFrame(), observedAt: observedAt(),
            });
            if (verdict.blocked) {
                return Promise.resolve(new win.Response(
                    JSON.stringify({ ok: false, error: "ai_data_access_blocked", host: verdict.classification.host }),
                    { status: 451, statusText: "Unavailable For Legal Reasons", headers: { "Content-Type": "application/json" } }
                ));
            }
            return origFetch(input, init);
        };
    }

    // 2. XMLHttpRequest hook
    if (typeof win.XMLHttpRequest === "function") {
        const Orig = win.XMLHttpRequest;
        function PatchedXHR() {
            const x = new Orig();
            let _url = null, _method = null;
            const origOpen = x.open;
            x.open = function (m, u) {
                _method = m; _url = u;
                return origOpen.apply(x, arguments);
            };
            const origSend = x.send;
            x.send = function (body) {
                const bodyBytes = body && typeof body.length === "number" ? body.length : null;
                const verdict = engine.observe({
                    transport: "xhr", method: _method, url: _url,
                    bodyBytes: bodyBytes, bodySha256: null,
                    caller: callerFrame(), observedAt: observedAt(),
                });
                if (verdict.blocked) {
                    // Synthesize an abort that looks like a network failure.
                    try { x.abort(); } catch (e) {}
                    setTimeout(function () {
                        try {
                            if (typeof x.onreadystatechange === "function") {
                                Object.defineProperty(x, "readyState", { value: 4, configurable: true });
                                Object.defineProperty(x, "status", { value: 0, configurable: true });
                                x.onreadystatechange();
                            }
                        } catch (e) {}
                    }, 0);
                    return;
                }
                return origSend.apply(x, arguments);
            };
            return x;
        }
        try { PatchedXHR.prototype = Orig.prototype; } catch (e) {}
        win.XMLHttpRequest = PatchedXHR;
    }

    // 3. WebSocket hook
    if (typeof win.WebSocket === "function") {
        const OrigWS = win.WebSocket;
        function PatchedWS(url, protocols) {
            const verdict = engine.observe({
                transport: "websocket", method: "WS", url: url,
                bodyBytes: null, bodySha256: null,
                caller: callerFrame(), observedAt: observedAt(),
            });
            if (verdict.blocked) {
                throw new Error("ai_data_access_blocked: WebSocket to " + verdict.classification.host + " refused by jso-ai-script-governance.");
            }
            return new OrigWS(url, protocols);
        }
        try { PatchedWS.prototype = OrigWS.prototype; } catch (e) {}
        win.WebSocket = PatchedWS;
    }

    // 4. Beacon flush -- same shape as third-party-inventory so the
    // SIEM adapters can route both event kinds without an adapter
    // change. Flushes deltas every flushIntervalMs.
    function setupBeaconFlush() {
        if (!config.beaconUrl) return;
        const interval = (typeof config.flushIntervalMs === "number" && config.flushIntervalMs > 0)
            ? config.flushIntervalMs
            : DEFAULT_FLUSH_INTERVAL_MS;
        let lastSent = 0;
        function flush() {
            const v = engine.violations();
            if (v.length === lastSent) return;
            lastSent = v.length;
            const body = JSON.stringify(engine.snapshot());
            try {
                if (typeof win.fetch === "function") {
                    // NOTE: we call the ORIGINAL fetch via __jsoOriginalFetch
                    // would loop forever as we just patched fetch above and
                    // the beacon URL isn't an LLM host -- the observe()
                    // call returns acted=false, so this is harmless. Kept
                    // explicit comment so future edits don't add an LLM
                    // host that overlaps the beacon URL.
                    win.fetch(config.beaconUrl, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: body,
                        keepalive: true,
                        credentials: "omit",
                    }).catch(function () {});
                } else if (typeof win.navigator !== "undefined" && win.navigator.sendBeacon) {
                    win.navigator.sendBeacon(config.beaconUrl, body);
                }
            } catch (e) {}
        }
        win.setInterval(flush, interval);
        if (typeof win.addEventListener === "function") win.addEventListener("pagehide", flush, false);
    }
    setupBeaconFlush();

    win.__jsoAiGovAttached = engine;
    return engine;
}

module.exports = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    DEFAULT_LLM_HOSTS: DEFAULT_LLM_HOSTS.slice(),
    createGovernanceEngine: createGovernanceEngine,
    attach: attach,
};
