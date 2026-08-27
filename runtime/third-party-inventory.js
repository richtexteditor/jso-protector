"use strict";

// Third-party script inventory + Magecart detection (browser runtime module).
//
// Pure browser code — no Node APIs. Add to a protected output to:
//
//   1. snapshot every <script> element present at DOMContentLoaded;
//   2. intercept document.createElement("script") so DOM-injected
//      scripts are recorded the moment they're created (even if the
//      attacker tries to remove them before they execute);
//   3. observe PerformanceObserver "resource" entries for any script
//      load that bypassed createElement (e.g. <iframe>-injected,
//      worker importScripts, ServiceWorker fetches);
//   4. compare each observed script against an allowlist of script
//      origins + inline content hashes. Anything outside the allowlist
//      is a "violation" and gets POSTed to the beacon URL together
//      with the full inventory snapshot.
//
// Threat model
// ------------
// Targets the Magecart family of card-skimming attacks: an adversary
// who has gained access to one third-party dependency (CDN, tag
// manager, marketing script) and is injecting a payment-skimming
// snippet into the page. The defender has the JSO-protected core
// application; this module's job is to catch the *uninvited guest*
// (a script the build pipeline didn't sign off on) and raise an
// alarm BEFORE the user types card data.
//
// Detection signals
// -----------------
//   - script `src` not in the configured `originAllowlist`;
//   - inline `<script>` whose sha256 is not in `inlineContentAllowlist`;
//   - script DOM-injected AFTER document.readyState === "complete"
//     (deferred-injection is a common Magecart evasion pattern);
//   - same script URL but the content sha256 changed between page loads
//     (catches "supply-chain swap" attacks where the URL is in the
//     allowlist but the upstream CDN has been compromised).
//
// What this module does NOT do
// ----------------------------
// It does not BLOCK malicious scripts. By the time we observe a
// violation the script may already be in the DOM. The module exists
// to *evidence* the attack to your on-call rotation; pair it with
// Content-Security-Policy + Subresource-Integrity for in-line
// blocking. Use jso-beacon-slack to pipe the violation events to
// Slack / Splunk / Elasticsearch.
//
// Public API (Node + browser)
// ---------------------------
//   const tpi = require("jso-protector/runtime/third-party-inventory");
//   const engine = tpi.createInventoryEngine({
//       originAllowlist:        ["https://www.example.com", "https://cdn.example.com"],
//       inlineContentAllowlist: ["a3f5...", "b07e..."],         // sha256 hex
//       beaconUrl:              "https://beacon.example.com/v1/jso/inventory",
//       beaconSecret:           "<HMAC-SHA256 key>",            // optional
//       flushIntervalMs:        15000,                          // 15s
//   });
//   // pure-data path (testable):
//   engine.recordScript({ src: "...", inline: null, sha256: "..." });
//   engine.recordScript({ src: null, inline: "alert(1)", sha256: "..." });
//   const snapshot = engine.snapshot();
//   const violations = engine.violations();
//
//   // DOM-attached path (browser only):
//   tpi.attach(window, { ...config });
//
// Wire format of beacon POST
// --------------------------
// Same envelope shape as the rest of the runtime-defense beacon so
// jso-beacon-slack can forward it without an adapter change:
//
//   {
//     v: 1,
//     kind: "inventory",
//     buildId: "<from window.__jsoBuildId>",
//     pageHref: "https://...",
//     observedAt: "2026-06-02T13:14:15Z",
//     scripts: [
//       {
//         src, sha256, inline:bool, injectedAfterLoad:bool, allowlisted:bool,
//         checkoutSurface, frameContext, frameOwner, parentPageHref, frameHref, frameOrigin
//       },
//       ...
//     ],
//     violations: [ { reason, ...row } ],
//   }

const SCHEMA_VERSION = 1;
const DEFAULT_FLUSH_INTERVAL_MS = 15000;
const MAX_INVENTORY_SIZE = 500;

// ---- pure engine (Node-testable) ------------------------------------------

function createInventoryEngine(config) {
    config = config || {};
    const originAllowlist = Array.isArray(config.originAllowlist) ? config.originAllowlist.slice() : [];
    const inlineContentAllowlist = new Set(Array.isArray(config.inlineContentAllowlist) ? config.inlineContentAllowlist : []);
    const previousContentBySrc = (config.previousContentBySrc && typeof config.previousContentBySrc === "object")
        ? config.previousContentBySrc
        : {};

    const scripts = [];   // [{ src, sha256, inline, injectedAfterLoad, allowlisted, observedAt, surface metadata }]
    const violations = []; // [{ reason, ...script }]
    const seenKeys = new Set(); // dedup by (src || "inline:" + sha256)

    function originOf(url) {
        try {
            const u = new URL(url, "https://example.com/");
            return u.origin;
        } catch (e) {
            return null;
        }
    }

    function isOriginAllowlisted(src) {
        if (!src) return true; // inline; allowlist by content not origin
        const origin = originOf(src);
        if (!origin) return false;
        for (const allowed of originAllowlist) {
            if (allowed === origin) return true;
            if (allowed === "*") return true;
            // Trailing-slash tolerance: "https://x.com/" matches "https://x.com"
            if (allowed.replace(/\/+$/, "") === origin) return true;
        }
        return false;
    }

    function recordScript(row) {
        if (!row || typeof row !== "object") return { recorded: false, allowed: false, violations: [] };
        const src = row.src || null;
        const sha256 = row.sha256 || null;
        const inline = !src;
        const injectedAfterLoad = !!row.injectedAfterLoad;

        const key = src || ("inline:" + (sha256 || "no-hash"));
        if (seenKeys.has(key)) return { recorded: false, allowed: true, violations: [] };
        // Back-pressure: check the cap BEFORE adding to seenKeys.
        // Previously seenKeys grew unbounded even when scripts was
        // capped, leaving long-lived pages vulnerable to a memory DoS
        // via a spray of unique attacker-controlled src URLs.
        if (scripts.length >= MAX_INVENTORY_SIZE) return { recorded: false, allowed: false, violations: [{ reason: "inventory-cap-exceeded" }] };
        seenKeys.add(key);
        const violationStart = violations.length;

        const allowlisted = inline
            ? (sha256 ? inlineContentAllowlist.has(sha256) : false)
            : isOriginAllowlisted(src);

        const out = {
            src: src,
            sha256: sha256,
            inline: inline,
            injectedAfterLoad: injectedAfterLoad,
            allowlisted: allowlisted,
            observedAt: row.observedAt || null,
            checkoutSurface: surfaceValue(row.checkoutSurface || row.paymentSurface || config.checkoutSurface || config.paymentSurface),
            frameContext: surfaceValue(row.frameContext || config.frameContext),
            frameOwner: surfaceValue(row.frameOwner || config.frameOwner),
            parentPageHref: surfaceValue(row.parentPageHref || config.parentPageHref),
            frameHref: surfaceValue(row.frameHref || config.frameHref),
            frameOrigin: surfaceValue(row.frameOrigin || config.frameOrigin),
        };
        scripts.push(out);

        // Violation rules
        if (!allowlisted) {
            violations.push(Object.assign({ reason: inline ? "unknown-inline-content" : "unknown-origin" }, out));
        }
        if (injectedAfterLoad && !inline && config.blockLateInjection !== false) {
            violations.push(Object.assign({ reason: "injected-after-load" }, out));
        }
        // Use hasOwnProperty.call to defeat prototype-chain lookups.
        // An attacker with control over a script src (e.g.
        // <script src="toString">) used to trigger a false
        // content-changed-vs-previous-deploy alarm because
        // `previousContentBySrc["toString"]` resolves to the inherited
        // Object.prototype.toString method.
        if (src && sha256) {
            const prev = Object.prototype.hasOwnProperty.call(previousContentBySrc, src)
                ? previousContentBySrc[src]
                : null;
            if (prev && prev !== sha256) {
                violations.push(Object.assign(
                    { reason: "content-changed-vs-previous-deploy", previousSha256: prev },
                    out
                ));
            }
        }
        const newViolations = violations.slice(violationStart);
        return { recorded: true, allowed: newViolations.length === 0, script: out, violations: newViolations };
    }

    function surfaceValue(value) {
        if (value == null) return null;
        const text = String(value).trim();
        return text || null;
    }

    function snapshot() {
        return {
            v: SCHEMA_VERSION,
            kind: "inventory",
            buildId: config.buildId || null,
            pageHref: config.pageHref || null,
            scripts: scripts.slice(),
            violations: violations.slice(),
        };
    }

    function violationsOnly() {
        return violations.slice();
    }

    function size() {
        return scripts.length;
    }

    function reset() {
        scripts.length = 0;
        violations.length = 0;
        seenKeys.clear();
    }

    return {
        SCHEMA_VERSION: SCHEMA_VERSION,
        recordScript: recordScript,
        snapshot: snapshot,
        violations: violationsOnly,
        size: size,
        reset: reset,
        _seenKeysForTest: function () { return new Set(seenKeys); },
    };
}

// ---- browser bootstrap -----------------------------------------------------
//
// attach(window, config) wires DOM listeners + PerformanceObserver onto
// the engine. Safe to call before or after DOMContentLoaded. No-op if
// the global window already has `__jsoTpiAttached === true` (idempotent).

function attach(win, config) {
    if (!win || typeof win !== "object") {
        throw new Error("third-party-inventory.attach: window object required");
    }
    if (win.__jsoTpiAttached) return win.__jsoTpiAttached;

    const engine = createInventoryEngine(config);
    const doc = win.document;
    const observedAt = function () {
        return new Date().toISOString();
    };

    async function sha256Hex(text) {
        if (!win.crypto || !win.crypto.subtle) return null;
        const enc = new win.TextEncoder().encode(text);
        const buf = await win.crypto.subtle.digest("SHA-256", enc);
        const bytes = new Uint8Array(buf);
        let hex = "";
        for (let i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, "0");
        }
        return hex;
    }

    // 1. Snapshot existing <script> elements.
    function snapshotExisting() {
        if (!doc || !doc.querySelectorAll) return;
        const nodes = doc.querySelectorAll("script");
        const promises = [];
        for (let i = 0; i < nodes.length; i++) {
            const s = nodes[i];
            if (s.src) {
                engine.recordScript({ src: s.src, sha256: null, observedAt: observedAt() });
            } else if (s.textContent) {
                const t = s.textContent;
                promises.push(sha256Hex(t).then(function (hex) {
                    engine.recordScript({ src: null, sha256: hex, inline: true, observedAt: observedAt() });
                }));
            }
        }
        return Promise.all(promises);
    }

    // 2. Intercept document.createElement("script").
    function interceptCreate() {
        if (!doc || !doc.createElement) return;
        const orig = doc.createElement.bind(doc);
        doc.createElement = function (tag) {
            const el = orig.apply(this, arguments);
            if (typeof tag === "string" && tag.toLowerCase() === "script") {
                // Defer reading src until the consumer sets it.
                let _src = "";
                let _text = "";
                const srcDescriptor = Object.getOwnPropertyDescriptor(el, "src") || { set: undefined, get: undefined };
                try {
                    Object.defineProperty(el, "src", {
                        configurable: true,
                        enumerable: true,
                        get: function () { return _src; },
                        set: function (v) {
                            _src = String(v);
                            const decision = engine.recordScript({
                                src: _src,
                                sha256: null,
                                injectedAfterLoad: (doc.readyState === "complete"),
                                observedAt: observedAt(),
                            });
                            if (config.enforcementMode === "block" && decision && !decision.allowed) {
                                try { el.type = "application/x-jso-blocked"; el.setAttribute("data-jso-blocked-src", _src); } catch (e) {}
                                if (typeof config.onBlocked === "function") { try { config.onBlocked(decision); } catch (e) {} }
                                try {
                                    if (typeof win.dispatchEvent === "function" && typeof win.CustomEvent === "function") {
                                        win.dispatchEvent(new win.CustomEvent("jso:script-blocked", { detail: decision }));
                                    }
                                } catch (e) {}
                                return;
                            }
                            if (srcDescriptor && srcDescriptor.set) srcDescriptor.set.call(el, v);
                            else el.setAttribute("src", v);
                        },
                    });
                } catch (e) { /* swallow; some hosts freeze prototypes */ }
                // Also catch inline body via textContent setter
                try {
                    const textDescriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "textContent") || {};
                    Object.defineProperty(el, "textContent", {
                        configurable: true,
                        enumerable: true,
                        get: function () { return _text; },
                        set: function (v) {
                            _text = String(v);
                            sha256Hex(_text).then(function (hex) {
                                engine.recordScript({
                                    src: null,
                                    sha256: hex,
                                    inline: true,
                                    injectedAfterLoad: (doc.readyState === "complete"),
                                    observedAt: observedAt(),
                                });
                            }).catch(function () { /* swallow */ });
                            if (textDescriptor && textDescriptor.set) textDescriptor.set.call(el, v);
                        },
                    });
                } catch (e) { /* swallow */ }
            }
            return el;
        };
    }

    // 3. PerformanceObserver fallback for script loads that bypassed createElement.
    function observeResources() {
        if (typeof win.PerformanceObserver !== "function") return;
        try {
            const po = new win.PerformanceObserver(function (list) {
                for (const entry of list.getEntries()) {
                    if (entry.initiatorType !== "script") continue;
                    engine.recordScript({
                        src: entry.name,
                        sha256: null,
                        injectedAfterLoad: (doc.readyState === "complete"),
                        observedAt: observedAt(),
                    });
                }
            });
            po.observe({ entryTypes: ["resource"] });
        } catch (e) { /* swallow */ }
    }

    // 4. Periodically flush violations to the beacon URL.
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
                    win.fetch(config.beaconUrl, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: body,
                        keepalive: true,
                        credentials: "omit",
                    }).catch(function () { /* swallow */ });
                } else if (typeof win.navigator !== "undefined" && win.navigator.sendBeacon) {
                    win.navigator.sendBeacon(config.beaconUrl, body);
                }
            } catch (e) { /* swallow */ }
        }
        win.setInterval(flush, interval);
        // Flush on pagehide for last-second violations.
        if (typeof win.addEventListener === "function") {
            win.addEventListener("pagehide", flush, false);
        }
    }

    interceptCreate();
    observeResources();
    setupBeaconFlush();
    // Run snapshot async to avoid blocking the page load.
    Promise.resolve().then(snapshotExisting).catch(function () { /* swallow */ });

    win.__jsoTpiAttached = engine;
    return engine;
}

async function attachFromPolicy(win, config) {
    config = config || {};
    if (!win || typeof win.fetch !== "function") throw new Error("third-party-inventory.attachFromPolicy: fetch-capable window required");
    if (!config.policyUrl) throw new Error("third-party-inventory.attachFromPolicy: policyUrl is required");
    const response = await win.fetch(config.policyUrl, { method: "GET", credentials: "omit", cache: "no-cache" });
    if (!response || response.ok === false || typeof response.json !== "function") throw new Error("third-party-inventory.attachFromPolicy: policy request failed");
    const policy = await response.json();
    if (!policy || policy.kind !== "managed-integrity-policy" || !policy.id || !policy.version) throw new Error("third-party-inventory.attachFromPolicy: invalid managed policy");
    const merged = Object.assign({}, config, {
        originAllowlist: Array.isArray(policy.allowedOrigins) ? policy.allowedOrigins : [],
        inlineContentAllowlist: Array.isArray(policy.allowedInlineHashes) ? policy.allowedInlineHashes : [],
        enforcementMode: policy.mode === "block" ? "block" : "monitor",
        blockLateInjection: policy.blockLateInjection !== false,
        policyId: policy.id,
        policyVersion: policy.version,
    });
    delete merged.policyUrl;
    return attach(win, merged);
}

module.exports = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    createInventoryEngine: createInventoryEngine,
    attach: attach,
    attachFromPolicy: attachFromPolicy,
};
