"use strict";

// Tests for the third-party-inventory runtime module. The pure engine
// is Node-testable without any DOM; the DOM-attach path is covered by
// a thin window stub that records the calls our code makes onto it.

const test = require("node:test");
const assert = require("node:assert");
const tpi = require("../runtime/third-party-inventory.js");

test("engine: clean inventory passes when every script is allowlisted", function () {
    const e = tpi.createInventoryEngine({
        originAllowlist: ["https://cdn.example.com", "https://www.example.com"],
        inlineContentAllowlist: ["abc123"],
        buildId: "build-1",
        pageHref: "https://www.example.com/checkout",
    });
    e.recordScript({ src: "https://cdn.example.com/app.js", sha256: "h1" });
    e.recordScript({ src: "https://www.example.com/init.js", sha256: "h2" });
    e.recordScript({ inline: true, sha256: "abc123" });
    const snap = e.snapshot();
    assert.equal(snap.scripts.length, 3);
    assert.equal(snap.violations.length, 0);
    assert.equal(snap.kind, "inventory");
    assert.equal(snap.buildId, "build-1");
    assert.ok(snap.scripts.every(function (s) { return s.allowlisted; }));
});

test("engine: preserves optional checkout iframe context", function () {
    const e = tpi.createInventoryEngine({
        originAllowlist: ["https://js.stripe.com"],
        buildId: "build-frame-1",
        pageHref: "https://shop.example/checkout",
        checkoutSurface: "hosted-checkout",
        frameContext: "psp-iframe",
        frameOwner: "Payments",
        parentPageHref: "https://shop.example/checkout",
        frameHref: "https://checkout.stripe.example/frame",
        frameOrigin: "https://checkout.stripe.example",
    });
    e.recordScript({ src: "https://js.stripe.com/v3/", sha256: "h-frame" });
    const row = e.snapshot().scripts[0];
    assert.equal(row.checkoutSurface, "hosted-checkout");
    assert.equal(row.frameContext, "psp-iframe");
    assert.equal(row.frameOwner, "Payments");
    assert.equal(row.parentPageHref, "https://shop.example/checkout");
    assert.equal(row.frameHref, "https://checkout.stripe.example/frame");
    assert.equal(row.frameOrigin, "https://checkout.stripe.example");
});

test("engine: unknown origin generates an 'unknown-origin' violation", function () {
    const e = tpi.createInventoryEngine({
        originAllowlist: ["https://cdn.example.com"],
    });
    e.recordScript({ src: "https://evil.com/skimmer.js", sha256: "x" });
    const v = e.violations();
    assert.equal(v.length, 1);
    assert.equal(v[0].reason, "unknown-origin");
    assert.equal(v[0].src, "https://evil.com/skimmer.js");
    assert.equal(v[0].allowlisted, false);
});

test("engine: record decision exposes whether policy enforcement may continue", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["https://safe.example"] });
    assert.equal(e.recordScript({ src: "https://safe.example/app.js" }).allowed, true);
    const blocked = e.recordScript({ src: "https://evil.example/skimmer.js" });
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.violations[0].reason, "unknown-origin");
});

test("engine: unknown inline content => 'unknown-inline-content' violation", function () {
    const e = tpi.createInventoryEngine({
        inlineContentAllowlist: ["expected-hash"],
    });
    e.recordScript({ inline: true, sha256: "surprise-hash" });
    const v = e.violations();
    assert.equal(v.length, 1);
    assert.equal(v[0].reason, "unknown-inline-content");
    assert.equal(v[0].inline, true);
});

test("engine: post-load DOM injection (even from allowed origin) flags 'injected-after-load'", function () {
    const e = tpi.createInventoryEngine({
        originAllowlist: ["https://cdn.example.com"],
    });
    e.recordScript({ src: "https://cdn.example.com/late.js", injectedAfterLoad: true });
    const v = e.violations();
    assert.equal(v.length, 1);
    assert.equal(v[0].reason, "injected-after-load");
});

test("engine: same src with new sha256 vs previous deploy => 'content-changed-vs-previous-deploy'", function () {
    const e = tpi.createInventoryEngine({
        originAllowlist: ["https://cdn.example.com"],
        previousContentBySrc: { "https://cdn.example.com/lib.js": "old-hash" },
    });
    e.recordScript({ src: "https://cdn.example.com/lib.js", sha256: "new-hash" });
    const v = e.violations();
    const c = v.find(function (x) { return x.reason === "content-changed-vs-previous-deploy"; });
    assert.ok(c, "should flag content swap");
    assert.equal(c.previousSha256, "old-hash");
    assert.equal(c.sha256, "new-hash");
});

test("engine: dedups identical script entries (same src) without double-counting violations", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["https://x.com"] });
    e.recordScript({ src: "https://evil.com/a.js" });
    e.recordScript({ src: "https://evil.com/a.js" });
    e.recordScript({ src: "https://evil.com/a.js" });
    assert.equal(e.size(), 1, "snapshot has one entry");
    assert.equal(e.violations().length, 1, "violations dedup too");
});

test("engine: dedups identical inline scripts by sha256", function () {
    const e = tpi.createInventoryEngine({ inlineContentAllowlist: [] });
    e.recordScript({ inline: true, sha256: "h1" });
    e.recordScript({ inline: true, sha256: "h1" });
    assert.equal(e.size(), 1);
});

test("engine: malformed URLs are treated as not-allowlisted", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["https://x.com"] });
    e.recordScript({ src: "not a url" });
    const v = e.violations();
    assert.equal(v.length, 1);
    assert.equal(v[0].reason, "unknown-origin");
});

test("engine: '*' wildcard origin allowlist allows everything (smoke escape)", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["*"] });
    e.recordScript({ src: "https://anything.example/x.js" });
    e.recordScript({ src: "https://other.example/y.js" });
    assert.equal(e.violations().length, 0);
});

test("engine: trailing-slash tolerance in allowlist", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["https://cdn.example.com/"] });
    e.recordScript({ src: "https://cdn.example.com/app.js" });
    assert.equal(e.violations().length, 0);
});

test("engine: backpressure caps inventory at MAX_INVENTORY_SIZE", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["https://x.com"] });
    // 600 distinct scripts; module caps at 500.
    for (let i = 0; i < 600; i++) {
        e.recordScript({ src: "https://x.com/s" + i + ".js" });
    }
    assert.ok(e.size() <= 500, "inventory size " + e.size() + " should be capped at 500");
});

test("engine: reset() clears state", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["https://x.com"] });
    e.recordScript({ src: "https://evil.com/a.js" });
    assert.equal(e.violations().length, 1);
    e.reset();
    assert.equal(e.violations().length, 0);
    assert.equal(e.size(), 0);
});

test("engine: snapshot is structurally stable across calls", function () {
    const e = tpi.createInventoryEngine({ originAllowlist: ["*"] });
    e.recordScript({ src: "https://a.com/x.js" });
    const a = e.snapshot();
    const b = e.snapshot();
    assert.equal(a.v, tpi.SCHEMA_VERSION);
    assert.equal(b.v, tpi.SCHEMA_VERSION);
    // Slices = independent arrays, so mutating one shouldn't affect the other.
    a.scripts.push({ src: "intruder" });
    assert.equal(b.scripts.length, 1);
});

test("attach: idempotent (second attach returns same engine)", function () {
    const fakeWin = makeWindowStub();
    const e1 = tpi.attach(fakeWin, { originAllowlist: ["*"] });
    const e2 = tpi.attach(fakeWin, { originAllowlist: ["never-matched"] });
    assert.strictEqual(e1, e2, "second attach must be a no-op and return the same engine");
});

test("attach: throws when window is missing", function () {
    assert.throws(function () { tpi.attach(null, {}); }, /window object required/);
});

test("attach: createElement('script') intercept records src + 'injected-after-load' when document is complete", function () {
    const fakeWin = makeWindowStub();
    fakeWin.document.readyState = "complete";
    const engine = tpi.attach(fakeWin, { originAllowlist: ["https://safe.com"] });
    const s = fakeWin.document.createElement("script");
    s.src = "https://evil.com/skimmer.js";
    // Wait a tick for the property setter to fire any async hashing.
    const v = engine.violations();
    // The recorded violation could be both 'unknown-origin' and 'injected-after-load'.
    const reasons = v.map(function (x) { return x.reason; });
    assert.ok(reasons.includes("unknown-origin"), "should flag unknown-origin; got " + JSON.stringify(reasons));
    assert.ok(reasons.includes("injected-after-load"), "should flag injected-after-load; got " + JSON.stringify(reasons));
});

test("attach: block enforcement neutralizes unknown dynamically-created scripts", function () {
    const fakeWin = makeWindowStub();
    let blocked = null;
    tpi.attach(fakeWin, { originAllowlist: ["https://safe.com"], enforcementMode: "block", onBlocked: function (decision) { blocked = decision; } });
    const script = fakeWin.document.createElement("script");
    script.src = "https://evil.example/skimmer.js";
    assert.equal(script.type, "application/x-jso-blocked");
    assert.equal(script.getAttribute("src"), null);
    assert.equal(script.getAttribute("data-jso-blocked-src"), "https://evil.example/skimmer.js");
    assert.equal(blocked.allowed, false);
});

test("attachFromPolicy fetches hosted policy and enables block enforcement", async function () {
    const fakeWin = makeWindowStub();
    fakeWin.fetch = async function () { return { ok: true, json: async function () { return { kind: "managed-integrity-policy", id: "checkout", version: "2", mode: "block", allowedOrigins: ["https://safe.example"], allowedInlineHashes: [] }; } }; };
    await tpi.attachFromPolicy(fakeWin, { policyUrl: "/v1/runtime/integrity-policy.ashx?id=checkout" });
    const script = fakeWin.document.createElement("script"); script.src = "https://evil.example/a.js";
    assert.equal(script.type, "application/x-jso-blocked");
});

// ---- helpers ---------------------------------------------------------------

function makeWindowStub() {
    // Minimal stand-in for `window` covering only what the module reads.
    // Keeps tests Node-native (no jsdom / happy-dom dependency).
    const win = {};
    const intervals = [];
    win.setInterval = function (fn, ms) { intervals.push({ fn: fn, ms: ms }); return intervals.length; };
    win.addEventListener = function () {};
    win.fetch = function () { return Promise.resolve({ ok: true }); };
    win.navigator = { sendBeacon: function () { return true; } };
    win.PerformanceObserver = function (cb) {
        this.observe = function () {};
        return this;
    };
    win.TextEncoder = function () {
        this.encode = function (s) { return Buffer.from(String(s), "utf8"); };
    };
    win.crypto = {
        subtle: {
            digest: async function (algo, buf) {
                const crypto = require("node:crypto");
                const hash = crypto.createHash("sha256").update(Buffer.from(buf)).digest();
                // Match SubtleCrypto: return an ArrayBuffer.
                const ab = new ArrayBuffer(hash.length);
                new Uint8Array(ab).set(hash);
                return ab;
            },
        },
    };
    // Document stub
    const proto = {};
    Object.defineProperty(proto, "textContent", {
        configurable: true,
        get: function () { return this._tc || ""; },
        set: function (v) { this._tc = String(v); },
    });
    win.document = {
        readyState: "loading",
        querySelectorAll: function () { return []; },
        createElement: function (tag) {
            const el = Object.create(proto);
            el.tagName = String(tag).toUpperCase();
            // Write attributes to a private slot so the runtime module's
            // defineProperty('src', ...) overrides don't recurse through
            // setAttribute back to the property setter.
            el._attrs = {};
            el.setAttribute = function (k, v) { el._attrs[k] = String(v); };
            el.getAttribute = function (k) { return el._attrs[k] || null; };
            return el;
        },
    };
    return win;
}
