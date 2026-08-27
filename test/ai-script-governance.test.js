"use strict";

const test = require("node:test");
const assert = require("node:assert");
const aig = require("../runtime/ai-script-governance.js");

test("engine: classify recognises canonical LLM hosts", function () {
    const e = aig.createGovernanceEngine();
    assert.equal(e.isKnownLLMHost("https://api.openai.com/v1/chat/completions"), true);
    assert.equal(e.isKnownLLMHost("https://api.anthropic.com/v1/messages"), true);
    assert.equal(e.isKnownLLMHost("https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"), true);
    assert.equal(e.isKnownLLMHost("https://api.mistral.ai/v1/chat/completions"), true);
});

test("engine: Azure OpenAI subdomain pattern matches every tenant", function () {
    const e = aig.createGovernanceEngine();
    assert.equal(e.isKnownLLMHost("https://acme-prod.openai.azure.com/openai/deployments/x/chat/completions?api-version=2024-02-15-preview"), true);
    assert.equal(e.isKnownLLMHost("https://anothertenant.openai.azure.com/x"), true);
});

test("engine: AWS Bedrock URL substring rule matches", function () {
    const e = aig.createGovernanceEngine();
    assert.equal(e.isKnownLLMHost("https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke"), true);
});

test("engine: non-LLM domain does NOT match", function () {
    const e = aig.createGovernanceEngine();
    assert.equal(e.isKnownLLMHost("https://www.example.com/api"), false);
    assert.equal(e.isKnownLLMHost("https://amazonaws.com/s3"), false);   // bedrock substring rule is /bedrock-runtime
    assert.equal(e.isKnownLLMHost(""), false);
    assert.equal(e.isKnownLLMHost(null), false);
});

test("engine: additionalKnownLLMHosts extends matching", function () {
    const e = aig.createGovernanceEngine({ additionalKnownLLMHosts: ["custom-llm.internal.example"] });
    assert.equal(e.isKnownLLMHost("https://custom-llm.internal.example/v1/chat"), true);
    assert.equal(e.isKnownLLMHost("https://other.internal.example/v1/chat"), false);
});

test("engine: observe log mode records the event + adds to violations", function () {
    const e = aig.createGovernanceEngine({ mode: "log" });
    const r = e.observe({
        transport: "fetch", method: "POST",
        url: "https://api.openai.com/v1/chat/completions",
        bodyBytes: 1024, bodySha256: "abc",
        caller: "app.js:42",
        observedAt: "2026-06-02T12:00:00Z",
    });
    assert.equal(r.acted, true);
    assert.equal(r.blocked, false);
    const ev = e.events();
    assert.equal(ev.length, 1);
    assert.equal(ev[0].transport, "fetch");
    assert.equal(ev[0].host, "api.openai.com");
    assert.equal(ev[0].bodyBytes, 1024);
    assert.equal(ev[0].blocked, false);
    assert.equal(e.violations().length, 1);
});

test("engine: observe block mode marks event blocked + still records", function () {
    const e = aig.createGovernanceEngine({ mode: "block" });
    const r = e.observe({ transport: "fetch", url: "https://api.openai.com/v1/x" });
    assert.equal(r.acted, true);
    assert.equal(r.blocked, true);
    assert.equal(e.events()[0].blocked, true);
});

test("engine: non-LLM URL is a no-op", function () {
    const e = aig.createGovernanceEngine();
    const r = e.observe({ url: "https://www.example.com/api/order" });
    assert.equal(r.acted, false);
    assert.equal(e.events().length, 0);
});

test("engine: snapshot returns stable shape with kind + version", function () {
    const e = aig.createGovernanceEngine({ buildId: "build-123", pageHref: "https://shop.example/cart" });
    e.observe({ url: "https://api.openai.com/v1/chat" });
    const snap = e.snapshot();
    assert.equal(snap.v, aig.SCHEMA_VERSION);
    assert.equal(snap.kind, "ai-data-access");
    assert.equal(snap.buildId, "build-123");
    assert.equal(snap.pageHref, "https://shop.example/cart");
    assert.equal(snap.events.length, 1);
    assert.equal(snap.violations.length, 1);
});

test("engine: reset clears events + sequence", function () {
    const e = aig.createGovernanceEngine();
    e.observe({ url: "https://api.openai.com/x" });
    assert.equal(e.size(), 1);
    e.reset();
    assert.equal(e.size(), 0);
    assert.equal(e.events().length, 0);
    assert.equal(e.violations().length, 0);
});

test("engine: backpressure caps event log at MAX_EVENT_LOG", function () {
    const e = aig.createGovernanceEngine();
    for (let i = 0; i < 600; i++) e.observe({ url: "https://api.openai.com/v1/x?n=" + i });
    assert.ok(e.size() <= 500, "got " + e.size());
});

test("engine: malformed URL returns no-op classification, not crash", function () {
    const e = aig.createGovernanceEngine();
    assert.equal(e.isKnownLLMHost("definitely not a url"), false);
    const r = e.observe({ url: "definitely not a url" });
    assert.equal(r.acted, false);
});

test("engine: snapshot arrays are independent copies", function () {
    const e = aig.createGovernanceEngine();
    e.observe({ url: "https://api.openai.com/v1/x" });
    const a = e.snapshot();
    const b = e.snapshot();
    a.events.push({ url: "intruder" });
    assert.equal(b.events.length, 1);
});

test("attach: idempotent (second attach returns same engine)", function () {
    const fakeWin = makeWindowStub();
    const e1 = aig.attach(fakeWin, { mode: "log" });
    const e2 = aig.attach(fakeWin, { mode: "block" });
    assert.strictEqual(e1, e2);
});

test("attach: throws when window is missing", function () {
    assert.throws(function () { aig.attach(null, {}); }, /window object required/);
});

test("attach: fetch hook routes LLM URL through engine; non-LLM passes through", async function () {
    const fakeWin = makeWindowStub();
    let realFetched = [];
    fakeWin.fetch = function (u, init) {
        realFetched.push({ u: u, init: init });
        return Promise.resolve({ ok: true, status: 200 });
    };
    const engine = aig.attach(fakeWin, { mode: "log" });
    // Non-LLM: passes through normally
    await fakeWin.fetch("https://www.example.com/api/order", { method: "POST" });
    // LLM: also passes through in log mode, but engine records it
    await fakeWin.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "hello" });
    assert.equal(realFetched.length, 2);
    assert.equal(engine.events().length, 1);
    assert.equal(engine.events()[0].host, "api.openai.com");
});

test("attach: block-mode fetch returns 451 synthetic response", async function () {
    const fakeWin = makeWindowStub();
    fakeWin.fetch = function () { throw new Error("orig fetch should not run in block mode"); };
    fakeWin.Response = function (body, init) {
        this.body = body;
        this.status = (init && init.status) || 200;
        this.statusText = (init && init.statusText) || "";
    };
    const engine = aig.attach(fakeWin, { mode: "block" });
    const r = await fakeWin.fetch("https://api.anthropic.com/v1/messages", { method: "POST", body: "..." });
    assert.equal(r.status, 451);
    assert.match(String(r.body), /ai_data_access_blocked/);
    assert.equal(engine.events().length, 1);
    assert.equal(engine.events()[0].blocked, true);
});

// ---- helpers ---------------------------------------------------------------
function makeWindowStub() {
    const win = {};
    win.setInterval = function () { return 1; };
    win.addEventListener = function () {};
    win.navigator = { sendBeacon: function () { return true; } };
    return win;
}
