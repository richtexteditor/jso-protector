"use strict";

// Unit tests for the AI client wrapper in ai.js.
// Stands up a tiny mock JSO AI HTTP server, points the ai module at it,
// then asserts the request body shape and how the methods unpack the
// response envelope.

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const http   = require("node:http");
const path   = require("node:path");
const test   = require("node:test");

const ai = require("../ai.js");

// ----- mock server -----------------------------------------------------

function startMock(handler) {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            const chunks = [];
            req.on("data", c => chunks.push(c));
            req.on("end", () => {
                const body = Buffer.concat(chunks).toString("utf8");
                let parsed = null;
                try { parsed = JSON.parse(body); } catch { /* leave null */ }
                handler(req, parsed, res);
            });
        });
        server.listen(0, "127.0.0.1", () => {
            const addr = server.address();
            resolve({ server, baseUrl: `http://127.0.0.1:${addr.port}` });
        });
    });
}

function reply(res, body, status = 200) {
    res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(body));
}

// ----- env-isolating helper --------------------------------------------

function withEnv(overrides, fn) {
    const saved = {};
    for (const k of Object.keys(overrides)) {
        saved[k] = process.env[k];
        if (overrides[k] === undefined) delete process.env[k];
        else process.env[k] = overrides[k];
    }
    return Promise.resolve()
        .then(fn)
        .finally(() => {
            for (const k of Object.keys(saved)) {
                if (saved[k] === undefined) delete process.env[k];
                else process.env[k] = saved[k];
            }
        });
}

function providerKeyHealth(overrides) {
    return Object.assign({
        hasKey: true,
        provider: "openai",
        status: "ready",
        label: "Key ready",
        testDue: false,
        rotationDue: false,
        lastTestStatus: "passed",
        lastTestUtc: "2026-05-26T00:00:00Z",
        nextTestDueUtc: "2026-06-25T00:00:00Z",
        rotationDueUtc: "2026-08-24T00:00:00Z",
        recommendedAction: "No action needed today.",
    }, overrides || {});
}

function runAiCli(args, envOverrides) {
    return new Promise((resolve, reject) => {
        const child = childProcess.spawn(process.execPath, [
            path.join(__dirname, "..", "bin", "jso-protector.js"),
            "ai",
            ...args,
        ], {
            cwd: path.join(__dirname, ".."),
            env: Object.assign({}, process.env, envOverrides || {}),
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", c => { stdout += c.toString("utf8"); });
        child.stderr.on("data", c => { stderr += c.toString("utf8"); });
        child.on("error", reject);
        child.on("close", code => resolve({ code, stdout, stderr }));
    });
}

// ----- tests -----------------------------------------------------------

test("ai.usage: sends APIKey+APIPwd and parses the envelope", async () => {
    let captured = null;
    const { server, baseUrl } = await startMock((req, body, res) => {
        captured = { path: req.url, body };
        reply(res, {
            ok: true, previewMode: true,
            tier: "FreeTrial", billingMonth: "2026-05-01",
            actionsUsed: 0, actionsCap: 10, actionsRemaining: 10,
            tokensUsed: 0, tokensCap: 0, tokensRemaining: 0,
            approxCostCents: 0, costCapCents: 200, costRemainingCents: 200,
            providerKey: providerKeyHealth(),
            quotaRejections: 0, asOfUtc: "2026-05-26T00:00:00Z",
        });
    });
    try {
        await withEnv({ JSO_API_KEY: "ZHVtbXk=", JSO_API_PASSWORD: "ZHVtbXk=" }, async () => {
            const r = await ai.usage({ endpoint: baseUrl });
            assert.equal(captured.path, "/v1/ai/usage.ashx");
            assert.equal(captured.body.APIKey, "ZHVtbXk=");
            assert.equal(captured.body.APIPwd, "ZHVtbXk=");
            assert.equal(r.ok, true);
            assert.equal(r.tier, "FreeTrial");
            assert.equal(r.actionsRemaining, 10);
            assert.equal(r.providerKey.status, "ready");
            assert.equal(r.providerKey.provider, "openai");
            assert.equal(r.providerKey.nextTestDueUtc, "2026-06-25T00:00:00Z");
            assert.equal(Object.prototype.hasOwnProperty.call(r.providerKey, "apiKey"), false);
        });
    } finally { server.close(); }
});

test("jso ai usage --pretty: prints source-free provider-key health", async () => {
    const { server, baseUrl } = await startMock((_req, _body, res) => {
        reply(res, {
            ok: true, previewMode: false,
            tier: "Pro", billingMonth: "2026-06-01",
            actionsUsed: 12, actionsCap: 500, actionsRemaining: 488,
            tokensUsed: 21000, tokensCap: 1000000, tokensRemaining: 979000,
            approxCostCents: 450, costCapCents: 5000, costRemainingCents: 4550,
            providerKey: providerKeyHealth(),
            quotaRejections: 0, asOfUtc: "2026-06-08T12:00:00Z",
        });
    });
    try {
        const r = await runAiCli([
            "usage",
            "--pretty",
            "--endpoint", baseUrl,
            "--api-key", "x",
            "--api-password", "y",
        ]);
        assert.equal(r.code, 0, r.stderr);
        assert.match(r.stdout, /AI key health:\s+Key ready \(openai\) \[ready\]/);
        assert.match(r.stdout, /next key test:\s+2026-06-25T00:00:00Z/);
        assert.match(r.stdout, /rotation review:\s+2026-08-24T00:00:00Z/);
        assert.match(r.stdout, /key action:\s+No action needed today\./);
        assert.doesNotMatch(r.stdout, /apiKey|keyLast4|sk-/i);
    } finally { server.close(); }
});

test("ai.presetSuggest: sends description and unpacks suggestion", async () => {
    let captured = null;
    const { server, baseUrl } = await startMock((req, body, res) => {
        captured = body;
        reply(res, {
            ok: true, previewMode: true, provider: "rule-based", tokensIn: 0, tokensOut: 0,
            suggestion: {
                previewMode: true, source: "rule-based",
                config: { preset: "balanced" },
                signals: ["signal a", "signal b"],
            },
        });
    });
    try {
        const r = await ai.presetSuggest({
            apiKey: "x", apiPassword: "y", endpoint: baseUrl,
            description: "React SaaS, balanced",
        });
        assert.equal(captured.description, "React SaaS, balanced");
        assert.equal(captured.APIKey, "x");
        assert.equal(captured.APIPwd, "y");
        assert.equal(r.ok, true);
        assert.equal(r.suggestion.config.preset, "balanced");
        assert.equal(r.suggestion.signals.length, 2);
    } finally { server.close(); }
});

test("ai.presetSuggest: missing description throws synchronously", async () => {
    await assert.rejects(
        ai.presetSuggest({ apiKey: "x", apiPassword: "y", endpoint: "http://127.0.0.1:0" }),
        (err) => err.code === "input_invalid" && /description/i.test(err.message));
});

test("ai.compatCheck: sends source + framework hint", async () => {
    let captured = null;
    const { server, baseUrl } = await startMock((req, body, res) => {
        captured = body;
        reply(res, {
            ok: true, previewMode: true, provider: "rule-based", tokensIn: 0, tokensOut: 0,
            report: {
                previewMode: true, source: "rule-based",
                summary: { errors: 2, warnings: 1, infos: 0 },
                findings: [
                    { category: "dynamic-eval", severity: "error", line: 1, column: 1,
                      message: "eval", suggestedFix: "dispatch table" },
                    { category: "debug-leak", severity: "error", line: 2, column: 1,
                      message: "debugger", suggestedFix: "remove" },
                    { category: "inline-html", severity: "warning", line: 3, column: 1,
                      message: "document.write", suggestedFix: "audit" },
                ],
            },
        });
    });
    try {
        const r = await ai.compatCheck({
            apiKey: "x", apiPassword: "y", endpoint: baseUrl,
            source: "eval('x'); debugger; document.write(name);",
            framework: "react",
        });
        assert.equal(captured.source, "eval('x'); debugger; document.write(name);");
        assert.equal(captured.framework, "react");
        assert.equal(r.ok, true);
        assert.equal(r.report.summary.errors, 2);
        assert.equal(r.report.findings.length, 3);
    } finally { server.close(); }
});

test("ai.explainError: sends error and unpacks explanation", async () => {
    let captured = null;
    const { server, baseUrl } = await startMock((req, body, res) => {
        captured = body;
        reply(res, {
            ok: true, previewMode: true, provider: "rule-based", tokensIn: 0, tokensOut: 0,
            explanation: {
                previewMode: true, source: "rule-based",
                cause: "name-mangling", transform: "Name Mangling", confidence: "high",
                explanation: "renamed identifier", fix: "VariableExclusion",
                docsUrl: "/Docs/VariableExclusionList.aspx",
            },
        });
    });
    try {
        const r = await ai.explainError({
            apiKey: "x", apiPassword: "y", endpoint: baseUrl,
            error: "Uncaught TypeError: api.charge is not a function",
        });
        assert.equal(captured.error, "Uncaught TypeError: api.charge is not a function");
        assert.equal(r.ok, true);
        assert.equal(r.explanation.cause, "name-mangling");
        assert.equal(r.explanation.confidence, "high");
    } finally { server.close(); }
});

test("ai: missing credentials throws auth_missing", async () => {
    await withEnv({ JSO_API_KEY: undefined, JSO_API_PASSWORD: undefined }, async () => {
        await assert.rejects(
            ai.usage({ endpoint: "http://127.0.0.1:0" }),
            (err) => err.code === "auth_missing");
    });
});

test("ai: env-var fallback works when no explicit credentials", async () => {
    let captured = null;
    const { server, baseUrl } = await startMock((req, body, res) => {
        captured = body;
        reply(res, { ok: true, previewMode: true, tier: "FreeTrial", billingMonth: "2026-05-01",
            actionsUsed: 0, actionsCap: 10, actionsRemaining: 10,
            tokensUsed: 0, tokensCap: 0, tokensRemaining: 0,
            approxCostCents: 0, costCapCents: 0, costRemainingCents: 0,
            quotaRejections: 0, asOfUtc: "2026-05-26T00:00:00Z" });
    });
    try {
        await withEnv({ JSO_API_KEY: "envkey", JSO_API_PASSWORD: "envpwd" }, async () => {
            await ai.usage({ endpoint: baseUrl });
        });
        assert.equal(captured.APIKey, "envkey");
        assert.equal(captured.APIPwd, "envpwd");
    } finally { server.close(); }
});

test("ai: HTTP 4xx surfaces as rejected promise with status + body", async () => {
    const { server, baseUrl } = await startMock((req, body, res) => {
        reply(res, { ok: false, error: "rate_limited", message: "Retry after 30s." }, 429);
    });
    try {
        await assert.rejects(
            ai.usage({ apiKey: "x", apiPassword: "y", endpoint: baseUrl }),
            (err) => err.status === 429 && err.body && err.body.error === "rate_limited");
    } finally { server.close(); }
});

test("ai: business-logic ok:false comes back as resolved value", async () => {
    const { server, baseUrl } = await startMock((req, body, res) => {
        reply(res, { ok: false, error: "auth_failed", message: "Bad APIKey." }, 200);
    });
    try {
        const r = await ai.usage({ apiKey: "bad", apiPassword: "bad", endpoint: baseUrl });
        assert.equal(r.ok, false);
        assert.equal(r.error, "auth_failed");
    } finally { server.close(); }
});

test("ai: User-Agent header advertises the package", async () => {
    let userAgent = null;
    const { server, baseUrl } = await startMock((req, body, res) => {
        userAgent = req.headers["user-agent"];
        reply(res, { ok: true, previewMode: true, tier: "FreeTrial", billingMonth: "2026-05-01",
            actionsUsed: 0, actionsCap: 10, actionsRemaining: 10,
            tokensUsed: 0, tokensCap: 0, tokensRemaining: 0,
            approxCostCents: 0, costCapCents: 0, costRemainingCents: 0,
            quotaRejections: 0, asOfUtc: "2026-05-26T00:00:00Z" });
    });
    try {
        await ai.usage({ apiKey: "x", apiPassword: "y", endpoint: baseUrl });
        assert.match(userAgent, /jso-protector-node\/ai/);
    } finally { server.close(); }
});
