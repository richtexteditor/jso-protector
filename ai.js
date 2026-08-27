"use strict";

// JSO AI client. Wraps the four /v1/ai/* endpoints documented at
// https://javascriptobfuscator.com/docs/aiapi.aspx
//
// Same auth model as the protect API: { apiKey, apiPassword } (base64
// values from the dashboard). Reads JSO_API_KEY / JSO_API_PASSWORD from
// the environment if not passed explicitly, matching the CLI's behavior.
//
// Zero dependencies. Node 18+ recommended (uses global fetch); falls
// back to node:https on older runtimes.

const http  = require("node:http");
const https = require("node:https");

const DEFAULT_ENDPOINT = "https://javascriptobfuscator.com";

function resolveCredentials(opts = {}) {
    const apiKey      = opts.apiKey      || process.env.JSO_API_KEY;
    const apiPassword = opts.apiPassword || process.env.JSO_API_PASSWORD;
    if (!apiKey || !apiPassword) {
        const err = new Error(
            "JSO AI: APIKey / APIPwd required. Pass {apiKey, apiPassword} or set " +
            "JSO_API_KEY / JSO_API_PASSWORD environment variables.");
        err.code = "auth_missing";
        throw err;
    }
    return { apiKey, apiPassword };
}

function resolveEndpoint(opts = {}) {
    return (opts.endpoint || process.env.JSO_BASE_URL || DEFAULT_ENDPOINT)
        .replace(/\/+$/, "");
}

// Post JSON to the given path. Resolves with the parsed envelope.
// Rejects with an Error carrying .status + .body for HTTP-level failures
// (405, 429, 5xx). Business-logic errors (ok:false) come back as a normal
// resolved value with body.ok === false; callers branch on that.
function postJson(url, body, timeoutMs) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const client = u.protocol === "http:" ? http : https;
        const payload = JSON.stringify(body);
        const req = client.request({
            method: "POST",
            hostname: u.hostname,
            port: u.port || (u.protocol === "http:" ? 80 : 443),
            path: u.pathname + (u.search || ""),
            headers: {
                "Content-Type":   "application/json",
                "Content-Length": Buffer.byteLength(payload),
                "User-Agent":     "jso-protector-node/ai",
            },
            timeout: timeoutMs || 30000,
        }, (res) => {
            const chunks = [];
            res.on("data", c => chunks.push(c));
            res.on("end", () => {
                const text = Buffer.concat(chunks).toString("utf8");
                let parsed = null;
                try { parsed = JSON.parse(text); } catch { /* leave null */ }
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    const err = new Error("HTTP " + res.statusCode + " from " + u.pathname);
                    err.status = res.statusCode;
                    err.body   = parsed || text;
                    return reject(err);
                }
                if (parsed === null) {
                    return reject(new Error("Non-JSON response from " + u.pathname));
                }
                resolve(parsed);
            });
        });
        req.on("timeout", () => req.destroy(new Error("Request timed out after " + (timeoutMs || 30000) + "ms")));
        req.on("error",   reject);
        req.write(payload);
        req.end();
    });
}

function buildBody(creds, extra) {
    return Object.assign({ APIKey: creds.apiKey, APIPwd: creds.apiPassword }, extra || {});
}

/**
 * Ask the preset assistant to suggest a `jso.config.json` from a natural-
 * language description.
 *
 *   const { suggestion } = await ai.presetSuggest({
 *       description: "React SaaS frontend, balanced performance, lock to example.com"
 *   });
 *   fs.writeFileSync("jso.config.json", JSON.stringify(suggestion.config, null, 2));
 */
async function presetSuggest(opts = {}) {
    const creds = resolveCredentials(opts);
    const endpoint = resolveEndpoint(opts);
    if (!opts.description) {
        const err = new Error("ai.presetSuggest: 'description' is required");
        err.code = "input_invalid";
        throw err;
    }
    return postJson(endpoint + "/v1/ai/preset-suggest.ashx",
        buildBody(creds, { description: opts.description }),
        opts.timeoutMs);
}

/**
 * Scan a JS source string for patterns that won't survive obfuscation
 * (eval, debugger, document.write, source maps, etc.). Returns a structured
 * findings report.
 *
 *   const { report } = await ai.compatCheck({
 *       source: fs.readFileSync("src/app.js", "utf8"),
 *       framework: "react"
 *   });
 *   if (report.summary.errors > 0) process.exit(1);
 */
async function compatCheck(opts = {}) {
    const creds = resolveCredentials(opts);
    const endpoint = resolveEndpoint(opts);
    if (!opts.source) {
        const err = new Error("ai.compatCheck: 'source' is required");
        err.code = "input_invalid";
        throw err;
    }
    const body = { source: opts.source };
    if (opts.framework) body.framework = opts.framework;
    return postJson(endpoint + "/v1/ai/compat-check.ashx",
        buildBody(creds, body),
        opts.timeoutMs);
}

/**
 * Diagnose a protected-output runtime error. Returns the likely JSO
 * transform that caused it + a recommended fix.
 *
 *   const { explanation } = await ai.explainError({
 *       error: "Uncaught TypeError: api.charge is not a function"
 *   });
 *   console.log(explanation.transform, "->", explanation.fix);
 */
async function explainError(opts = {}) {
    const creds = resolveCredentials(opts);
    const endpoint = resolveEndpoint(opts);
    if (!opts.error) {
        const err = new Error("ai.explainError: 'error' is required");
        err.code = "input_invalid";
        throw err;
    }
    const body = { error: opts.error };
    if (opts.config) body.config = opts.config;
    return postJson(endpoint + "/v1/ai/explain-error.ashx",
        buildBody(creds, body),
        opts.timeoutMs);
}

/**
 * Read the current-month AI quota counters for this account.
 * Free to poll (this endpoint does not count against actionsCap).
 *
 *   const u = await ai.usage();
 *   if (u.actionsRemaining < 5) console.warn("AI quota almost exhausted");
 *   if (u.providerKey && u.providerKey.status !== "ready") {
 *       console.warn("AI key health:", u.providerKey.label);
 *   }
 */
async function usage(opts = {}) {
    const creds = resolveCredentials(opts);
    const endpoint = resolveEndpoint(opts);
    return postJson(endpoint + "/v1/ai/usage.ashx",
        buildBody(creds, {}),
        opts.timeoutMs);
}

module.exports = { presetSuggest, compatCheck, explainError, usage };
