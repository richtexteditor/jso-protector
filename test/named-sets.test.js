"use strict";

// Unit tests for config/named-sets.js. Pure-data resolution; no I/O.

const test = require("node:test");
const assert = require("node:assert");
const ns = require("../config/named-sets.js");

test("matchGlob: basic *", function () {
    assert.equal(ns.matchGlob("*.js", "app.js"), true);
    assert.equal(ns.matchGlob("*.js", "app.ts"), false);
    assert.equal(ns.matchGlob("*.js", "src/app.js"), false, "single * does NOT cross slashes");
});

test("matchGlob: ** crosses slashes", function () {
    assert.equal(ns.matchGlob("src/**/*.js", "src/app.js"), true);
    assert.equal(ns.matchGlob("src/**/*.js", "src/a/b/c/app.js"), true);
    assert.equal(ns.matchGlob("src/**", "src"), true, "trailing /** matches the bare directory too");
    assert.equal(ns.matchGlob("src/**", "src/checkout/index.js"), true);
});

test("matchGlob: ? matches one non-slash char", function () {
    assert.equal(ns.matchGlob("a?b", "axb"), true);
    assert.equal(ns.matchGlob("a?b", "a/b"), false);
});

test("matchGlob: character class", function () {
    assert.equal(ns.matchGlob("[abc].js", "a.js"), true);
    assert.equal(ns.matchGlob("[abc].js", "d.js"), false);
});

test("matchGlob: brace expansion", function () {
    assert.equal(ns.matchGlob("**/*.{js,ts}", "src/app.js"), true);
    assert.equal(ns.matchGlob("**/*.{js,ts}", "src/app.ts"), true);
    assert.equal(ns.matchGlob("**/*.{js,ts}", "src/app.css"), false);
});

test("matchGlob: backslashes normalised to forward slashes", function () {
    assert.equal(ns.matchGlob("src/**/*.js", "src\\checkout\\pay.js"), true);
});

test("resolveForFile: returns baseline when no set matches", function () {
    const config = {
        preset: "balanced",
        options: { EncodeStrings: true },
        namedSets: {
            checkout: { match: ["src/checkout/**"], preset: "maximum" },
        },
    };
    const r = ns.resolveForFile(config, "src/marketing/landing.js");
    assert.equal(r.set, null);
    assert.equal(r.preset, "balanced");
    assert.deepEqual(r.options, { EncodeStrings: true });
});

test("resolveForFile: matched set overrides preset + merges options", function () {
    const config = {
        preset: "balanced",
        options: { EncodeStrings: true, MoveStrings: true },
        namedSets: {
            checkout: {
                match: ["src/checkout/**"],
                preset: "maximum",
                options: { AddDeadCode: true, MoveStrings: false }, // override one baseline option
            },
        },
    };
    const r = ns.resolveForFile(config, "src/checkout/pay.js");
    assert.equal(r.set, "checkout");
    assert.equal(r.preset, "maximum");
    assert.deepEqual(r.options, { EncodeStrings: true, MoveStrings: false, AddDeadCode: true });
});

test("resolveForFile: countermeasures cascade (set > top > none)", function () {
    const config = {
        countermeasures: { onTamper: "log" },
        namedSets: {
            checkout: {
                match: ["src/checkout/**"],
                countermeasures: { onTamper: ["break", "deleteCookies"] },
            },
        },
    };
    const r1 = ns.resolveForFile(config, "src/checkout/pay.js");
    assert.deepEqual(r1.countermeasures, { onTamper: ["break", "deleteCookies"] });
    const r2 = ns.resolveForFile(config, "src/marketing/x.js");
    assert.deepEqual(r2.countermeasures, { onTamper: "log" });
});

test("resolveForFiles: first-matching-set wins (deterministic precedence)", function () {
    const config = {
        namedSets: {
            "high-risk":   { match: ["src/checkout/**"], preset: "maximum" },
            "all-source":  { match: ["src/**"],          preset: "balanced" },
        },
    };
    const r = ns.resolveForFiles(config, ["src/checkout/pay.js", "src/marketing/landing.js"]);
    assert.equal(r["src/checkout/pay.js"].set, "high-risk");
    assert.equal(r["src/checkout/pay.js"].preset, "maximum");
    assert.equal(r["src/marketing/landing.js"].set, "all-source");
    assert.equal(r["src/marketing/landing.js"].preset, "balanced");
});

test("resolveForFiles: empty namedSets is a no-op", function () {
    const config = { preset: "balanced", options: { EncodeStrings: true } };
    const r = ns.resolveForFile(config, "src/anything.js");
    assert.equal(r.set, null);
    assert.equal(r.preset, "balanced");
});

test("resolveForFiles: set without 'match' is ignored (not a crash)", function () {
    const config = {
        namedSets: { broken: { preset: "maximum" } }, // missing 'match'
    };
    const r = ns.resolveForFile(config, "src/x.js");
    assert.equal(r.set, null);
});

test("schema-shaped config: a real-world checkout vs marketing split resolves", function () {
    const config = {
        endpoint: "https://javascriptobfuscator.com/HttpApi.ashx",
        preset: "balanced",
        options: { EncodeStrings: true },
        countermeasures: { onTamper: "log" },
        namedSets: {
            checkout: {
                match: ["src/checkout/**", "src/wallet/**", "src/payment/**"],
                preset: "maximum",
                options: { AddDeadCode: true, DeadcodeLevel: "High" },
                countermeasures: { onTamper: ["break", "deleteCookies"], redirectUrl: "https://example.com/outage" },
            },
            authenticated: {
                match: ["src/dashboard/**", "src/account/**"],
                preset: "maximum",
                countermeasures: { onTamper: ["deleteCookies"] },
            },
            // marketing falls through to the baseline
        },
    };
    const fileSet = [
        "src/checkout/pay.js",
        "src/wallet/topup.js",
        "src/dashboard/home.js",
        "src/marketing/landing.js",
        "src/marketing/blog/post1.js",
    ];
    const r = ns.resolveForFiles(config, fileSet);
    assert.equal(r["src/checkout/pay.js"].set, "checkout");
    assert.equal(r["src/wallet/topup.js"].set, "checkout");
    assert.equal(r["src/dashboard/home.js"].set, "authenticated");
    assert.equal(r["src/marketing/landing.js"].set, null);
    assert.equal(r["src/marketing/blog/post1.js"].set, null);
    // Baseline countermeasures (log) apply to marketing.
    assert.deepEqual(r["src/marketing/landing.js"].countermeasures, { onTamper: "log" });
    // Checkout uses the escalated countermeasures.
    assert.deepEqual(r["src/checkout/pay.js"].countermeasures.onTamper, ["break", "deleteCookies"]);
});
