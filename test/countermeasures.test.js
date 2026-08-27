"use strict";

// Unit tests for runtime/countermeasures.js. No DOM dependency - the
// module's API is pure-data until you call .react(win, ...), and we
// pass a minimal hand-rolled win stub to exercise each action.

const test = require("node:test");
const assert = require("node:assert");
const cm = require("../runtime/countermeasures.js");

test("ALL_ACTIONS exposes the documented set", function () {
    assert.deepEqual(cm.ALL_ACTIONS, ["log", "break", "deleteCookies", "selfDestruct", "redirect", "callback"]);
});

test("createCountermeasurePolicy: rejects unknown action name", function () {
    assert.throws(function () { cm.createCountermeasurePolicy({ onTamper: "self-destruct" }); },
        /unknown action 'self-destruct'/);
});

test("createCountermeasurePolicy: rejects non-string non-array onTamper", function () {
    assert.throws(function () { cm.createCountermeasurePolicy({ onTamper: 42 }); },
        /must be a string or array/);
});

test("createCountermeasurePolicy: rejects javascript: redirectUrl", function () {
    assert.throws(function () { cm.createCountermeasurePolicy({ onTamper: "redirect", redirectUrl: "javascript:alert(1)" }); },
        /must be a plain http\(s\) URL/);
});

test("createCountermeasurePolicy: allowList blocks escalation", function () {
    assert.throws(function () {
        cm.createCountermeasurePolicy({
            onTamper: ["log", "selfDestruct"],
            allowList: ["log", "break"], // selfDestruct not allowed in dev
        });
    }, /not in allowList/);
});

test("describe() reflects the policy without side effects", function () {
    const policy = cm.createCountermeasurePolicy({
        onTamper: ["log", "deleteCookies"],
        allowList: ["log", "deleteCookies"],
    });
    const d = policy.describe();
    assert.deepEqual(d.onTamper, ["log", "deleteCookies"]);
    assert.deepEqual(d.allowList, ["log", "deleteCookies"]);
    assert.equal(d.callbackBound, false);
});

test("react: 'log' action always fires first and returns the action tag", function () {
    const policy = cm.createCountermeasurePolicy({ onTamper: "log" });
    const result = policy.react({}, { reason: "test" });
    assert.deepEqual(result, ["log"]);
});

test("react: 'break' stubs functions on window.__jsoEntry", function () {
    const calls = [];
    const win = {
        __jsoEntry: {
            charge: function () { calls.push("real-charge"); return "ok"; },
            log:    function () { calls.push("real-log"); },
        },
    };
    const policy = cm.createCountermeasurePolicy({ onTamper: ["log", "break"] });
    policy.react(win, { reason: "tampered" });
    // The functions still exist...
    assert.equal(typeof win.__jsoEntry.charge, "function");
    // ... but they're stubs (no return value, no side effect).
    const r = win.__jsoEntry.charge("4111111111111111");
    assert.equal(r, undefined);
    assert.equal(calls.length, 0, "real charge function must NOT run after break");
});

test("react: 'deleteCookies' clears cookies + storage", function () {
    let cookieValue = "session=abc; _ga=def; userid=u123";
    const sessionCleared = [];
    const localCleared = [];
    const win = {
        document: {
            get cookie() { return cookieValue; },
            set cookie(v) { cookieValue = v; },
        },
        sessionStorage: { clear: function () { sessionCleared.push("yes"); } },
        localStorage:   { clear: function () { localCleared.push("yes"); } },
    };
    const policy = cm.createCountermeasurePolicy({ onTamper: ["deleteCookies"] });
    policy.react(win, { reason: "skim" });
    // Cookie should now be a "this is expired" string for the LAST key set
    assert.match(cookieValue, /expires=Thu, 01 Jan 1970/);
    assert.equal(sessionCleared.length, 1);
    assert.equal(localCleared.length, 1);
});

test("react: 'selfDestruct' blank-body mode empties body element", function () {
    const removed = [];
    const child1 = { nodeName: "DIV" };
    const child2 = { nodeName: "FORM" };
    const body = {
        children: [child1, child2],
        get firstChild() { return this.children[0] || null; },
        removeChild: function (c) {
            removed.push(c);
            this.children.shift();
        },
    };
    const win = { document: { body: body } };
    const policy = cm.createCountermeasurePolicy({
        onTamper: ["selfDestruct"],
        selfDestruct: { mode: "blank-body" },
    });
    const result = policy.react(win, { reason: "ioc" });
    assert.equal(removed.length, 2);
    assert.ok(result.includes("selfDestruct:blank-body"));
});

test("react: 'redirect' uses location.assign when available", function () {
    const visited = [];
    const win = {
        location: { assign: function (u) { visited.push(u); } },
    };
    const policy = cm.createCountermeasurePolicy({
        onTamper: ["redirect"],
        redirectUrl: "https://example.com/outage",
    });
    policy.react(win, {});
    assert.deepEqual(visited, ["https://example.com/outage"]);
});

test("react: 'redirect' with no URL configured is noop", function () {
    let assigned = null;
    const win = { location: { assign: function (u) { assigned = u; } } };
    const policy = cm.createCountermeasurePolicy({ onTamper: ["redirect"] });
    const result = policy.react(win, {});
    assert.equal(assigned, null);
    assert.ok(result.includes("redirect:noop"));
});

test("react: 'callback' invokes the user function with the violation", function () {
    const seen = [];
    const policy = cm.createCountermeasurePolicy({
        onTamper: "callback",
        callback: function (v) { seen.push(v); },
    });
    policy.react({}, { reason: "ioc", src: "https://evil.com/x.js" });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].reason, "ioc");
});

test("react: 'callback' exception does not stop the chain", function () {
    let nextReached = false;
    const win = { location: { assign: function () { nextReached = true; } } };
    const policy = cm.createCountermeasurePolicy({
        onTamper: ["callback", "redirect"],
        redirectUrl: "https://example.com/x",
        callback: function () { throw new Error("boom"); },
    });
    policy.react(win, {});
    assert.equal(nextReached, true, "redirect should still fire after callback threw");
});

test("react: multiple actions fire in declared order", function () {
    const trace = [];
    const win = {
        document: { body: { children: [], get firstChild(){return null;}, removeChild: function(){} }, cookie: "" },
        sessionStorage: { clear: function () { trace.push("session"); } },
        localStorage:   { clear: function () { trace.push("local"); } },
        location:       { assign: function (u) { trace.push("redirect:" + u); } },
    };
    const policy = cm.createCountermeasurePolicy({
        onTamper: ["log", "deleteCookies", "selfDestruct", "redirect"],
        redirectUrl: "https://example.com/x",
        selfDestruct: { mode: "blank-body" },
    });
    policy.react(win, {});
    // order: deleteCookies (session+local) before redirect.
    assert.deepEqual(trace, ["session", "local", "redirect:https://example.com/x"]);
});
