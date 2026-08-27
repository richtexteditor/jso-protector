"use strict";

// Unit tests for runtime/environment-integrity.js. No real DOM: the
// module takes `win` as a parameter, so we hand it stubs. That also lets
// us stage things a real browser will not do on demand, such as a
// Function.prototype.toString that lies about itself.

const test = require("node:test");
const assert = require("node:assert");
const ei = require("../runtime/environment-integrity.js");

// ---------------------------------------------------------------- helpers

function nativeText(name) {
    return "function " + name + "() { [native code] }";
}

// A stringifier that reports every function as native unless the
// function is flagged `__hooked`. Mirrors what a real engine does.
function makeToString() {
    const f = function () {
        if (this && this.__hooked) return "function () { /* patched by harness */ }";
        return nativeText((this && this.__name) || "anonymous");
    };
    f.__name = "toString";
    return f;
}

function stubFn(name, hooked) {
    const f = function () {};
    f.__name = name;
    if (hooked) f.__hooked = true;
    return f;
}

// hookedPaths: dotted paths to mark as replaced.
// toStringHooked: also lie about Function.prototype.toString itself.
function makeWin(opts) {
    opts = opts || {};
    const hooked = opts.hookedPaths || [];
    function isHooked(p) { return hooked.indexOf(p) !== -1; }

    const toStringFn = makeToString();
    if (opts.toStringHooked) toStringFn.__hooked = true;

    return {
        Function: {
            prototype: {
                toString: toStringFn,
                call: stubFn("call", isHooked("Function.prototype.call")),
                apply: stubFn("apply", isHooked("Function.prototype.apply")),
                bind: stubFn("bind", isHooked("Function.prototype.bind")),
            },
        },
        Object: {
            defineProperty: stubFn("defineProperty", isHooked("Object.defineProperty")),
            getOwnPropertyDescriptor: stubFn("getOwnPropertyDescriptor",
                isHooked("Object.getOwnPropertyDescriptor")),
        },
        JSON: {
            parse: stubFn("parse", isHooked("JSON.parse")),
            stringify: stubFn("stringify", isHooked("JSON.stringify")),
        },
        navigator: opts.navigator || {},
    };
}

// A document stub whose iframe exposes a pristine realm. `pristine`
// decides whether that realm's toString is honest about hooks.
function attachDocument(win, opts) {
    opts = opts || {};
    const appended = [];
    const removed = [];

    const frame = {
        style: {},
        setAttribute: function () {},
        parentNode: null,
        contentWindow: opts.blocked ? {} : {
            Function: { prototype: { toString: makeToString() } },
        },
    };

    win.document = {
        createElement: function () {
            if (opts.throwOnCreate) throw new Error("blocked by CSP");
            return frame;
        },
        body: {
            appendChild: function (el) { appended.push(el); el.parentNode = win.document.body; },
            removeChild: function (el) { removed.push(el); el.parentNode = null; },
        },
    };
    win.document.body.parentNode = null;
    return { frame: frame, appended: appended, removed: removed };
}

function markers(report, check) {
    return report.findings
        .filter(function (f) { return check ? f.check === check : true; })
        .map(function (f) { return f.marker; });
}

// ------------------------------------------------------------------ tests

test("ALL_CHECKS exposes the documented set", function () {
    assert.deepEqual(ei.ALL_CHECKS, ["hookedBuiltins", "crossRealm", "automation"]);
});

test("createEnvironmentIntegrityPolicy: rejects an unknown check", function () {
    assert.throws(function () {
        ei.createEnvironmentIntegrityPolicy({ checks: ["antiGravity"] });
    }, /unknown check 'antiGravity'/);
});

test("createEnvironmentIntegrityPolicy: accepts a bare string for checks and watch", function () {
    const p = ei.createEnvironmentIntegrityPolicy({ checks: "automation", watch: "JSON.parse" });
    assert.deepEqual(p.describe(), { checks: ["automation"], watch: ["JSON.parse"] });
});

test("createEnvironmentIntegrityPolicy: rejects a non-array checks value", function () {
    assert.throws(function () {
        ei.createEnvironmentIntegrityPolicy({ checks: 7 });
    }, /checks must be a string or an array/);
});

test("console is not watched by default (legitimate wrappers are common)", function () {
    assert.ok(ei.DEFAULT_WATCH.every(function (p) { return p.indexOf("console") === -1; }),
        "DEFAULT_WATCH must not include console methods");
});

test("clean environment reports ok and complete", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(makeWin());
    assert.equal(report.ok, true);
    assert.equal(report.complete, true);
    assert.deepEqual(report.findings, []);
    assert.equal(report.counts.high, 0);
});

test("hookedBuiltins flags a replaced builtin as high severity", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(makeWin({ hookedPaths: ["Function.prototype.call"] }));
    assert.equal(report.ok, false);
    assert.equal(report.counts.high, 1);
    assert.deepEqual(markers(report, "hookedBuiltins"), ["Function.prototype.call"]);
    assert.equal(report.violation.reason, "environment-hooked");
    assert.equal(report.violation.src, "environment-integrity");
});

test("hookedBuiltins flags a lying Function.prototype.toString as unreliable", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(makeWin({ toStringHooked: true }));
    assert.deepEqual(markers(report), ["toStringUnreliable"]);
    assert.equal(report.ok, false);
});

test("an unreliable toString does not flood the report with per-builtin findings", function () {
    // Regression guard. An unreliable stringifier misreports every function,
    // so a naive loop would mark all eight watched builtins as hooked and
    // bury the single finding that actually matters.
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(makeWin({ toStringHooked: true }));
    assert.equal(report.findings.length, 1,
        "expected exactly one finding, got: " + JSON.stringify(markers(report)));
});

test("hookedBuiltins treats an absent builtin as unremarkable", function () {
    const win = makeWin();
    delete win.JSON;
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(win);
    assert.equal(report.ok, true, "a missing global is not evidence of tampering");
});

test("hookedBuiltins reports unavailable when toString itself is missing", function () {
    const win = makeWin();
    // Assign undefined rather than `delete`: deleting the own property lets
    // it resolve up the prototype chain to Object.prototype.toString, which
    // is a different scenario (covered by the next test).
    win.Function.prototype.toString = undefined;
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(win);
    assert.deepEqual(markers(report), ["toStringMissing"]);
    assert.equal(report.complete, false);
    assert.equal(report.ok, true, "could-not-look is unavailable, not a positive finding");
});

test("toString resolving to Object.prototype.toString yields one finding, not eight", function () {
    // Realistic degradation: something removed Function.prototype.toString,
    // so lookups fall through to Object.prototype.toString, which answers
    // "[object Object]" for every function. Must read as one unreliable
    // stringifier, not as eight hooked builtins.
    const win = makeWin();
    delete win.Function.prototype.toString;
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(win);
    assert.deepEqual(markers(report), ["toStringUnreliable"]);
});

test("crossRealm catches a hook that spoofed its own toString", function () {
    // Main realm lies (toStringHooked) AND JSON.parse is replaced, so the
    // same-realm check is untrustworthy; the pristine realm still sees it.
    const win = makeWin({ toStringHooked: true, hookedPaths: ["JSON.parse"] });
    attachDocument(win);
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["crossRealm"] });
    const report = probe.inspect(win);
    assert.ok(markers(report, "crossRealm").indexOf("JSON.parse") !== -1,
        "pristine realm should expose the replaced JSON.parse");
    assert.equal(report.counts.high >= 1, true);
});

test("crossRealm removes its probe iframe (no observable residue)", function () {
    const win = makeWin();
    const dom = attachDocument(win);
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["crossRealm"] });
    probe.inspect(win);
    assert.equal(dom.appended.length, 1, "should have appended one iframe");
    assert.equal(dom.removed.length, 1, "should have removed the iframe again");
    assert.equal(dom.frame.parentNode, null);
});

test("crossRealm reports unavailable, not ok, when the iframe is blocked", function () {
    const win = makeWin();
    attachDocument(win, { blocked: true });
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["crossRealm"] });
    const report = probe.inspect(win);
    assert.deepEqual(markers(report), ["realmUnavailable"]);
    assert.equal(report.complete, false);
    assert.equal(report.violation.reason, "environment-unverified");
});

test("crossRealm survives a throwing createElement and still cleans up", function () {
    const win = makeWin();
    attachDocument(win, { throwOnCreate: true });
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["crossRealm"] });
    const report = probe.inspect(win);
    assert.deepEqual(markers(report), ["realmError"]);
    assert.equal(report.complete, false);
});

test("crossRealm reports unavailable with no document at all", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["crossRealm"] });
    const report = probe.inspect(makeWin());
    assert.deepEqual(markers(report), ["noDocument"]);
});

test("automation flags navigator.webdriver as a signal, not high", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["automation"] });
    const report = probe.inspect(makeWin({ navigator: { webdriver: true } }));
    assert.deepEqual(markers(report), ["navigator.webdriver"]);
    assert.equal(report.counts.signal, 1);
    assert.equal(report.counts.high, 0, "automation is heuristic and must never be high severity");
    assert.equal(report.violation.reason, "automation-signal");
});

test("automation detects a leftover driver global", function () {
    const win = makeWin();
    win._phantom = {};
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["automation"] });
    const report = probe.inspect(win);
    assert.ok(markers(report).indexOf("_phantom") !== -1);
});

test("automation detects a cdc_ property once per host", function () {
    const win = makeWin();
    win.cdc_adoQpoasnfa76pfcZLmcfl_Array = 1;
    win.cdc_adoQpoasnfa76pfcZLmcfl_Promise = 1;
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["automation"] });
    const report = probe.inspect(win);
    const cdc = markers(report).filter(function (m) { return m.indexOf("cdc_") !== -1; });
    assert.equal(cdc.length, 1, "one cdc_ finding per host is enough evidence");
});

test("a clean automation check on a plain browser-like win stays ok", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["automation"] });
    const report = probe.inspect(makeWin({ navigator: { webdriver: false } }));
    assert.equal(report.ok, true);
    assert.deepEqual(report.findings, []);
});

test("inspect tolerates a null win without throwing", function () {
    const probe = ei.createEnvironmentIntegrityPolicy({});
    assert.doesNotThrow(function () { probe.inspect(null); });
    const report = probe.inspect(null);
    assert.equal(report.complete, false, "nothing could be verified");
});

test("every runtime module is reachable through the package exports map", function () {
    // Guard against a whole class of shipping bug. Because package.json
    // declares an "exports" map, Node *blocks* any subpath that is not
    // listed: a consumer calling require("jso-protector/runtime/<name>")
    // gets ERR_PACKAGE_PATH_NOT_EXPORTED, even though the file is present
    // in the tarball via files:["runtime/"]. Adding a runtime module
    // without adding its export ships a module nobody can load.
    // ai-script-governance was in exactly that state when this test was
    // written; environment-integrity would have been the second.
    const fs = require("node:fs");
    const path = require("node:path");
    const json = require("../package.json");
    const dir = path.join(__dirname, "..", "runtime");

    const modules = fs.readdirSync(dir)
        .filter(function (f) { return f.slice(-3) === ".js"; })
        .map(function (f) { return f.slice(0, -3); });

    assert.ok(modules.length > 0, "expected to find runtime modules on disk");

    const unexported = modules.filter(function (name) {
        return !json.exports["./runtime/" + name];
    });
    assert.deepEqual(unexported, [],
        "these runtime modules exist but are not in the exports map: " + unexported.join(", "));
});

test("violation payload is shaped for countermeasures.react", function () {
    const cm = require("../runtime/countermeasures.js");
    const policy = cm.createCountermeasurePolicy({ onTamper: "log" });
    const probe = ei.createEnvironmentIntegrityPolicy({ checks: ["hookedBuiltins"] });
    const report = probe.inspect(makeWin({ hookedPaths: ["JSON.stringify"] }));
    // The point of the test: the report drops straight into the existing
    // response pipeline with no adapter.
    assert.doesNotThrow(function () { policy.react({}, report.violation); });
});
