"use strict";

// Environment-integrity checks (browser runtime module).
//
// The other runtime modules answer "has my *code* been altered?"
// (managed-integrity) and "is my page talking to somewhere it should
// not?" (data-exfiltration-guard). This module answers a third
// question: **has the JavaScript environment itself been instrumented
// underneath my code?**
//
// That is the precondition for most automated analysis. A tracing
// harness -- hand-rolled or LLM-driven -- typically replaces a few
// builtins (`Function.prototype.call`, `Object.defineProperty`,
// `JSON.parse`) so it can watch arguments and return values without
// touching the protected bundle at all. Integrity hashing of the
// bundle cannot see that, because the bundle is untouched.
//
// Three checks, in descending order of confidence:
//
//   "hookedBuiltins" - compare each watched builtin against the
//                      `[native code]` shape that `Function.prototype
//                      .toString` produces for un-replaced natives.
//                      Cheap, synchronous, no DOM needed.
//   "crossRealm"     - build a throwaway same-origin iframe (a
//                      pristine realm), and diff the main realm's
//                      builtins against it. Catches a hook that also
//                      spoofed its own `toString`, which defeats
//                      check 1 on its own.
//   "automation"     - look for driver/headless markers
//                      (`navigator.webdriver`, PhantomJS and Selenium
//                      leftovers, CDP `cdc_` properties).
//
// HONEST SCOPING -- please read before quoting this in a datasheet.
// ------------------------------------------------------------------
// These checks raise the cost of automated analysis. They do not make
// anything irreversible, and they are bypassable by an attacker who
// controls the runtime: every check here is itself JavaScript running
// in the attacker's browser, so a sufficiently patient attacker can
// neutralise it. In particular:
//
//   * Check 1 trusts `Function.prototype.toString`. If *that* is
//     hooked, a hook can return a fake `[native code]` string. We
//     therefore probe it first and report `toStringUnreliable`, which
//     downgrades the confidence of every other finding in the report.
//   * Check 2 needs same-origin iframes. A strict CSP
//     (`frame-src 'none'`) or a sandboxed context will block it; we
//     report `unavailable` rather than `ok`, because "could not look"
//     is not "nothing there".
//   * Check 3 is heuristic. `navigator.webdriver` is a one-line patch,
//     and a tuned headless browser leaves none of these markers. Treat
//     automation findings as signals, never as proof.
//
// Deliberately conservative defaults
// ----------------------------------
// `console.*` is NOT watched by default. Analytics, logging, and error
// reporting libraries legitimately wrap console methods, so watching
// them produces false positives on ordinary production pages. Opt in
// with `watch: ["console.log"]` if your build has no such library.
//
// Public API
// ----------
//   const ei = require("jso-protector/runtime/environment-integrity");
//   const probe = ei.createEnvironmentIntegrityPolicy({
//       checks: ["hookedBuiltins", "crossRealm", "automation"],
//       watch:  ["Function.prototype.call", "JSON.parse"],
//   });
//   const report = probe.inspect(window);
//   if (!report.ok) { countermeasurePolicy.react(window, report.violation); }
//
// `inspect()` is read-only apart from the iframe the crossRealm check
// creates and removes. The policy is pure data until you call it, so it
// unit-tests against a stub `win` with no DOM.

const ALL_CHECKS = ["hookedBuiltins", "crossRealm", "automation"];

// Builtins worth watching by default: each is a plausible interception
// point for a tracing harness, and none is commonly re-wrapped by
// ordinary libraries. `Function.prototype.toString` leads because every
// other hookedBuiltins result depends on it.
const DEFAULT_WATCH = [
    "Function.prototype.toString",
    "Function.prototype.call",
    "Function.prototype.apply",
    "Function.prototype.bind",
    "Object.defineProperty",
    "Object.getOwnPropertyDescriptor",
    "JSON.parse",
    "JSON.stringify",
];

// Engines differ in spacing and in the function name they echo back, so
// match the shape rather than an exact string.
const NATIVE_CODE = /\{\s*\[native code\]\s*\}/;

// Automation leftovers. Each is a global that a driver injects and does
// not always clean up. Absence proves nothing.
const AUTOMATION_GLOBALS = [
    "_phantom", "__phantomas", "callPhantom",
    "__nightmare",
    "__selenium_unwrapped", "__selenium_evaluate", "__webdriver_evaluate",
    "__driver_evaluate", "__fxdriver_evaluate", "__webdriver_script_fn",
    "domAutomation", "domAutomationController",
];

function resolvePath(root, path) {
    // "Function.prototype.call" -> the function object, or undefined if
    // any hop is missing. Never throws: a missing global is a normal
    // outcome in a non-browser or trimmed environment.
    const parts = String(path).split(".");
    let cur = root;
    for (let i = 0; i < parts.length; i++) {
        if (cur === null || cur === undefined) return undefined;
        try {
            cur = cur[parts[i]];
        } catch (e) {
            return undefined;
        }
    }
    return cur;
}

function looksNative(toStringFn, fn) {
    // Returns true / false / null, where null means "could not tell".
    if (typeof fn !== "function") return null;
    let text;
    try {
        text = toStringFn.call(fn);
    } catch (e) {
        return null;
    }
    if (typeof text !== "string") return null;
    return NATIVE_CODE.test(text);
}

function createEnvironmentIntegrityPolicy(config) {
    const cfg = config || {};

    let checks = cfg.checks === undefined ? ALL_CHECKS.slice() : cfg.checks;
    if (typeof checks === "string") checks = [checks];
    if (!Array.isArray(checks)) {
        throw new TypeError("environment-integrity: checks must be a string or an array");
    }
    checks = checks.slice();
    for (let i = 0; i < checks.length; i++) {
        if (ALL_CHECKS.indexOf(checks[i]) === -1) {
            throw new Error("environment-integrity: unknown check '" + checks[i] + "'");
        }
    }

    let watch = cfg.watch === undefined ? DEFAULT_WATCH.slice() : cfg.watch;
    if (typeof watch === "string") watch = [watch];
    if (!Array.isArray(watch)) {
        throw new TypeError("environment-integrity: watch must be a string or an array");
    }
    watch = watch.slice();

    function checkHookedBuiltins(win, findings) {
        const toStringFn = resolvePath(win, "Function.prototype.toString");
        if (typeof toStringFn !== "function") {
            findings.push({
                check: "hookedBuiltins",
                marker: "toStringMissing",
                severity: "unavailable",
                detail: "Function.prototype.toString is not a function; cannot inspect builtins.",
            });
            return;
        }

        // Probe the prober. A hook that spoofs its own toString will
        // pass here, which is exactly why crossRealm exists.
        if (looksNative(toStringFn, toStringFn) === false) {
            findings.push({
                check: "hookedBuiltins",
                marker: "toStringUnreliable",
                severity: "high",
                detail: "Function.prototype.toString does not report as native; every other " +
                    "hookedBuiltins result is untrustworthy. Prefer the crossRealm check here.",
            });
            // Stop here on purpose. A stringifier that misreports itself
            // misreports everything, so continuing would flag every watched
            // builtin as hooked -- a false-positive storm that buries the one
            // finding that matters. (Seen for real when toString resolves to
            // Object.prototype.toString, which returns "[object Object]".)
            // crossRealm is the check that can still get a truthful answer.
            return;
        }

        for (let i = 0; i < watch.length; i++) {
            const path = watch[i];
            const fn = resolvePath(win, path);
            if (fn === undefined) continue;   // absent is not suspicious
            const native = looksNative(toStringFn, fn);
            if (native === false) {
                findings.push({
                    check: "hookedBuiltins",
                    marker: path,
                    severity: "high",
                    detail: path + " is not reporting as native code, which means it has been " +
                        "replaced or wrapped.",
                });
            } else if (native === null) {
                findings.push({
                    check: "hookedBuiltins",
                    marker: path,
                    severity: "unavailable",
                    detail: "Could not stringify " + path + " to compare it against native code.",
                });
            }
        }
    }

    function checkCrossRealm(win, findings) {
        // A pristine realm gives us a second opinion that a same-realm
        // hook cannot forge. Needs a DOM and same-origin iframes.
        const doc = win && win.document;
        if (!doc || typeof doc.createElement !== "function" || !doc.body) {
            findings.push({
                check: "crossRealm",
                marker: "noDocument",
                severity: "unavailable",
                detail: "No usable document; cannot build a pristine realm.",
            });
            return;
        }

        let frame = null;
        try {
            frame = doc.createElement("iframe");
            frame.setAttribute("aria-hidden", "true");
            frame.style.display = "none";
            doc.body.appendChild(frame);

            const other = frame.contentWindow;
            const pristineToString = resolvePath(other, "Function.prototype.toString");
            if (typeof pristineToString !== "function") {
                findings.push({
                    check: "crossRealm",
                    marker: "realmUnavailable",
                    severity: "unavailable",
                    detail: "Pristine realm produced no Function.prototype.toString; a CSP " +
                        "(frame-src) or sandbox probably blocked the iframe. Could not look " +
                        "is not the same as nothing found.",
                });
                return;
            }

            for (let i = 0; i < watch.length; i++) {
                const path = watch[i];
                const mine = resolvePath(win, path);
                if (typeof mine !== "function") continue;
                // Ask the *pristine* realm's toString about our function.
                if (looksNative(pristineToString, mine) === false) {
                    findings.push({
                        check: "crossRealm",
                        marker: path,
                        severity: "high",
                        detail: path + " fails the pristine-realm native check. This survives a " +
                            "hook that spoofs its own toString in the main realm.",
                    });
                }
            }
        } catch (e) {
            findings.push({
                check: "crossRealm",
                marker: "realmError",
                severity: "unavailable",
                detail: "Building the pristine realm threw: " + (e && e.message ? e.message : String(e)),
            });
        } finally {
            // Always clean up; leaving the probe iframe attached would
            // itself be an observable side effect.
            try {
                if (frame && frame.parentNode) frame.parentNode.removeChild(frame);
            } catch (e) { /* nothing useful to do */ }
        }
    }

    function checkAutomation(win, findings) {
        const nav = win && win.navigator;

        if (nav && nav.webdriver === true) {
            findings.push({
                check: "automation",
                marker: "navigator.webdriver",
                severity: "signal",
                detail: "navigator.webdriver is true, i.e. the page reports being driven. " +
                    "Trivially patchable, so treat as a signal rather than proof.",
            });
        }

        for (let i = 0; i < AUTOMATION_GLOBALS.length; i++) {
            const name = AUTOMATION_GLOBALS[i];
            let present = false;
            try {
                present = win ? (name in win) : false;
            } catch (e) {
                present = false;
            }
            if (present) {
                findings.push({
                    check: "automation",
                    marker: name,
                    severity: "signal",
                    detail: "Automation global '" + name + "' is present, which a driver " +
                        "injected and did not clean up.",
                });
            }
        }

        // Chrome DevTools Protocol drivers leave `cdc_`-prefixed keys on
        // window and document.
        const cdcHosts = [["window", win], ["document", win && win.document]];
        for (let h = 0; h < cdcHosts.length; h++) {
            const host = cdcHosts[h][1];
            if (!host) continue;
            let keys = [];
            try {
                keys = Object.getOwnPropertyNames(host);
            } catch (e) {
                keys = [];
            }
            for (let k = 0; k < keys.length; k++) {
                if (keys[k].indexOf("cdc_") === 0) {
                    findings.push({
                        check: "automation",
                        marker: cdcHosts[h][0] + "." + keys[k],
                        severity: "signal",
                        detail: "A cdc_-prefixed property indicates a ChromeDriver-family tool.",
                    });
                    break;   // one per host is enough evidence
                }
            }
        }
    }

    function inspect(win) {
        const findings = [];
        if (checks.indexOf("hookedBuiltins") !== -1) checkHookedBuiltins(win, findings);
        if (checks.indexOf("crossRealm") !== -1) checkCrossRealm(win, findings);
        if (checks.indexOf("automation") !== -1) checkAutomation(win, findings);

        let high = 0, signal = 0, unavailable = 0;
        for (let i = 0; i < findings.length; i++) {
            if (findings[i].severity === "high") high++;
            else if (findings[i].severity === "signal") signal++;
            else unavailable++;
        }

        // `ok` means "found nothing actionable". Unavailable checks do
        // NOT clear the report on their own, so a caller that only looks
        // at `ok` still learns that something could not be verified.
        const report = {
            ok: high === 0 && signal === 0,
            counts: { high: high, signal: signal, unavailable: unavailable },
            complete: unavailable === 0,
            findings: findings,
        };

        // Shaped for countermeasures.react(win, violation).
        report.violation = {
            reason: high > 0 ? "environment-hooked"
                : signal > 0 ? "automation-signal"
                : "environment-unverified",
            src: "environment-integrity",
            findings: findings,
        };
        return report;
    }

    function describe() {
        return {
            checks: checks.slice(),
            watch: watch.slice(),
        };
    }

    return {
        ALL_CHECKS: ALL_CHECKS.slice(),
        inspect: inspect,
        describe: describe,
    };
}

module.exports = {
    ALL_CHECKS: ALL_CHECKS.slice(),
    DEFAULT_WATCH: DEFAULT_WATCH.slice(),
    AUTOMATION_GLOBALS: AUTOMATION_GLOBALS.slice(),
    createEnvironmentIntegrityPolicy: createEnvironmentIntegrityPolicy,
};
