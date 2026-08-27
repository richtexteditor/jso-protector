"use strict";

// Named configuration sets - apply a different protection profile to
// different parts of one app in a single build.
//
// Inspired by JSDefender v2's named sets: e.g. a checkout flow gets
// maximum-mode + RASP countermeasures, marketing pages get standard
// preset + simple beacon. Both ship from one CI run.
//
// The config schema accepts:
//
//   {
//     "preset": "balanced",                 // baseline applied to ALL files
//     "options": { ... },                   // baseline options
//     "namedSets": {
//       "checkout": {
//         "match": ["src/checkout/**", "src/wallet/**"],
//         "preset": "maximum",
//         "options": { "AddDeadCode": true, "DeadcodeLevel": "High" },
//         "countermeasures": { "onTamper": ["break", "deleteCookies"] }
//       },
//       "marketing": {
//         "match": ["src/marketing/**"],
//         "preset": "standard"
//       }
//     }
//   }
//
// The resolver takes a list of file paths + the config and returns,
// per file, the *effective* preset + options + countermeasures. A
// file matched by multiple sets gets the FIRST listed set (config
// authors get deterministic precedence by writing sets in priority
// order, like CSS / route tables).
//
// Pure data-shaping: no I/O, no API calls. Easy to unit-test.

function resolveForFiles(config, files) {
    const namedSets = (config && config.namedSets) || {};
    const baselinePreset = (config && config.preset) || null;
    const baselineOptions = (config && config.options) || {};
    const setNames = Object.keys(namedSets);

    const out = {};
    for (const file of files) {
        let chosen = null;
        for (const name of setNames) {
            const set = namedSets[name];
            if (!set || !Array.isArray(set.match)) continue;
            for (const pattern of set.match) {
                if (matchGlob(pattern, file)) { chosen = { name: name, set: set }; break; }
            }
            if (chosen) break;
        }
        if (chosen) {
            out[file] = {
                set: chosen.name,
                preset: chosen.set.preset || baselinePreset,
                options: Object.assign({}, baselineOptions, chosen.set.options || {}),
                countermeasures: chosen.set.countermeasures || (config && config.countermeasures) || null,
            };
        } else {
            out[file] = {
                set: null,
                preset: baselinePreset,
                options: Object.assign({}, baselineOptions),
                countermeasures: (config && config.countermeasures) || null,
            };
        }
    }
    return out;
}

function resolveForFile(config, file) {
    return resolveForFiles(config, [file])[file];
}

// Minimal glob matcher: supports **, *, ?, character classes [a-z],
// and brace expansion {a,b}. POSIX-style forward slashes only (we
// normalise backslashes on input). No `picomatch` / `minimatch`
// runtime dependency.
function matchGlob(pattern, input) {
    const p = String(pattern).replace(/\\/g, "/");
    const s = String(input).replace(/\\/g, "/");
    // Expand braces first (one level).
    const expanded = expandBraces(p);
    for (const variant of expanded) {
        const re = globToRegExp(variant);
        if (re.test(s)) return true;
    }
    return false;
}

// Hard cap on total variants to prevent a malicious jso.config.json
// (e.g. 20 nested {a,b} groups = 1M variants) from DoS-ing the build.
const MAX_BRACE_VARIANTS = 256;

function expandBraces(pattern) {
    const m = pattern.match(/^([^{]*)\{([^{}]+)\}(.*)$/);
    if (!m) return [pattern];
    const prefix = m[1], parts = m[2].split(","), suffix = m[3];
    const out = [];
    for (const p of parts) {
        for (const tail of expandBraces(suffix)) {
            if (out.length >= MAX_BRACE_VARIANTS) {
                throw new Error(
                    "named-sets: glob brace expansion exceeded " + MAX_BRACE_VARIANTS +
                    " variants; simplify the pattern (got '" + pattern + "')"
                );
            }
            out.push(prefix + p + tail);
        }
    }
    return out;
}

function globToRegExp(glob) {
    // Build a regex incrementally so escaping is exact.
    let re = "^";
    let i = 0;
    while (i < glob.length) {
        const c = glob[i];
        // /** at end of pattern: matches the leading dir plus
        // ANY number of trailing segments (including zero, so
        // `src/**` matches both `src` and `src/x/y/z`).
        if (c === "/" && glob[i + 1] === "*" && glob[i + 2] === "*" && i + 3 === glob.length) {
            re += "(?:/.*)?";
            i += 3;
            continue;
        }
        // /**/ in the middle: matches zero or more intermediate
        // segments. `src/**/x.js` matches `src/x.js` AND
        // `src/a/b/c/x.js`.
        if (c === "/" && glob[i + 1] === "*" && glob[i + 2] === "*" && glob[i + 3] === "/") {
            re += "(?:/.*)?/";
            i += 4;
            continue;
        }
        if (c === "*" && glob[i + 1] === "*") {
            // Bare ** at start or alone: matches anything including slashes.
            re += ".*";
            i += 2;
            if (glob[i] === "/") i++;
            continue;
        }
        if (c === "*") {
            // *   matches anything except a slash
            re += "[^/]*";
            i++;
            continue;
        }
        if (c === "?") {
            re += "[^/]";
            i++;
            continue;
        }
        if (c === "[") {
            // pass through character class verbatim
            const close = glob.indexOf("]", i);
            if (close < 0) { re += "\\["; i++; continue; }
            re += glob.slice(i, close + 1);
            i = close + 1;
            continue;
        }
        // Escape regex specials. {} are included so a stray unmatched
        // brace (left over after expandBraces) can't be reinterpreted
        // as a quantifier-open by stricter regex engines.
        if (/[.+^$()|\\{}]/.test(c)) {
            re += "\\" + c;
            i++;
            continue;
        }
        re += c;
        i++;
    }
    re += "$";
    return new RegExp(re);
}

module.exports = {
    resolveForFile: resolveForFile,
    resolveForFiles: resolveForFiles,
    matchGlob: matchGlob,
    _globToRegExp: globToRegExp,
    _expandBraces: expandBraces,
};
