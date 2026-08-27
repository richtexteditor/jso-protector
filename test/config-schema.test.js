"use strict";

// Regression tests for jso.config.schema.json.
//
// Background: the schema declares `"additionalProperties": false`, so
// any documented config key that isn't in the schema is REJECTED by
// IDE validators (vscode-json-language-server, idea, etc.) and by the
// CLI's own --validate-config pass. The supply-chain-integrity surface
// (report / label / watermark / watermarkKey) shipped without schema
// entries, so customer configs using those keys produced spurious
// "Property X is not allowed" errors in editors.
//
// Pin every runtime-config key here so the bug can't silently
// regress. If a future flag becomes a config key, add it to this
// matrix and the schema in one PR.

const test    = require("node:test");
const assert  = require("node:assert");
const fs      = require("node:fs");
const path    = require("node:path");

const SCHEMA_PATH = path.resolve(__dirname, "..", "jso.config.schema.json");
const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

// Every config key read by mergeConfig() in bin/jso-protector.js. Source
// of truth: grep for `config\.\w+` in that function — these are the
// keys the runtime accepts and therefore the keys IDE schema validators
// must accept too.
const RUNTIME_CONFIG_KEYS = [
    // Auth + endpoint
    "endpoint", "apiKey", "apiPassword",
    // Project shape
    "projectName", "input", "output", "preset", "options", "webPreset",
    // File walking
    "extensions", "markupExtensions", "include", "exclude", "copyAssets",
    "assetExclude", "mixedServer", "reservedNames", "variableExclusion",
    // Source-handling switches
    "parseHtml", "honorConditionalComments", "protectMarkedComments",
    "ignoreImports", "keepHeaderComment", "protectObjectDeclaration",
    "moveNestedFunction", "formattedOutput", "keepIndent", "lineNumbers",
    "removeSourceMaps",
    // Lock convenience aliases
    "lockDomainSubdomains", "lockDomainMessage", "lockDate", "lockDateValue",
    "lockDateMessage",
    // Audit / reporting / supply-chain integrity (the keys this regression
    // test was originally added for):
    "manifest", "report", "label", "watermark", "watermarkKey",
    "maxOutputBytes", "maxGrowthRatio",
    // RASP + named sets (deep-research GAP 4):
    "countermeasures", "namedSets",
];

test("schema is parseable and has additionalProperties locked", () => {
    assert.equal(schema.additionalProperties, false,
        "Schema must remain strict — additionalProperties is the gate that " +
        "makes missing entries customer-visible. Don't relax it; add the key " +
        "to RUNTIME_CONFIG_KEYS and the schema instead.");
    assert.ok(schema.properties, "schema.properties exists");
});

test("every documented config key has a schema entry", () => {
    const missing = [];
    for (const key of RUNTIME_CONFIG_KEYS) {
        if (!(key in schema.properties)) missing.push(key);
    }
    assert.equal(missing.length, 0,
        "missing schema entries for documented config keys: " + JSON.stringify(missing));
});

test("supply-chain integrity keys have correct types", () => {
    // These four were the original bug — pin their exact shape.
    const cases = [
        ["report", "string"],
        ["label", "string"],
        ["watermark", "string"],
        ["watermarkKey", "string"],
    ];
    for (const [key, expectedType] of cases) {
        const entry = schema.properties[key];
        assert.ok(entry, "schema has property: " + key);
        // type can be a string or an array of strings.
        const types = Array.isArray(entry.type) ? entry.type : [entry.type];
        assert.ok(types.includes(expectedType),
            key + " type should include " + expectedType + ", got " + JSON.stringify(entry.type));
        assert.ok(entry.description && entry.description.length > 10,
            key + " has a non-trivial description");
    }
});

test("schema's manifest entry still has a non-trivial description", () => {
    // Sanity check: prove the schema file isn't truncated above where
    // the supply-chain entries live.
    assert.ok(schema.properties.manifest);
    assert.ok(schema.properties.manifest.description.length > 10);
});
