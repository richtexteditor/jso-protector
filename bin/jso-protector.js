#!/usr/bin/env node

"use strict";

const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const path = require("path");
const namedSetsResolver = require("../config/named-sets.js");
const { spawnSync } = require("child_process");
const Module = require("module");
const packageJson = require("../package.json");
const watermark = require("../watermark.js");
const releaseSigner = require("../release-signer.js");
const pciCompliance = require("../compliance/pci-dss-v4/index.js");

const DEFAULT_CONFIG_FILE = "jso.config.json";
const DEFAULT_CONFIG_FILES = ["jso.config.json", "jso.config.cjs", "jso.config.mjs", "jso.config.js"];
const DEFAULT_ENDPOINT = "https://javascriptobfuscator.com/HttpApi.ashx";
const DEFAULT_EXTENSIONS = [".js", ".jsx"];
const DEFAULT_MARKUP_EXTENSIONS = [".html", ".htm", ".php", ".phtml", ".asp", ".aspx", ".jsp", ".cshtml", ".vbhtml"];
const DEFAULT_EXCLUDE = ["**/*.map", "**/node_modules/**", "**/*-obfuscated.js"];
const DEFAULT_ASSET_EXCLUDE = ["**/*.map"];
const WEB_PRESET_FORMAT = "javascript-obfuscator-web-preset";
const CONDITIONAL_MARKER_PATTERN = /\/\/\s*javascript-obfuscator:(disable|enable)\b|\/\*\s*javascript-obfuscator:(disable|enable)\s*\*\//g;
const PROTECT_MARKER_PATTERN = /\/\/\s*javascript-obfuscator:protect-(begin|end)\b|\/\*\s*javascript-obfuscator:protect-(begin|end)\s*\*\//g;
const HTML_SCRIPT_PATTERN = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
const SOURCE_MAP_COMMENT_LINE_PATTERN = /^[ \t]*\/\/[#@]\s*sourceMappingURL=.*(?:\r?\n)?/gm;
const SOURCE_MAP_COMMENT_BLOCK_PATTERN = /[ \t]*\/\*[#@]\s*sourceMappingURL=[\s\S]*?\*\/[ \t]*(?:\r?\n)?/g;

const PRESET_OPTIONS = {
  standard: {
    EncodeStrings: true,
    MoveStrings: true,
    ReplaceNames: true,
    SelfCompression: true,
    CompressionRatio: "Best"
  },
  balanced: {
    IdentityStyle: "v2abcd",
    EncodeStrings: true,
    MoveStrings: true,
    ReplaceNames: true,
    SelfCompression: true,
    SelfCompressionMinSize: 0,
    CompressionRatio: "Best",
    DeepObfuscate: true,
    ReorderCode: true,
    EncryptStrings: true,
    FlatTransform: true
  },
  maximum: {
    IdentityStyle: "v2abcd",
    EncodeStrings: true,
    MoveStrings: true,
    ReplaceNames: true,
    RenameGlobals: true,
    RenameMembers: true,
    MoveMembers: true,
    SelfCompression: true,
    SelfCompressionMinSize: 0,
    CompressionRatio: "Best",
    DeepObfuscate: true,
    ReorderCode: true,
    AddDeadCode: true,
    DeadcodeLevel: "Low",
    EncryptStrings: true,
    FlatTransform: true
  }
};

const WEB_FEATURE_OPTIONS = {
  "Short Local Name": { IdentityStyle: "v2abcd" },
  "Compressor": { SelfCompression: true, SelfCompressionMinSize: 0, CompressionRatio: "Best" },
  "Deep Obfuscation": { DeepObfuscate: true },
  "Code Transposition": { ReorderCode: true },
  "Dead Code Insertion": { AddDeadCode: true, DeadcodeLevel: "Low" },
  "Encrypt Strings": { EncryptStrings: true },
  "Move Members": { MoveMembers: true },
  "Replace Globals": { RenameGlobals: true },
  "Protect Members": { RenameMembers: true },
  "Keep Header Comment": { KeepComment: true },
  "Move Strings": { MoveStrings: true },
  "Flat Transform": { FlatTransform: true },
  "Encode Strings": { EncodeStrings: true }
};

const JAVASCRIPT_OBFUSCATOR_MIGRATION_MAP = [
  { source: "optionsPreset", target: ["preset"], confidence: "approximate", note: "default/low and VM low/default presets map to standard, medium and VM medium map to balanced, and high plus stronger VM presets map to maximum." },
  { source: "stringArray", target: ["MoveStrings"], confidence: "direct", note: "Moves string literals into generated lookup structures." },
  { source: "stringArrayEncoding", target: ["EncodeStrings", "EncryptStrings"], confidence: "approximate", note: "rc4-style values map to encrypted strings; other values map to encoded strings." },
  { source: "stringArrayThreshold", target: ["StringArrayThreshold", "MoveStrings"], confidence: "direct", note: "Applies a seeded per-unique-literal probability from 0 through 1; zero disables moved strings." },
  { source: "stringArrayCallsTransform", target: ["StringArrayCallsTransform"], confidence: "direct", note: "Routes selected moved-string lookups through a generated secondary index table." },
  { source: "stringArrayCallsTransformThreshold", target: ["StringArrayCallsTransformThreshold"], confidence: "direct", note: "Applies a seeded per-lookup indirection probability from 0 through 1." },
  { source: "stringArrayWrappersCount", target: ["StringArrayWrappersCount"], confidence: "approximate", note: "Adds 0-10 root-level wrappers; competitor per-scope wrapper placement is not reproduced." },
  { source: "stringArrayWrappersChainedCalls", target: ["StringArrayWrappersChainedCalls"], confidence: "direct", note: "Controls whether generated wrappers delegate through the previous wrapper." },
  { source: "stringArrayWrappersParametersMaxCount", target: ["StringArrayWrappersParametersMaxCount"], confidence: "direct", note: "Bounds function-wrapper parameters from 2 through 5 and fills non-index arguments with noise values." },
  { source: "stringArrayWrappersType", target: ["StringArrayWrappersType"], confidence: "direct", note: "Supports variable aliases and function wrappers." },
  { source: "transformObjectKeys", target: ["TransformObjectKeys"], confidence: "approximate", note: "Moves safe identifier and quoted data keys into computed string-table lookups; numeric, method/accessor, shorthand-sensitive, and __proto__ keys remain literal." },
  { source: "stringArrayIndexShift", target: ["StringArrayIndexShift"], confidence: "approximate", note: "Adds a nonzero table offset; vendor-specific randomized shift magnitude is not reproduced." },
  { source: "stringArrayShuffle", target: ["StringArrayShuffle"], confidence: "direct", note: "Randomizes moved-string table order and rewrites every generated lookup." },
  { source: "stringArrayRotate", target: ["StringArrayRotate"], confidence: "direct", note: "Cyclically rotates moved-string table order by a per-build offset and rewrites every generated lookup." },
  { source: "stringArrayIndexesType", target: ["StringArrayIndexesType"], confidence: "direct", note: "Supports hexadecimal-number and hexadecimal-numeric-string lookup representations, including mixed lists." },
  { source: "unicodeEscapeSequence", target: ["EncodeStrings"], confidence: "approximate", note: "Maps to encoded strings." },
  { source: "controlFlowFlattening", target: ["FlatTransform", "DeepObfuscate"], confidence: "approximate", note: "Maps to deeper control-flow and flat-transform protection." },
  { source: "deadCodeInjection", target: ["AddDeadCode"], confidence: "direct", note: "Enables dead-code insertion." },
  { source: "deadCodeInjectionThreshold", target: ["DeadcodeLevel"], confidence: "approximate", note: "Threshold is converted to the nearest Low, Medium, or High level." },
  { source: "identifierNamesGenerator", target: ["IdentityStyle"], confidence: "approximate", note: "Hexadecimal maps to v1hex; other styles map to v2abcd." },
  { source: "renameGlobals", target: ["RenameGlobals"], confidence: "direct", note: "Enables global renaming." },
  { source: "renameProperties", target: ["RenameMembers"], confidence: "approximate", note: "Review public member access before enabling." },
  { source: "selfDefending", target: ["SelfDefending"], confidence: "direct", note: "Enables the hosted engine's self-integrity guard." },
  { source: "debugProtection", target: ["DebugProtection"], confidence: "direct", note: "Enables the hosted engine's debugger reaction guard." },
  { source: "debugProtectionInterval", target: ["DebugProtectionIntervalMilliseconds"], confidence: "direct", note: "Maps the millisecond interval; 0 disables periodic timing probes while retaining other enabled debug checks." },
  { source: "disableConsoleOutput", target: ["DisableConsoleOutput"], confidence: "direct", note: "Suppresses common browser console methods in protected output." },
  { source: "seed", target: ["Seed"], confidence: "direct", note: "Maps to deterministic engine entropy. The same input, options, and seed produce byte-identical output; omit it for per-build polymorphism." },
  { source: "reservedStrings", target: ["ReservedStrings"], confidence: "direct", note: "Preserves matching literals verbatim outside MoveStrings and EncodeStrings. Up to 100 regex patterns are accepted." },
  { source: "forceTransformStrings", target: ["ForceTransformStrings"], confidence: "direct", note: "Matching literals override ReservedStrings and pass through enabled string transforms." },
  { source: "splitStrings", target: ["SplitStrings"], confidence: "direct", note: "Splits eligible literals into fixed-length concatenated chunks." },
  { source: "splitStringsChunkLength", target: ["SplitStringsChunkLength"], confidence: "direct", note: "Sets a bounded chunk length from 1 through 1024; the engine default is 10." },
  { source: "numbersToExpressions", target: ["EncodeNumbers"], confidence: "approximate", note: "Obscures numeric literals with the native numeric encoder; generated expression shape is not preserved." },
  { source: "reservedNames", target: ["reservedNames", "VariableExclusion"], confidence: "direct", note: "Reserved name expressions are preserved." },
  { source: "domainLock", target: ["LockDomain", "LockDomainList"], confidence: "approximate", note: "Domain lock lists map to LockDomain and LockDomainList; review subdomain and redirect behavior." },
  { source: "domainLockRedirectUrl", target: ["LockDomainRedirectUrl"], confidence: "direct", note: "Maps to the domain-lock-specific safe redirect without changing reactions for other runtime defenses." },
  { source: "compact", target: ["SelfCompression", "CompressionRatio", "WriteFormats"], confidence: "approximate", note: "Compact true maps to compression; compact false maps to formatted output." },
  { source: "target", target: ["OptimizationMode"], confidence: "approximate", note: "browser maps to Web; node maps to NodeJS." },
  { source: "parseHtml", target: ["parseHtml"], confidence: "direct", note: "Protects marked <script data-javascript-obfuscator> blocks in HTML or template files." },
  { source: "ignoreImports", target: ["ignoreImports"], confidence: "approximate", note: "Preserves import/export-from statements and common static require/import() statements before sending the remaining code to the hosted API." }
];

const JS_CONFUSER_MIGRATION_MAP = [
  { source: "preset", target: ["preset"], confidence: "approximate", note: "JS-Confuser low/medium/high presets map to standard/balanced/maximum." },
  { source: "target", target: ["OptimizationMode"], confidence: "direct", note: "browser maps to Web; node maps to NodeJS." },
  { source: "renameVariables", target: ["ReplaceNames"], confidence: "approximate", note: "Variable renaming maps to local-name replacement." },
  { source: "renameGlobals", target: ["RenameGlobals"], confidence: "direct", note: "Enables global renaming." },
  { source: "globalConcealing", target: ["RenameGlobals"], confidence: "approximate", note: "Global concealing maps to global renaming; review runtime behavior." },
  { source: "stringEncoding", target: ["EncodeStrings"], confidence: "approximate", note: "String encoding maps to encoded strings." },
  { source: "stringConcealing", target: ["EncryptStrings"], confidence: "approximate", note: "String concealing maps to encrypted strings." },
  { source: "duplicateLiteralsRemoval", target: ["MoveStrings"], confidence: "approximate", note: "Duplicate literal removal maps to moved string storage." },
  { source: "stringSplitting", target: ["SplitStrings"], confidence: "approximate", note: "Boolean/numeric enablement maps to fixed-length splitting; probability values collapse to enabled/disabled and custom selector functions require review." },
  { source: "stringCompression", target: ["SelfCompression", "CompressionRatio"], confidence: "approximate", note: "String compression maps to self-compression." },
  { source: "compact", target: ["SelfCompression", "CompressionRatio", "WriteFormats"], confidence: "approximate", note: "Compact output maps to self-compression; false maps to formatted output." },
  { source: "minify", target: ["SelfCompression", "CompressionRatio", "WriteFormats"], confidence: "approximate", note: "Minify maps to self-compression; false maps to formatted output." },
  { source: "controlFlowFlattening", target: ["FlatTransform", "DeepObfuscate"], confidence: "approximate", note: "Maps to deeper control-flow and flat-transform protection." },
  { source: "deadCode", target: ["AddDeadCode"], confidence: "direct", note: "Enables dead-code insertion." },
  { source: "identifierGenerator", target: ["IdentityStyle"], confidence: "approximate", note: "Hexadecimal generators map to v1hex; other styles map to v2abcd." },
  { source: "hexadecimalNumbers", target: ["EncodeNumbers"], confidence: "approximate", note: "Obscures numeric literals with the native numeric encoder; hexadecimal formatting is not guaranteed." },
  { source: "lock.domainLock", target: ["LockDomain", "LockDomainList"], confidence: "approximate", note: "Domain lock maps to LockDomain and LockDomainList; review subdomain behavior." },
  { source: "lock.endDate", target: ["LockDate", "LockDateValue"], confidence: "approximate", note: "End-date lock maps to LockDate and yyyyMMdd LockDateValue." },
  { source: "lock.startDate", target: ["LockStartDate", "LockStartDateValue"], confidence: "approximate", note: "Start-date lock maps to the native browser activation boundary." },
  { source: "lock.antiDebug", target: ["DebugProtection"], confidence: "approximate", note: "Boolean/numeric enablement maps to the native debugger guard; probability values collapse to enabled/disabled." },
  { source: "lock.integrity", target: ["SelfDefending"], confidence: "approximate", note: "Boolean/numeric enablement maps to native integrity monitoring; probability values collapse to enabled/disabled." },
  { source: "lock.selfDefending", target: ["SelfDefending"], confidence: "approximate", note: "Boolean/numeric enablement maps to native self-integrity monitoring." },
  { source: "lock.tamperProtection", target: ["AntiMonkeyPatching"], confidence: "approximate", note: "Boolean/numeric enablement maps to native security-relevant global integrity checks." }
];

const JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS = {
  identifiersDictionary: "Custom identifier dictionaries are not exposed by the hosted API workflow; review naming requirements manually.",
  identifiersPrefix: "Global identifier prefixes are not exposed by the hosted API workflow; review multi-file naming requirements manually.",
  identifierNamesCache: "Identifier-name cache files are not emitted by the hosted API workflow; review deterministic rename requirements manually.",
  identifierNamesCachePath: "Identifier-name cache files are not emitted by the hosted API workflow; remove cache-file assumptions from release scripts.",
  inputFileName: "Review source-map input file naming manually; the hosted API workflow protects named request items.",
  log: "Review logging needs in CI; use --json, --dry-run, --doctor, and manifests for structured release output.",
  renamePropertiesMode: "Review property rename mode manually before enabling RenameMembers.",
  simplify: "Simplify is accepted for migration compatibility; review whether hosted API compression and formatting options meet the same goal.",
  sourceMap: "Do not publish source maps with protected release output unless your release policy allows it.",
  sourceMapBaseUrl: "Source maps are not emitted by the hosted API workflow; review release source-map policy.",
  sourceMapFileName: "Source maps are not emitted by the hosted API workflow; review release source-map policy.",
  sourceMapMode: "Review source map handling manually.",
  sourceMapSourcesMode: "Source maps are not emitted by the hosted API workflow; review release source-map policy.",
  strictMode: "Review strict-mode assumptions manually; the hosted API workflow auto-detects runtime semantics from submitted code.",
};

const JS_CONFUSER_REVIEW_OPTIONS = {
  "lock.countermeasures": "Review runtime countermeasure behavior manually.",
  "lock.customLocks": "Custom runtime locks need manual review.",
  astScrambler: "AST scrambling has no direct hosted API mapping; review output manually.",
  calculator: "Calculator transforms have no direct hosted API mapping; review output manually.",
  dispatcher: "Dispatcher control-flow transforms have no direct hosted API mapping; review output manually.",
  flatten: "Function flattening has no direct hosted API mapping; review output manually.",
  movedDeclarations: "Moved declaration behavior has no direct hosted API mapping; review output manually.",
  objectExtraction: "Object extraction has no direct hosted API mapping; review output manually.",
  opaquePredicates: "Opaque predicate transforms have no direct hosted API mapping; review output manually.",
  pack: "Packing/runtime loader behavior has no direct hosted API mapping; review distribution changes manually.",
  preserveFunctionLength: "Function-length preservation needs manual review.",
  renameLabels: "Label renaming has no direct hosted API mapping; review output manually.",
  rgf: "RGF transforms have no direct hosted API mapping; review output manually.",
  shuffle: "Shuffle transforms have no direct hosted API mapping; review output manually.",
  variableMasking: "Variable masking has no direct hosted API mapping; review output manually."
};

const JS_CONFUSER_CONFIG_REVIEW_FIELDS = {
  jsConfuserLockCountermeasures: "Preserved JS-Confuser lock.countermeasures value for manual review."
};

const JS_CONFUSER_CONFIG_MAPPED_FIELDS = [
  "jsConfuserLockAntiDebug",
  "jsConfuserLockIntegrity",
  "jsConfuserLockSelfDefending",
  "jsConfuserLockStartDate",
  "jsConfuserLockTamperProtection"
];

const JS_CONFUSER_CONFIG_REVIEW_FIELD_TYPES = {
  jsConfuserLockAntiDebug: "booleanOrNonNegativeNumber",
  jsConfuserLockIntegrity: "booleanOrNonNegativeNumber",
  jsConfuserLockSelfDefending: "booleanOrNonNegativeNumber",
  jsConfuserLockStartDate: "string",
  jsConfuserLockCountermeasures: "string",
  jsConfuserLockTamperProtection: "booleanOrNonNegativeNumber"
};

const RUNTIME_DEFENSE_REVIEW_FIELDS = [
  ...Object.keys(JS_CONFUSER_CONFIG_REVIEW_FIELDS)
];

const RUNTIME_DEFENSE_REVIEW_OPTIONS = [
  ...RUNTIME_DEFENSE_REVIEW_FIELDS,
  "lock.antiDebug",
  "lock.countermeasures",
  "lock.customLocks",
  "lock.integrity",
  "lock.selfDefending",
  "lock.startDate",
  "lock.tamperProtection"
];

const COMPETITOR_LIMITATION_GROUPS = [
  {
    id: "source-maps",
    fields: ["sourceMap", "sourceMapBaseUrl", "sourceMapFileName", "sourceMapMode", "sourceMapSourcesMode"],
    title: "Source maps are not emitted",
    message: "The hosted API workflow removes release source maps instead of generating new protected maps.",
    recommendation: "Keep source maps out of protected artifacts or switch to the desktop/local workflow when protected maps are mandatory."
  },
  {
    id: "identifier-name-cache",
    fields: ["identifierNamesCache", "identifierNamesCachePath"],
    title: "Identifier cache files are not emitted",
    message: "Deterministic identifier-name cache files are not available through the hosted API workflow.",
    recommendation: "Remove cache-file assumptions from release scripts and review any cross-build naming expectations manually."
  },
  {
    id: "custom-identifier-dictionary",
    fields: ["identifiersDictionary", "identifiersPrefix"],
    title: "Custom naming dictionaries are not supported",
    message: "Hosted API naming controls do not expose the same custom dictionary or prefix behavior used by some npm-first obfuscators.",
    recommendation: "Review naming-sensitive integrations before release and avoid assuming dictionary-driven output."
  },
  {
    id: "runtime-self-defending",
    fields: [
      "debugProtection",
      "selfDefending",
      "jsConfuserLockAntiDebug",
      "jsConfuserLockIntegrity",
      "jsConfuserLockSelfDefending",
      "jsConfuserLockStartDate",
      "jsConfuserLockCountermeasures",
      "jsConfuserLockTamperProtection"
    ],
    title: "Runtime defense settings need manual review",
    message: "JSO ships runtime monitoring and countermeasure helpers, but competitor anti-debug, integrity, self-defending, and related runtime lock switches do not map one-to-one to this hosted API workflow.",
    recommendation: "Treat these settings as migration notes, map runtime requirements to the JSO runtime defense helpers where appropriate, and validate behavior before release."
  }
];

const COMPETITOR_CAPABILITY_MATRIX = [
  {
    id: "control-flow",
    capability: "Control-flow flattening",
    competitorExamples: ["Obfuscator.io", "javascript-obfuscator", "Jscrambler", "JSDefender"],
    status: "covered",
    jsoSupport: "Use preset=balanced/maximum or options.FlatTransform plus options.DeepObfuscate.",
    evidence: ["controlFlowFlattening", "FlatTransform", "DeepObfuscate"]
  },
  {
    id: "string-hiding",
    capability: "String hiding and encryption",
    competitorExamples: ["Obfuscator.io", "javascript-obfuscator", "Jscrambler", "JS-Confuser"],
    status: "covered",
    jsoSupport: "Use MoveStrings, EncodeStrings, and EncryptStrings.",
    evidence: ["stringArray", "MoveStrings", "EncodeStrings", "EncryptStrings"]
  },
  {
    id: "dead-code",
    capability: "Dead-code insertion",
    competitorExamples: ["Obfuscator.io", "javascript-obfuscator", "Jscrambler", "JS-Confuser"],
    status: "covered",
    jsoSupport: "Use AddDeadCode and DeadcodeLevel through maximum preset or explicit options.",
    evidence: ["deadCodeInjection", "AddDeadCode", "DeadcodeLevel"]
  },
  {
    id: "locks",
    capability: "Domain and expiry locks",
    competitorExamples: ["Obfuscator.io", "Jscrambler", "JS-Confuser", "javascript-obfuscator"],
    status: "partial",
    jsoSupport: "Domain, start-date, end-date, browser, and OS allowlists ship through LockDomain, LockStartDate, LockDate, LockBrowser, and LockOS. Browser/OS classification uses spoofable runtime signals; custom countermeasure functions remain a manual-review gap.",
    evidence: ["domainLock", "lock.domainLock", "lock.endDate", "lock.startDate", "lock.countermeasures"]
  },
  {
    id: "runtime-defense",
    capability: "Self-defending, anti-debug, and tamper/integrity reactions",
    competitorExamples: ["Obfuscator.io", "Jscrambler", "JSDefender", "JS-Confuser", "javascript-obfuscator"],
    status: "partial",
    jsoSupport: "javascript-obfuscator selfDefending, debugProtection, and bounded debugProtectionInterval settings map directly to JSO runtime options. Bounded page-realm integrity scheduling, dotted callback dispatch, hosted dashboard intake, and beacon forwarding provide customer-owned reactions and evidence; arbitrary vendor countermeasure functions and vendor-specific integrity semantics still require explicit review and runtime proof.",
    evidence: ["SelfDefendingIntervalSeconds", "DebugProtectionIntervalMilliseconds", "RuntimeDefenseCallback", "RuntimeDefenseBeaconUrl", "dashboard-monitoring", "jso-beacon-slack", "runtime/countermeasures", "selfDefending", "debugProtection", "debugProtectionInterval", "lock.antiDebug", "lock.integrity", "lock.selfDefending", "lock.tamperProtection"]
  },
  {
    id: "release-forensics",
    capability: "Release attribution, watermarking, and artifact verification",
    competitorExamples: ["commercial client-side protection suites"],
    status: "covered",
    jsoSupport: "Use --label, --report, --watermark/--scan-watermarks, --sign-release, and --verify-release.",
    evidence: ["label", "report", "watermark", "sign-release", "verify-release"]
  },
  {
    id: "source-maps",
    capability: "Protected source-map and identifier-cache workflows",
    competitorExamples: ["Obfuscator.io", "javascript-obfuscator"],
    status: "gap",
    jsoSupport: "Hosted API releases intentionally remove source maps and do not emit identifier-name caches.",
    evidence: ["sourceMap", "identifierNamesCache", "identifierNamesCachePath"]
  },
  {
    id: "vm-bytecode",
    capability: "Selective JavaScript bytecode virtualization",
    competitorExamples: ["Obfuscator.io Pro", "Jscrambler", "enterprise application-protection vendors"],
    status: "partial",
    jsoSupport: "Use UseVMProtection with @virtualize-marked functions and retain the VM proof pack. JSO plan eligibility starts at Corporate, but production access remains a staged beta and unsupported function shapes fall back with an explicit warning.",
    evidence: ["UseVMProtection", "@virtualize", "VMProtectionApplied", "vm-proof-pack-report"]
  },
  {
    id: "vm-runtime-hardening",
    capability: "VM runtime hardening and anti-analysis controls",
    competitorExamples: ["Obfuscator.io Pro", "JSDefender", "Jscrambler"],
    status: "partial",
    jsoSupport: "JSO combines per-build VM output with SelfDefending, AntiMonkeyPatching, DebugProtection, signed runtime envelopes, and customer-owned telemetry. It does not claim parity with every vendor-specific stateful-opcode, encoded-jump, encoded-stack, or anti-analysis implementation without side-by-side proof.",
    evidence: ["SelfDefending", "AntiMonkeyPatching", "DebugProtection", "RuntimeSigningPublicKey", "RuntimeDefenseBeaconUrl"]
  }
];

const COMPETITOR_SOURCE_SNAPSHOT = {
  reviewedOn: "2026-08-02",
  basis: "Public competitor product, documentation, marketplace, API, and platform pages reviewed for migration-positioning context.",
  sources: [
    { competitor: "Obfuscator.io", label: "Pricing", url: "https://obfuscator.io/pricing" },
    { competitor: "Obfuscator.io", label: "API docs", url: "https://obfuscator.io/docs/api" },
    { competitor: "javascript-obfuscator", label: "GitHub README and Obfuscator.io Pro VM option reference", url: "https://github.com/javascript-obfuscator/javascript-obfuscator" },
    { competitor: "JS-Confuser", label: "Options docs", url: "https://js-confuser.com/docs/options" },
    { competitor: "Jscrambler", label: "GitHub CI integration", url: "https://docs.jscrambler.com/code-integrity/documentation/github-ci-integration" },
    { competitor: "AfterPack", label: "Product page", url: "https://www.afterpack.dev/" },
    { competitor: "JSDefender", label: "Product page", url: "https://www.preemptive.com/products/jsdefender/" },
    { competitor: "Digital.ai", label: "Web application security", url: "https://digital.ai/products/application-security/application-security-for-web/" }
  ],
  claimBoundary: "Use this report for migration triage, not as a live competitor capability guarantee. Re-check current vendor pages before publishing named competitive claims."
};

const JS_CONFUSER_DETECT_KEYS = [
  "astScrambler",
  "calculator",
  "deadCode",
  "dispatcher",
  "duplicateLiteralsRemoval",
  "flatten",
  "globalConcealing",
  "hexadecimalNumbers",
  "identifierGenerator",
  "lock",
  "minify",
  "movedDeclarations",
  "objectExtraction",
  "opaquePredicates",
  "pack",
  "preserveFunctionLength",
  "renameLabels",
  "renameVariables",
  "rgf",
  "shuffle",
  "stringCompression",
  "stringConcealing",
  "stringEncoding",
  "stringSplitting",
  "variableMasking"
];

const JAVASCRIPT_OBFUSCATOR_REVIEW_OPTION_TYPES = {
  debugProtection: "boolean",
  forceTransformStrings: "stringArray",
  identifiersDictionary: "stringArray",
  identifiersPrefix: "string",
  identifierNamesCache: "objectOrNull",
  identifierNamesCachePath: "string",
  inputFileName: "string",
  log: "boolean",
  numbersToExpressions: "boolean",
  renamePropertiesMode: "string",
  reservedStrings: "stringArray",
  seed: "stringOrNumber",
  selfDefending: "boolean",
  simplify: "boolean",
  sourceMap: "boolean",
  sourceMapBaseUrl: "string",
  sourceMapFileName: "string",
  sourceMapMode: "string",
  sourceMapSourcesMode: "string",
  strictMode: "booleanOrNull",
  splitStrings: "boolean",
  splitStringsChunkLength: "nonNegativeNumber",
  stringArrayCallsTransform: "boolean",
  stringArrayCallsTransformThreshold: "nonNegativeNumber",
  stringArrayIndexShift: "boolean",
  stringArrayShuffle: "boolean",
  stringArrayRotate: "boolean",
  stringArrayIndexesType: "stringOrStringArray",
  stringArrayRotate: "boolean",
  stringArrayShuffle: "boolean",
  stringArrayWrappersChainedCalls: "boolean",
  stringArrayWrappersCount: "nonNegativeNumber",
  stringArrayWrappersParametersMaxCount: "nonNegativeNumber",
  stringArrayWrappersType: "string",
  ignoreImports: "boolean",
  transformObjectKeys: "boolean"
};

const OPTION_REFERENCE = [
  { name: "EncodeStrings", type: "boolean", category: "strings", description: "Encode string literals." },
  { name: "MoveStrings", type: "boolean", category: "strings", description: "Move string literals into a generated lookup structure." },
  { name: "SplitStrings", type: "boolean", category: "strings", description: "Split eligible string literals into fixed-length concatenated chunks." },
  { name: "SplitStringsChunkLength", type: "number", category: "strings", description: "String chunk length from 1 through 1024; defaults to 10." },
  { name: "StringArrayIndexShift", type: "boolean", category: "strings", description: "Offset moved-string table references by one nonzero slot." },
  { name: "StringArrayShuffle", type: "boolean", category: "strings", description: "Randomize moved-string table order while preserving generated lookups." },
  { name: "StringArrayRotate", type: "boolean", category: "strings", description: "Cyclically rotate moved-string table order by a per-build offset." },
  { name: "StringArrayIndexesType", type: "string", category: "strings", values: ["hexadecimal-number", "hexadecimal-numeric-string"], description: "Choose one or both hexadecimal moved-string lookup representations." },
  { name: "StringArrayThreshold", type: "number", category: "strings", description: "Move each unique eligible literal with probability 0 through 1." },
  { name: "StringArrayCallsTransform", type: "boolean", category: "strings", description: "Route selected moved-string lookups through a secondary index table." },
  { name: "StringArrayCallsTransformThreshold", type: "number", category: "strings", description: "Secondary index-indirection probability from 0 through 1." },
  { name: "StringArrayWrappersCount", type: "number", category: "strings", description: "Generate 0-10 root-level string-table wrappers." },
  { name: "StringArrayWrappersChainedCalls", type: "boolean", category: "strings", description: "Delegate each wrapper through the previous wrapper." },
  { name: "StringArrayWrappersParametersMaxCount", type: "number", category: "strings", description: "Function-wrapper parameter ceiling from 2 through 5." },
  { name: "StringArrayWrappersType", type: "string", category: "strings", values: ["variable", "function"], description: "Generate variable aliases or multi-parameter function wrappers." },
  { name: "TransformObjectKeys", type: "boolean", category: "strings", description: "Move safe object-literal data keys into computed string-table lookups." },
  { name: "ReservedStrings", type: "string", category: "strings", description: "Newline-delimited regex patterns for literals kept verbatim outside move/encode transforms." },
  { name: "ForceTransformStrings", type: "string", category: "strings", description: "Newline-delimited regex patterns that override ReservedStrings for matching literals." },
  { name: "EncryptStrings", type: "boolean", category: "strings", description: "Encrypt strings for stronger string hiding." },
  { name: "ReplaceNames", type: "boolean", category: "names", description: "Rename local JavaScript identifiers." },
  { name: "RenameGlobals", type: "boolean", category: "names", description: "Rename global identifiers more aggressively." },
  { name: "RenameMembers", type: "boolean", category: "names", description: "Rename JavaScript members more aggressively." },
  { name: "MoveMembers", type: "boolean", category: "members", description: "Move object members into generated lookup structures." },
  { name: "VariableExclusion", type: "string", category: "names", description: "Multiline regular-expression list for names that must be preserved." },
  { name: "IdentityStyle", type: "enum", values: ["v1hex", "v2abcd"], category: "names", description: "Generated identifier style." },
  { name: "SelfCompression", type: "boolean", category: "compression", description: "Compress protected JavaScript output." },
  { name: "SelfCompressionMinSize", type: "number", category: "compression", description: "Minimum size threshold for compression." },
  { name: "CompressionRatio", type: "enum", values: ["Auto", "Low", "Medium", "High", "Best"], category: "compression", description: "Compression strength." },
  { name: "DeepObfuscate", type: "boolean", category: "control-flow", description: "Apply deeper obfuscation transforms." },
  { name: "ReorderCode", type: "boolean", category: "control-flow", description: "Reorder JavaScript source code." },
  { name: "FlatTransform", type: "boolean", category: "control-flow", description: "Apply flat transform protection." },
  { name: "AddDeadCode", type: "boolean", category: "control-flow", description: "Insert dead code." },
  { name: "DeadcodeLevel", type: "enum", values: ["Low", "Medium", "High"], category: "control-flow", description: "Dead-code insertion level." },
  { name: "OptimizationMode", type: "enum", values: ["Auto", "Web", "Html5", "Game", "Mobile", "NodeJS"], category: "runtime", description: "Runtime optimization target." },
  { name: "TargetVersion", type: "enum", values: ["es5", "modern"], category: "output", description: "Output syntax target. es5 (default) down-levels ES2015+ syntax for legacy browsers; modern keeps classes, arrows, destructuring and native for-of. Do not use modern if you must support pre-ES2015 browsers." },
  { name: "DownlevelIteration", type: "boolean", category: "output", description: "Spec-faithful ES5 for-of lowering: iterables are stepped lazily and iterator return() runs on break/throw, like TypeScript's downlevelIteration. Off by default because it adds a per-step call on arrays; no effect when TargetVersion is modern." },
  { name: "WriteFormats", type: "boolean", category: "formatting", description: "Write formatted output for debugging." },
  { name: "WriteFormats_KeepIndent", type: "boolean", category: "formatting", description: "Keep indentation when formatted output is enabled." },
  { name: "WriteFormats_LineNumbers", type: "boolean", category: "formatting", description: "Add line numbers when formatted output is enabled." },
  { name: "LockDomain", type: "boolean", category: "locks", description: "Enable domain locking." },
  { name: "LockDomainSubs", type: "boolean", category: "locks", description: "Allow subdomains in domain locking." },
  { name: "LockDomainList", type: "string", category: "locks", description: "Allowed domain list for domain locking." },
  { name: "LockDomainMsg", type: "string", category: "locks", description: "Message shown when domain locking fails." },
  { name: "LockDomainRedirectUrl", type: "string", category: "locks", description: "Domain-lock-specific HTTP(S) or root-relative redirect target." },
  { name: "LockDate", type: "boolean", category: "locks", description: "Enable date locking." },
  { name: "LockDateValue", type: "string", category: "locks", description: "Lock date in yyyyMMdd format." },
  { name: "LockDateMsg", type: "string", category: "locks", description: "Message shown when date locking fails." },
  { name: "LockStartDate", type: "boolean", category: "locks", description: "Prevent protected code from running before its activation date." },
  { name: "LockStartDateValue", type: "string", category: "locks", description: "Activation date in yyyyMMdd format." },
  { name: "LockStartDateMsg", type: "string", category: "locks", description: "Message used when the start-date lock fails." },
  { name: "LockBrowser", type: "boolean", category: "locks", description: "Restrict browser execution using user-agent classification." },
  { name: "LockBrowserList", type: "string", category: "locks", description: "Allowed browsers: chrome, edge, firefox, safari, opera, ie." },
  { name: "LockBrowserMsg", type: "string", category: "locks", description: "Message used when the browser lock fails." },
  { name: "LockOS", type: "boolean", category: "locks", description: "Restrict operating-system execution using browser runtime signals." },
  { name: "LockOSList", type: "string", category: "locks", description: "Allowed operating systems: windows, macos, linux, android, ios." },
  { name: "LockOSMsg", type: "string", category: "locks", description: "Message used when the operating-system lock fails." },
  { name: "SelfDefending", type: "boolean", category: "runtime-defense", description: "Enable protected-source integrity checks." },
  { name: "DebugProtectionIntervalMilliseconds", type: "number", category: "runtime-defense", description: "Debug timing probe interval: 0 disables periodic probes; otherwise 100 through 60000 milliseconds." },
  { name: "SelfDefendingIntervalSeconds", type: "number", category: "runtime-defense", description: "Repeat self-defending integrity checks every 1 through 86400 seconds; omit for invocation-only checks." },
  { name: "SelfHealing", type: "boolean", category: "runtime-defense", description: "Enable bounded local recovery after a self-defending check fails." },
  { name: "SelfHealingMaxAttempts", type: "number", category: "runtime-defense", description: "Limit local recovery attempts from 1 through 10." },
  { name: "AntiMonkeyPatching", type: "boolean", category: "runtime-defense", description: "Detect replacement of selected browser APIs." },
  { name: "AntiMonkeyPatchingCleanRealm", type: "boolean", category: "runtime-defense", description: "Compare startup APIs with a same-origin clean realm." },
  { name: "AntiMonkeyPatchingIncludeGlobals", type: "string", category: "runtime-defense", description: "Additional dotted API paths to monitor." },
  { name: "AntiMonkeyPatchingExcludeGlobals", type: "string", category: "runtime-defense", description: "Dotted API paths to omit from monitoring." },
  { name: "RuntimeDefenseAction", type: "enum", values: ["throw", "blank", "redirect", "reload", "callback", "degrade"], category: "runtime-defense", description: "Action taken after runtime defense trips and recovery is unavailable." },
  { name: "RuntimeDefenseCallback", type: "string", category: "runtime-defense", description: "Dotted global callback path receiving runtime-defense events." },
  { name: "RuntimeDefenseRedirectUrl", type: "string", category: "runtime-defense", description: "HTTP(S) or root-relative target used by the redirect action." }
];

const CONVENIENCE_OPTION_ALIASES = [
  { configKey: "targetVersion", optionName: "TargetVersion", type: "string" },
  { configKey: "downlevelIteration", optionName: "DownlevelIteration", type: "boolean" },
  { configKey: "keepHeaderComment", optionName: "KeepComment", type: "boolean" },
  { configKey: "protectObjectDeclaration", optionName: "ReorderCodeObjectDeclare", type: "boolean" },
  { configKey: "moveNestedFunction", optionName: "MoveNested", type: "boolean" },
  { configKey: "formattedOutput", optionName: "WriteFormats", type: "boolean" },
  { configKey: "keepIndent", optionName: "WriteFormats_KeepIndent", type: "boolean" },
  { configKey: "lineNumbers", optionName: "WriteFormats_LineNumbers", type: "boolean" },
  { configKey: "lockDomainSubdomains", optionName: "LockDomainSubs", type: "boolean" },
  { configKey: "lockDomainMessage", optionName: "LockDomainMsg", type: "string" },
  { configKey: "lockDate", optionName: "LockDate", type: "boolean" },
  { configKey: "lockDateValue", optionName: "LockDateValue", type: "string" },
  { configKey: "lockDateMessage", optionName: "LockDateMsg", type: "string" },
  { configKey: "selfHealing", optionName: "SelfHealing", type: "boolean" },
  { configKey: "selfHealingMaxAttempts", optionName: "SelfHealingMaxAttempts", type: "number" },
  { configKey: "antiMonkeyPatching", optionName: "AntiMonkeyPatching", type: "boolean" },
  { configKey: "antiMonkeyPatchingCleanRealm", optionName: "AntiMonkeyPatchingCleanRealm", type: "boolean" },
  { configKey: "antiMonkeyPatchingIncludeGlobals", optionName: "AntiMonkeyPatchingIncludeGlobals", type: "string" },
  { configKey: "antiMonkeyPatchingExcludeGlobals", optionName: "AntiMonkeyPatchingExcludeGlobals", type: "string" },
  { configKey: "runtimeDefenseAction", optionName: "RuntimeDefenseAction", type: "string" },
  { configKey: "selfDefendingIntervalSeconds", optionName: "SelfDefendingIntervalSeconds", type: "number" },
  { configKey: "debugProtectionIntervalMilliseconds", optionName: "DebugProtectionIntervalMilliseconds", type: "number" },
  { configKey: "runtimeDefenseCallback", optionName: "RuntimeDefenseCallback", type: "string" },
  { configKey: "runtimeDefenseRedirectUrl", optionName: "RuntimeDefenseRedirectUrl", type: "string" },
  { configKey: "seed", optionName: "Seed", type: "string" }
];

const INIT_TEMPLATE_CONFIGS = {
  "browser-app": {
    projectName: "browser-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js", ".jsx"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "html-app": {
    projectName: "html-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js", ".jsx"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: true,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "node-app": {
    projectName: "node-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js", ".cjs", ".mjs"],
    exclude: ["**/*.map", "**/node_modules/**", "**/*-obfuscated.js"],
    copyAssets: false,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: true,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "NodeJS",
      LockDomain: false,
      LockDate: false
    }
  },
  "electron-app": {
    projectName: "electron-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js", ".cjs", ".mjs"],
    exclude: ["**/*.map", "**/node_modules/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: true,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: true,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "NodeJS",
      LockDomain: false,
      LockDate: false
    }
  },
  "nextjs-app": {
    projectName: "nextjs-release",
    input: ".next/static",
    output: ".next/static-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/webpack-*.js", "**/polyfills-*.js", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^__NEXT_DATA__$", "^webpackChunk_N_E$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "vite-app": {
    projectName: "vite-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^import_meta_env$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "parcel-app": {
    projectName: "parcel-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^parcelRequire.*$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "bun-app": {
    projectName: "bun-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js", ".mjs"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^Bun$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "browserify-app": {
    projectName: "browserify-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^require$", "^module$", "^exports$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "webpack-app": {
    projectName: "webpack-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^webpackChunk.*$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "rspack-app": {
    projectName: "rspack-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^webpackChunk.*$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "turbopack-app": {
    projectName: "turbopack-release",
    input: ".next/static",
    output: ".next/static-protected",
    preset: "balanced",
    include: ["chunks/*.js", "chunks/**/*.js"],
    extensions: [".js"],
    exclude: ["**/*.map", "**/webpack-*.js", "**/polyfills-*.js", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^__NEXT_DATA__$", "^webpackChunk_N_E$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  },
  "react-native-app": {
    projectName: "react-native-release",
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    extensions: [".js"],
    exclude: ["**/*.map", "**/*-obfuscated.js"],
    copyAssets: false,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    keepHeaderComment: true,
    protectObjectDeclaration: false,
    moveNestedFunction: false,
    formattedOutput: false,
    keepIndent: false,
    lineNumbers: false,
    reservedNames: ["^__r$", "^__d$", "^__DEV__$", "^PublicApi$", "^keep_"],
    options: {
      OptimizationMode: "Mobile",
      LockDomain: false,
      LockDate: false
    }
  }
};

function printHelp() {
  process.stdout.write(`jso-protector

Usage:
  jso-protector --config jso.config.json
  jso-protector --input dist --output dist-protected
  jso-protector --stdin --stdout --file-name app.js
  jso-protector --preset balanced --input dist --output dist-protected
  jso-protector --migrate-javascript-obfuscator javascript-obfuscator.json --output jso.config.json
  jso-protector --migrate-javascript-obfuscator javascript-obfuscator.config.cjs --output jso.config.json
  jso-protector --migrate-js-confuser js-confuser.config.cjs --output jso.config.json
  jso-protector --ai-resistance-evidence dist-protected/jso-report.json --ai-resistance-evidence-output reports/ai-resistance-evidence.md
  jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md
  jso-protector --deployment-hygiene-evidence _temp/archive-hygiene.json --deployment-hygiene-output reports/deployment-hygiene.md
  jso-protector --runtime-incident-evidence reports/runtime-incidents.json --runtime-incident-evidence-output reports/runtime-incident-evidence.md
  jso-protector --vm-proof-pack dist-protected/jso-report.json --vm-proof-output reports/vm-proof-pack.md
  jso-protector --migration-review --migration-review-output reports/migration-review.md
  jso-protector --runtime-defense-review --runtime-defense-review-output reports/runtime-defense-review.md
  jso-protector --script-inventory-from-snapshot reports/runtime-inventory.json --script-inventory-output reports/payment-script-inventory.json
  jso-protector --payment-page-headers-from-har reports/checkout.har --payment-page-headers-baseline reports/payment-page-headers.baseline.json --payment-page-headers-output reports/payment-page-headers.json
  jso-protector --script-inventory-audit reports/payment-script-inventory.json --runtime-inventory-snapshot reports/runtime-inventory.json
  jso-protector --init

Options:
  --config <file>      Config file path. Supports JSON, CommonJS .cjs/.js, and ESM .mjs/.js files.
                       Defaults to jso.config.json, jso.config.cjs, jso.config.mjs, or jso.config.js when present.
  --mode <name>        Optional release mode passed to JavaScript config functions. Defaults to NODE_ENV when set.
  --input <path>       Input file or directory.
  --output <path>      Output file or directory.
  --stdin              Read one JavaScript file from standard input.
  --stdout             Write protected stdin output to standard output.
  --file-name <name>   Virtual file name for stdin mode. Defaults to stdin.js.
  --preset <name>      Protection preset: standard, balanced, or maximum.
  --seed <value>       Reproducible builds: the same input, options and seed produce
                       byte-identical output. Omit for the default per-build
                       polymorphic output. Forwarded to the engine as Seed.
  --web-preset <file>  Import an exported online-tool JSON preset.
  --migrate-javascript-obfuscator <file> Convert a javascript-obfuscator JSON or CommonJS config.
  --migrate-js-confuser <file> Convert a JS-Confuser JSON or CommonJS config.
  --list-migration-map Print javascript-obfuscator option migration guidance.
  --list-js-confuser-migration-map Print JS-Confuser option migration guidance.
  --competitor-gap-report Print covered/partial/gap parity against common JS obfuscators.
  --explain-compat <option> Explain how one javascript-obfuscator option is handled.
  --explain-js-confuser-compat <option> Explain how one JS-Confuser option is handled.
  --local              Protect on this machine with the bundled jso-local
                       executable instead of sending source to the hosted API.
                       Windows only; the plan check still runs online (no source).
  --local-exe <path>   Path to cli/jso-local.exe (else JSO_LOCAL_EXE, else the
                       usual desktop install locations).
  --local-only         Print local/offline workflow guidance and exit.
  --verify-manifest <file> Verify protected output against a written manifest.
  --verify-root <path> Override manifest output paths with a different artifact root.
  --audit-source-maps  With --verify-manifest, fail when protected artifacts leak .map files or sourceMappingURL comments.
  --source-map-evidence <file> Build a source-free source-map policy evidence report from a manifest.
  --source-map-evidence-output <file> Write source-map evidence text, or JSON when --json is set. Defaults to stdout.
  --deployment-hygiene-evidence <file> Build a source-free archive/deployment hygiene evidence packet from Build-UpdatedArchives JSON.
  --deployment-hygiene-output <file> Write deployment hygiene evidence text, or JSON when --json is set. Defaults to stdout.
  --runtime-incident-evidence <file> Build a source-free runtime incident response handoff from a Dashboard Monitoring CSV/JSON export.
  --runtime-incident-evidence-output <file> Write runtime incident evidence text, or JSON when --json is set. Defaults to stdout.
  --migration-review Build a source-free migration review packet for all accepted competitor-only fields.
  --migration-review-output <file> Write migration review text, or JSON when --json is set. Defaults to stdout.
  --identifier-cache-review Build a source-free migration review packet for identifier cache/dictionary replacement.
  --identifier-cache-review-output <file> Write identifier-cache review text, or JSON when --json is set. Defaults to stdout.
  --runtime-defense-review Build a source-free migration review packet for anti-debug, self-defending, lock, and countermeasure settings.
  --runtime-defense-review-output <file> Write runtime-defense review text, or JSON when --json is set. Defaults to stdout.
  --verify-vm-proof <file> Verify a source-free API report proves VM protection ran.
  --min-vm-functions <n> Minimum virtualized function count for --verify-vm-proof. Defaults to 1.
  --vm-proof-pack <file> Build a source-free VM reviewer proof pack from a saved API report.
  --vm-proof-output <file> Write VM proof pack Markdown, or JSON when --json is set. Defaults to stdout.
  --ai-resistance-evidence <file> Build a source-free AI resistance evidence report from a saved API report.
  --ai-resistance-evidence-output <file> Write AI resistance evidence text, or JSON when --json is set. Defaults to stdout.
  --require-vm-proof  With --ai-resistance-evidence, require VM proof to pass.
  --script-inventory-from-snapshot <file> Convert a third-party-inventory runtime snapshot into a PCI script inventory starter.
  --script-inventory-output <file> Write generated script inventory JSON to a file. Defaults to stdout.
  --payment-page-headers-from-har <file> Convert a browser HAR export into a source-free payment-page security-header snapshot.
  --payment-page-headers-baseline <file> Previous security-header snapshot used to mark baseline match/mismatch/missing states.
  --payment-page-headers-output <file> Write generated payment-page security-header JSON to a file. Defaults to stdout.
  --payment-page-url-pattern <regex> With --payment-page-headers-from-har, include only matching page URLs.
  --script-inventory-audit <file> Reconcile an approved payment-page script inventory against a runtime snapshot.
  --runtime-inventory-snapshot <file> Runtime third-party-inventory snapshot for --script-inventory-audit.
  --script-inventory-audit-output <file> Write script inventory audit Markdown, or JSON when --json is set. Defaults to stdout.
  --option <k=v>       Override an API option. Repeatable. Example: LockDomain=true.
  --reserved-name <re> Preserve a public name pattern. Repeatable.
  --include <glob>     Protect only matching input files. Repeatable.
  --exclude <glob>     Exclude matching input files. Repeatable.
  --asset-exclude <glob> Exclude matching copied assets. Repeatable.
  --parse-html [bool]  Protect marked <script data-javascript-obfuscator> blocks in HTML or template files.
  --honor-conditional-comments Preserve code between javascript-obfuscator:disable/enable markers.
  --protect-marked-comments Protect only code between javascript-obfuscator:protect-begin/end markers.
  --ignore-imports [bool] Preserve import/export-from statements and common static require/import() statements.
  --keep-header-comment Preserve the first comment block at the top of the output.
  --protect-object-declaration Hide object literal declaration structure.
  --move-nested-function Move nested functions away from call sites.
  --formatted-output   Emit multi-line formatted output for review builds.
  --keep-indent        Preserve indentation when formatted output is enabled.
  --line-numbers       Add line number hints when formatted output is enabled.
  --options-preset <name> Map javascript-obfuscator preset names.
  --string-array [bool] Map javascript-obfuscator string array extraction.
  --string-array-encoding <value> Map base64/rc4 string encoding.
  --string-array-index-shift [bool] Add a nonzero moved-string table offset.
  --string-array-shuffle [bool] Randomize moved-string table order and preserve lookups.
  --string-array-rotate [bool] Rotate moved-string table order by a per-build offset.
  --string-array-indexes-type <types> Use hexadecimal-number and/or hexadecimal-numeric-string lookups.
  --string-array-calls-transform [bool] Add secondary index-table indirection.
  --string-array-calls-transform-threshold <n> Set indirection probability from 0 through 1.
  --string-array-wrappers-count <n> Generate 0-10 root-level wrappers.
  --string-array-wrappers-chained-calls [bool] Chain wrappers through predecessors.
  --string-array-wrappers-parameters-max-count <n> Set function-wrapper parameters from 2 through 5.
  --string-array-wrappers-type <type> Use variable or function wrappers.
  --transform-object-keys [bool] Move safe data keys into computed string-table lookups.
  --split-strings [bool] Split eligible literals into fixed-length chunks.
  --split-strings-chunk-length <n> Set chunk length from 1 through 1024 (default 10).
  --control-flow-flattening [bool] Map control-flow flattening.
  --dead-code-injection [bool] Map dead code injection.
  --dead-code-injection-threshold <n> Map dead-code level.
  --identifier-names-generator <name> Map identifier style.
  --rename-globals [bool] Map global renaming.
  --rename-properties [bool] Map property/member renaming.
  --target <browser|node> Map runtime target.
  --compact [bool] Map compact output.
  --domain-lock <list> Map domain lock list.
  --source-map [bool] Accept source map flag for migration scripts.
  --source-map-sources-mode <value> Accept source-map sources mode for migration review.
  --identifier-names-cache <file> Accept identifier cache flag for migration review.
  --identifier-names-cache-path <file> Accept identifier cache path for migration review.
  --identifiers-dictionary <list> Accept identifier dictionary naming for migration review.
  --identifiers-prefix <value> Accept identifier prefix naming for migration review.
  --self-defending [bool] Map to the hosted SelfDefending runtime guard.
  --self-defending-interval-seconds <n> Repeat integrity checks every 1-86400 seconds.
  --self-healing [bool] Enable bounded local recovery after a self-defending check fails.
  --self-healing-max-attempts <n> Limit local recovery attempts (1-10).
  --anti-monkey-patching [bool] Detect replacement of selected browser APIs.
  --anti-monkey-patching-clean-realm [bool] Compare startup APIs with a same-origin clean realm.
  --runtime-defense-action <action> Set throw, blank, redirect, reload, callback, or degrade.
  --runtime-defense-callback <path> Set the dotted global callback path.
  --runtime-defense-redirect-url <url> Set an HTTP(S) or root-relative redirect target.
  --debug-protection [bool] Map to the hosted DebugProtection runtime guard.
  --strict-mode <bool|null> Accept strict-mode assumptions for migration review.
  --rename-properties-mode <value> Accept property rename mode for migration review.
  --manifest <file>    Write a JSON protection manifest after a successful run.
  --report <file>      Write the full API response (Report.BuildId, identifier maps,
                       polymorphism fingerprint, audit metadata) to this path. Pair
                       with jso-symbolicate for stack-trace demangling.
  --label <value>      Tag the request with a release label (e.g. git SHA or CI build
                       number). Appears as ReleaseLabel in the JSO dashboard audit log.
                       Also reads JSO_LABEL / JAVASCRIPT_OBFUSCATOR_LABEL from env.
  --max-output-bytes <n> Fail if any protected file is larger than n bytes.
  --max-growth-ratio <n> Fail if any protected file grows beyond source*n.
  --endpoint <url>     HTTP API endpoint. Defaults to ${DEFAULT_ENDPOINT}
  --api-key <value>    Base64 API key copied from the dashboard. Can use JSO_API_KEY.
  --api-password <v>   Base64 API password copied from the dashboard. Can use JSO_API_PASSWORD.
  --doctor             Check config, credentials, paths, file matching, and output readiness.
  --check-api          With --doctor, send a tiny live API request.
  --release-check      Run validate-config, dry-run planning, and doctor as one CI preflight.
  --strict             Treat validation warnings as failures in validate-config and release-check.
  --validate-config    Validate config shape and local release settings without calling the API.
  --print-config       Print resolved config with credentials redacted.
  --list-presets       Print available presets and their API options.
  --list-options       Print commonly used API option names.
  --compat-scan        Scan input files for common obfuscation compatibility risks.
  --ai-precheck        Before submitting to the obfuscation API, run an AI compat-check on every
                       input file. Aborts the build (exit 1) when a finding crosses the gate.
                       Wraps the same /v1/ai/compat-check endpoint as 'jso ai compat-scan'.
  --ai-precheck-fail-on <level>  Gate level for --ai-precheck: error (default), warning, or never.
  --watermark <tag>      Embed an HMAC-SHA256 watermark into every protected file. The tag is
                         visible (base64url) inside the output; the signature proves it was
                         produced with --watermark-key. Use for anti-piracy / dispute proof.
  --watermark-key <key>  HMAC secret for --watermark. Required when --watermark is set.
                         Also reads JSO_WATERMARK_KEY from env.
  --verify-watermark <f> Read a protected file and report whether it carries a valid watermark.
                         With --watermark-key, validates the HMAC; without, prints the tag only.
  --scan-watermarks <d>  Walk a directory tree, list every .js file that carries a watermark
                         marker. With --watermark-key, validates each signature. Useful for
                         CDN inventory ("does our prod bundle still carry our marker?") and
                         forensics ("which build did this file come from?"). --json supported.
  --sign-release <pem>   After a successful run, write a signed release attestation
                         (Ed25519 over BuildId + fingerprint + per-file SHA-256). Pairs
                         with --verify-release. Use --genkey-release to mint a fresh keypair.
  --verify-release <sig> Verify a .manifest.sig file. Pair with --public-key for trust pinning
                         and --verify-root <dir> to also re-hash the output files on disk.
  --public-key <pem>     Pin verification to this public key. Without it, the embedded
                         pubkey in the envelope is trusted (signature-only verification).
  --genkey-release <name> Generate an Ed25519 keypair: writes <name>.priv.pem + <name>.pub.pem
                         in the current directory. Don't commit the .priv.pem.
  --estimate             Pre-flight quota check. Walks input files, calls /v1/ai/usage to read
                         the current month's remaining quota, prints estimated burn for this
                         build (bytes / files / % of monthly cap). No obfuscation API call.
  --no-copy-assets     Only write protected JavaScript output.
  --dry-run            Show files and request summary without calling the API.
  --json               Print machine-readable output for dry runs and summaries.
  --init               Write jso.config.json in the current directory.
  --init-template <n>  Init template: browser-app, html-app, node-app, electron-app, nextjs-app,
                       vite-app, parcel-app, bun-app, browserify-app, webpack-app, rspack-app,
                       turbopack-app, or react-native-app.
  --version, -v        Print package version. Combine with --json for metadata.
  --help               Show this help.
`);
}

function parseArgs(argv) {
  const args = {
    config: null,
    mode: null,
    input: null,
    output: null,
    stdin: false,
    stdout: false,
    fileName: "stdin.js",
    preset: null,
    webPreset: null,
    migrateJavascriptObfuscator: null,
    migrateJsConfuser: null,
    listMigrationMap: false,
    listJsConfuserMigrationMap: false,
    competitorGapReport: false,
    explainCompat: null,
    explainJsConfuserCompat: null,
    localOnly: false,
    local: null,
    localExe: null,
    verifyManifest: null,
    verifyRoot: null,
    auditSourceMaps: false,
    sourceMapEvidence: null,
    sourceMapEvidenceOutput: null,
    deploymentHygieneEvidence: null,
    deploymentHygieneOutput: null,
    runtimeIncidentEvidence: null,
    runtimeIncidentEvidenceOutput: null,
    migrationReview: false,
    migrationReviewOutput: null,
    identifierCacheReview: false,
    identifierCacheReviewOutput: null,
    runtimeDefenseReview: false,
    runtimeDefenseReviewOutput: null,
    verifyVmProof: null,
    vmProofPack: null,
    vmProofOutput: null,
    minVmFunctions: 1,
    aiResistanceEvidence: null,
    aiResistanceEvidenceOutput: null,
    requireVmProof: false,
    scriptInventoryFromSnapshot: null,
    scriptInventoryOutput: null,
    paymentPageHeadersFromHar: null,
    paymentPageHeadersBaseline: null,
    paymentPageHeadersOutput: null,
    paymentPageUrlPattern: null,
    scriptInventoryAudit: null,
    runtimeInventorySnapshot: null,
    scriptInventoryAuditOutput: null,
    options: [],
    reservedNames: [],
    include: [],
    exclude: [],
    assetExclude: [],
    parseHtml: null,
    honorConditionalComments: false,
    protectMarkedComments: false,
    keepHeaderComment: null,
    protectObjectDeclaration: null,
    moveNestedFunction: null,
    formattedOutput: null,
    keepIndent: null,
    lineNumbers: null,
    ignoreImports: null,
    manifest: null,
    report: null,
    label: null,
    maxOutputBytes: null,
    maxGrowthRatio: null,
    endpoint: null,
    apiKey: null,
    apiPassword: null,
    doctor: false,
    checkApi: false,
    releaseCheck: false,
    strict: false,
    validateConfig: false,
    printConfig: false,
    listPresets: false,
    listOptions: false,
    compatScan: false,
    aiPrecheck: false,
    aiPrecheckFailOn: "error",
    watermark: null,
    watermarkKey: null,
    verifyWatermark: null,
    scanWatermarks: null,
    signRelease: null,
    verifyRelease: null,
    publicKey: null,
    genkeyRelease: null,
    estimate: false,
    noCopyAssets: false,
    dryRun: false,
    json: false,
    init: false,
    initTemplate: "browser-app",
    version: false,
    help: false,
    compatibilityReviewFields: [],
    compatibilityWarnings: []
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--config":
        args.config = requireValue(argv, ++i, arg);
        break;
      case "--mode":
        args.mode = requireValue(argv, ++i, arg);
        break;
      case "--input":
      case "-i":
        args.input = requireValue(argv, ++i, arg);
        break;
      case "--output":
      case "-o":
        args.output = requireValue(argv, ++i, arg);
        break;
      case "--stdin":
        args.stdin = true;
        break;
      case "--stdout":
        args.stdout = true;
        break;
      case "--file-name":
        args.fileName = requireValue(argv, ++i, arg);
        break;
      case "--preset":
        args.preset = requireValue(argv, ++i, arg);
        break;
      case "--web-preset":
        args.webPreset = requireValue(argv, ++i, arg);
        break;
      case "--migrate-javascript-obfuscator":
        args.migrateJavascriptObfuscator = requireValue(argv, ++i, arg);
        break;
      case "--migrate-js-confuser":
        args.migrateJsConfuser = requireValue(argv, ++i, arg);
        break;
      case "--list-migration-map":
        args.listMigrationMap = true;
        break;
      case "--list-js-confuser-migration-map":
        args.listJsConfuserMigrationMap = true;
        break;
      case "--competitor-gap-report":
        args.competitorGapReport = true;
        break;
      case "--explain-compat":
        args.explainCompat = requireValue(argv, ++i, arg);
        break;
      case "--explain-js-confuser-compat":
        args.explainJsConfuserCompat = requireValue(argv, ++i, arg);
        break;
      case "--local":
        args.local = true;
        break;
      case "--local-exe":
        args.localExe = requireValue(argv, ++i, arg);
        break;
      case "--local-only":
        args.localOnly = true;
        break;
      case "--verify-manifest":
        args.verifyManifest = requireValue(argv, ++i, arg);
        break;
      case "--verify-root":
        args.verifyRoot = requireValue(argv, ++i, arg);
        break;
      case "--audit-source-maps":
        args.auditSourceMaps = true;
        break;
      case "--source-map-evidence":
        args.sourceMapEvidence = requireValue(argv, ++i, arg);
        break;
      case "--source-map-evidence-output":
        args.sourceMapEvidenceOutput = requireValue(argv, ++i, arg);
        break;
      case "--deployment-hygiene-evidence":
        args.deploymentHygieneEvidence = requireValue(argv, ++i, arg);
        break;
      case "--deployment-hygiene-output":
        args.deploymentHygieneOutput = requireValue(argv, ++i, arg);
        break;
      case "--runtime-incident-evidence":
        args.runtimeIncidentEvidence = requireValue(argv, ++i, arg);
        break;
      case "--runtime-incident-evidence-output":
        args.runtimeIncidentEvidenceOutput = requireValue(argv, ++i, arg);
        break;
      case "--migration-review":
        args.migrationReview = true;
        break;
      case "--migration-review-output":
        args.migrationReviewOutput = requireValue(argv, ++i, arg);
        break;
      case "--identifier-cache-review":
        args.identifierCacheReview = true;
        break;
      case "--identifier-cache-review-output":
        args.identifierCacheReviewOutput = requireValue(argv, ++i, arg);
        break;
      case "--runtime-defense-review":
        args.runtimeDefenseReview = true;
        break;
      case "--runtime-defense-review-output":
        args.runtimeDefenseReviewOutput = requireValue(argv, ++i, arg);
        break;
      case "--verify-vm-proof":
        args.verifyVmProof = requireValue(argv, ++i, arg);
        break;
      case "--vm-proof-pack":
        args.vmProofPack = requireValue(argv, ++i, arg);
        break;
      case "--vm-proof-output":
        args.vmProofOutput = requireValue(argv, ++i, arg);
        break;
      case "--min-vm-functions":
        args.minVmFunctions = parsePositiveNumber(requireValue(argv, ++i, arg), arg);
        break;
      case "--ai-resistance-evidence":
        args.aiResistanceEvidence = requireValue(argv, ++i, arg);
        break;
      case "--ai-resistance-evidence-output":
        args.aiResistanceEvidenceOutput = requireValue(argv, ++i, arg);
        break;
      case "--require-vm-proof":
        args.requireVmProof = true;
        break;
      case "--script-inventory-from-snapshot":
        args.scriptInventoryFromSnapshot = requireValue(argv, ++i, arg);
        break;
      case "--script-inventory-output":
        args.scriptInventoryOutput = requireValue(argv, ++i, arg);
        break;
      case "--payment-page-headers-from-har":
        args.paymentPageHeadersFromHar = requireValue(argv, ++i, arg);
        break;
      case "--payment-page-headers-baseline":
        args.paymentPageHeadersBaseline = requireValue(argv, ++i, arg);
        break;
      case "--payment-page-headers-output":
        args.paymentPageHeadersOutput = requireValue(argv, ++i, arg);
        break;
      case "--payment-page-url-pattern":
        args.paymentPageUrlPattern = requireValue(argv, ++i, arg);
        break;
      case "--script-inventory-audit":
        args.scriptInventoryAudit = requireValue(argv, ++i, arg);
        break;
      case "--runtime-inventory-snapshot":
        args.runtimeInventorySnapshot = requireValue(argv, ++i, arg);
        break;
      case "--script-inventory-audit-output":
        args.scriptInventoryAuditOutput = requireValue(argv, ++i, arg);
        break;
      case "--option":
        args.options.push(requireValue(argv, ++i, arg));
        break;
      case "--seed":
        // Reproducible builds: same input + options + seed => byte-identical
        // output. Omit for the default per-build polymorphic output. Forwarded
        // to the engine as the Seed option; an integer is used directly, any
        // other string folds to a stable value.
        args.options.push(`Seed=${requireValue(argv, ++i, arg)}`);
        break;
      case "--reserved-name":
      case "--reserved-names":
        args.reservedNames.push(requireValue(argv, ++i, arg));
        break;
      case "--include":
        args.include.push(requireValue(argv, ++i, arg));
        break;
      case "--exclude":
        args.exclude.push(requireValue(argv, ++i, arg));
        break;
      case "--asset-exclude":
        args.assetExclude.push(requireValue(argv, ++i, arg));
        break;
      case "--parse-html":
        args.parseHtml = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--honor-conditional-comments":
        args.honorConditionalComments = true;
        break;
      case "--protect-marked-comments":
        args.protectMarkedComments = true;
        break;
      case "--keep-header-comment":
        args.keepHeaderComment = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--protect-object-declaration":
        args.protectObjectDeclaration = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--move-nested-function":
        args.moveNestedFunction = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--formatted-output":
        args.formattedOutput = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--keep-indent":
        args.keepIndent = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--line-numbers":
        args.lineNumbers = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--ignore-imports":
        args.ignoreImports = readOptionalBoolean(argv, i + 1);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--options-preset":
        args.preset = presetFromJavascriptObfuscatorPreset(requireValue(argv, ++i, arg));
        break;
      case "--string-array":
        args.options.push(`MoveStrings=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--unicode-escape-sequence":
        args.options.push(`EncodeStrings=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--control-flow-flattening": {
        const value = readOptionalBoolean(argv, i + 1);
        args.options.push(`DeepObfuscate=${value}`);
        args.options.push(`FlatTransform=${value}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      }
      case "--dead-code-injection":
        args.options.push(`AddDeadCode=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--rename-globals":
        args.options.push(`RenameGlobals=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--rename-properties":
        args.options.push(`RenameMembers=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--string-array-encoding":
        addStringArrayEncodingOption(args, requireValue(argv, ++i, arg));
        break;
      case "--string-array-threshold":
        {
          const threshold = normalizeProbability(requireValue(argv, ++i, arg), arg);
          args.options.push(`MoveStrings=${threshold > 0}`);
          args.options.push(`StringArrayThreshold=${threshold}`);
        }
        break;
      case "--dead-code-injection-threshold":
        args.options.push(`DeadcodeLevel=${deadCodeLevelFromThreshold(requireValue(argv, ++i, arg))}`);
        break;
      case "--identifier-names-generator":
        args.options.push(`IdentityStyle=${identityStyleFromGenerator(requireValue(argv, ++i, arg))}`);
        break;
      case "--target":
        args.options.push(`OptimizationMode=${optimizationModeFromTarget(requireValue(argv, ++i, arg))}`);
        break;
      case "--domain-lock":
        args.options.push("LockDomain=true");
        args.options.push(`LockDomainList=${requireValue(argv, ++i, arg)}`);
        args.compatibilityWarnings.push("--domain-lock was mapped to LockDomain and LockDomainList; review subdomain and redirect behavior.");
        break;
      case "--domain-lock-redirect-url":
        args.options.push(`LockDomainRedirectUrl=${normalizeRuntimeRedirectUrl(requireValue(argv, ++i, arg), "--domain-lock-redirect-url")}`);
        break;
      case "--self-defending":
		args.options.push(`SelfDefending=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--self-defending-interval-seconds": {
        const seconds = Number(requireValue(argv, ++i, arg));
        if (!Number.isInteger(seconds) || seconds < 1 || seconds > 86400) {
          throw new Error("--self-defending-interval-seconds must be an integer from 1 through 86400");
        }
        args.options.push(`SelfDefendingIntervalSeconds=${seconds}`);
        break;
      }
      case "--self-healing":
        args.options.push(`SelfHealing=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--self-healing-max-attempts": {
        const attempts = Number(requireValue(argv, ++i, arg));
        if (!Number.isInteger(attempts) || attempts < 1 || attempts > 10) {
          throw new Error("--self-healing-max-attempts must be an integer from 1 through 10");
        }
        args.options.push(`SelfHealingMaxAttempts=${attempts}`);
        break;
      }
      case "--anti-monkey-patching":
        args.options.push(`AntiMonkeyPatching=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--anti-monkey-patching-clean-realm":
        args.options.push(`AntiMonkeyPatchingCleanRealm=${readOptionalBoolean(argv, i + 1)}`);
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--runtime-defense-action": {
        const action = requireValue(argv, ++i, arg).toLowerCase();
        if (!["throw", "blank", "redirect", "reload", "callback", "degrade"].includes(action)) {
          throw new Error("--runtime-defense-action must be throw, blank, redirect, reload, callback, or degrade");
        }
        args.options.push(`RuntimeDefenseAction=${action}`);
        break;
      }
      case "--runtime-defense-callback":
        args.options.push(`RuntimeDefenseCallback=${requireValue(argv, ++i, arg)}`);
        break;
      case "--runtime-defense-redirect-url":
        args.options.push(`RuntimeDefenseRedirectUrl=${requireValue(argv, ++i, arg)}`);
        break;
      case "--debug-protection":
		args.options.push(`DebugProtection=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--debug-protection-interval":
		args.options.push(`DebugProtectionIntervalMilliseconds=${normalizeDebugProtectionInterval(requireValue(argv, ++i, arg), "--debug-protection-interval")}`);
        break;
      case "--disable-console-output":
		args.options.push(`DisableConsoleOutput=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--split-strings":
		args.options.push(`SplitStrings=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--split-strings-chunk-length":
		args.options.push(`SplitStringsChunkLength=${normalizeSplitStringsChunkLength(requireValue(argv, ++i, arg), arg)}`);
        break;
      case "--string-array-index-shift":
		args.options.push(`StringArrayIndexShift=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--string-array-shuffle":
		args.options.push(`StringArrayShuffle=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--string-array-rotate":
		args.options.push(`StringArrayRotate=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--string-array-indexes-type":
		args.options.push(`StringArrayIndexesType=${normalizeStringArrayIndexesType(requireValue(argv, ++i, arg), arg).join("\n")}`);
        break;
      case "--string-array-calls-transform":
		args.options.push(`StringArrayCallsTransform=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--string-array-calls-transform-threshold":
		args.options.push(`StringArrayCallsTransformThreshold=${normalizeProbability(requireValue(argv, ++i, arg), arg)}`);
        break;
      case "--string-array-wrappers-count":
		args.options.push(`StringArrayWrappersCount=${normalizeIntegerRange(requireValue(argv, ++i, arg), arg, 0, 10)}`);
        break;
      case "--string-array-wrappers-chained-calls":
		args.options.push(`StringArrayWrappersChainedCalls=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--string-array-wrappers-parameters-max-count":
		args.options.push(`StringArrayWrappersParametersMaxCount=${normalizeIntegerRange(requireValue(argv, ++i, arg), arg, 2, 5)}`);
        break;
      case "--string-array-wrappers-type":
		args.options.push(`StringArrayWrappersType=${normalizeStringArrayWrappersType(requireValue(argv, ++i, arg))}`);
        break;
      case "--transform-object-keys":
		args.options.push(`TransformObjectKeys=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      case "--source-map":
        addCompatibilityReviewField(args, "sourceMap");
        addReviewOnlyBooleanFlag(args, argv, i + 1, arg, "Source maps are not emitted by the hosted API workflow; keep release source maps out of protected artifacts.");
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--source-map-base-url":
      case "--source-map-file-name":
      case "--source-map-mode":
      case "--source-map-sources-mode":
        addCompatibilityReviewField(args, cliArgToReviewField(arg));
        args.compatibilityWarnings.push(`${arg} was accepted for migration compatibility, but source maps are not emitted by the hosted API workflow.`);
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--identifier-names-cache":
        addCompatibilityReviewField(args, "identifierNamesCache");
        args.compatibilityWarnings.push(`${arg} was accepted for migration compatibility, but identifier-name cache files are not emitted by the hosted API workflow.`);
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--identifier-names-cache-path":
        addCompatibilityReviewField(args, "identifierNamesCachePath");
        args.compatibilityWarnings.push(`${arg} was accepted for migration compatibility, but identifier-name cache files are not emitted by the hosted API workflow.`);
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--identifiers-dictionary":
        addCompatibilityReviewField(args, "identifiersDictionary");
        args.compatibilityWarnings.push(`${arg} was accepted for migration compatibility but hosted API naming controls do not expose the same identifier dictionary or prefix behavior; review output before release.`);
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--identifiers-prefix":
        addCompatibilityReviewField(args, "identifiersPrefix");
        args.compatibilityWarnings.push(`${arg} was accepted for migration compatibility but hosted API naming controls do not expose the same identifier dictionary or prefix behavior; review output before release.`);
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--reserved-strings":
		args.options.push(`ReservedStrings=${normalizeReservedStringPatterns(requireValue(argv, ++i, arg), arg).join("\n")}`);
		break;
      case "--force-transform-strings":
		args.options.push(`ForceTransformStrings=${normalizeReservedStringPatterns(requireValue(argv, ++i, arg), arg).join("\n")}`);
		break;
      case "--numbers-to-expressions":
		args.options.push(`EncodeNumbers=${readOptionalBoolean(argv, i + 1)}`);
		if (hasOptionalValue(argv, i + 1)) i += 1;
		break;
      case "--input-file-name":
      case "--log":
      case "--rename-properties-mode":
      case "--simplify":
      case "--strict-mode":
        addCompatibilityReviewField(args, cliArgToReviewField(arg));
        args.compatibilityWarnings.push(`${arg} was accepted for migration compatibility but has no direct hosted API mapping; review output before release.`);
        i += consumeCompatibilityValue(argv, i + 1, arg);
        break;
      case "--compact": {
        const value = readOptionalBoolean(argv, i + 1);
        if (value) {
          args.options.push("SelfCompression=true");
          args.options.push("CompressionRatio=Best");
        } else {
          args.options.push("SelfCompression=false");
          args.options.push("WriteFormats=true");
        }
        if (hasOptionalValue(argv, i + 1)) i += 1;
        break;
      }
      case "--manifest":
        args.manifest = requireValue(argv, ++i, arg);
        break;
      case "--report":
        // Write the full API response JSON to this path after a successful run.
        // Pairs with jso-symbolicate (consumes Report.GlobalIdentifierMap /
        // MemberIdentifierMap) and the GitHub Action (reads BuildId + fingerprint).
        args.report = requireValue(argv, ++i, arg);
        break;
      case "--label":
        // Tag the API request with a release label (e.g. git SHA, branch name,
        // CI build number). Surfaces in JSO dashboard audit log so support
        // tickets can be tied back to a specific build.
        args.label = requireValue(argv, ++i, arg);
        break;
      case "--max-output-bytes":
        args.maxOutputBytes = parsePositiveNumber(requireValue(argv, ++i, arg), arg);
        break;
      case "--max-growth-ratio":
        args.maxGrowthRatio = parsePositiveNumber(requireValue(argv, ++i, arg), arg);
        break;
      case "--endpoint":
        args.endpoint = requireValue(argv, ++i, arg);
        break;
      case "--api-key":
        args.apiKey = requireValue(argv, ++i, arg);
        break;
      case "--api-password":
        args.apiPassword = requireValue(argv, ++i, arg);
        break;
      case "--doctor":
        args.doctor = true;
        break;
      case "--check-api":
        args.checkApi = true;
        break;
      case "--release-check":
        args.releaseCheck = true;
        break;
      case "--strict":
        args.strict = true;
        break;
      case "--validate-config":
        args.validateConfig = true;
        break;
      case "--print-config":
        args.printConfig = true;
        break;
      case "--list-presets":
        args.listPresets = true;
        break;
      case "--list-options":
        args.listOptions = true;
        break;
      case "--compat-scan":
        args.compatScan = true;
        break;
      case "--ai-precheck":
        args.aiPrecheck = true;
        break;
      case "--ai-precheck-fail-on":
        args.aiPrecheckFailOn = String(requireValue(argv, ++i, arg)).toLowerCase();
        if (!["error", "warning", "never"].includes(args.aiPrecheckFailOn)) {
          throw new Error("--ai-precheck-fail-on must be error, warning, or never");
        }
        break;
      case "--watermark":
        args.watermark = requireValue(argv, ++i, arg);
        break;
      case "--watermark-key":
        args.watermarkKey = requireValue(argv, ++i, arg);
        break;
      case "--verify-watermark":
        args.verifyWatermark = requireValue(argv, ++i, arg);
        break;
      case "--scan-watermarks":
        args.scanWatermarks = requireValue(argv, ++i, arg);
        break;
      case "--sign-release":
        args.signRelease = requireValue(argv, ++i, arg);
        break;
      case "--verify-release":
        args.verifyRelease = requireValue(argv, ++i, arg);
        break;
      case "--public-key":
        args.publicKey = requireValue(argv, ++i, arg);
        break;
      case "--genkey-release":
        args.genkeyRelease = requireValue(argv, ++i, arg);
        break;
      case "--estimate":
        args.estimate = true;
        break;
      case "--no-copy-assets":
        args.noCopyAssets = true;
        break;
      case "--dry-run":
        args.dryRun = true;
        break;
      case "--json":
        args.json = true;
        break;
      case "--init":
        args.init = true;
        break;
      case "--init-template":
        args.initTemplate = normalizeInitTemplateName(requireValue(argv, ++i, arg));
        break;
      case "--version":
      case "-v":
        args.version = true;
        break;
      case "--help":
      case "-h":
        args.help = true;
        break;
      default:
        if (arg.startsWith("--")) {
          throw new Error(`Unknown option: ${arg}`);
        }
        if (!args.input) args.input = arg;
        else if (!args.output) args.output = arg;
        else throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return args;
}

function normalizeInitTemplateName(value) {
  const normalized = String(value || "browser-app").trim().toLowerCase();
  if (normalized === "default" || normalized === "web" || normalized === "browser") {
    return "browser-app";
  }
  if (normalized === "html") {
    return "html-app";
  }
  if (normalized === "node") {
    return "node-app";
  }
  if (normalized === "electron" || normalized === "desktop") {
    return "electron-app";
  }
  if (normalized === "next" || normalized === "nextjs") {
    return "nextjs-app";
  }
  if (normalized === "vite") {
    return "vite-app";
  }
  if (normalized === "parcel") {
    return "parcel-app";
  }
  if (normalized === "bun") {
    return "bun-app";
  }
  if (normalized === "browserify") {
    return "browserify-app";
  }
  if (normalized === "webpack") {
    return "webpack-app";
  }
  if (normalized === "rspack") {
    return "rspack-app";
  }
  if (normalized === "turbopack") {
    return "turbopack-app";
  }
  if (normalized === "react-native" || normalized === "reactnative" || normalized === "metro" || normalized === "expo") {
    return "react-native-app";
  }
  if (!Object.prototype.hasOwnProperty.call(INIT_TEMPLATE_CONFIGS, normalized)) {
    throw new Error(`Unknown init template "${value}". Use browser-app, html-app, node-app, electron-app, nextjs-app, vite-app, parcel-app, bun-app, browserify-app, webpack-app, rspack-app, turbopack-app, or react-native-app.`);
  }
  return normalized;
}

function consumeCompatibilityValue(argv, index) {
  return hasOptionalValue(argv, index) ? 1 : 0;
}

function addCompatibilityReviewField(args, field) {
  if (!field) return;
  if (!Array.isArray(args.compatibilityReviewFields)) args.compatibilityReviewFields = [];
  if (!args.compatibilityReviewFields.includes(field)) args.compatibilityReviewFields.push(field);
}

function cliArgToReviewField(arg) {
  const mappings = {
    "--source-map-base-url": "sourceMapBaseUrl",
    "--source-map-file-name": "sourceMapFileName",
    "--source-map-mode": "sourceMapMode",
    "--source-map-sources-mode": "sourceMapSourcesMode"
  };
  if (mappings[arg]) return mappings[arg];
  const normalized = String(arg || "").replace(/^--/, "");
  if (!normalized) return null;
  return normalized.replace(/-([a-z0-9])/g, (_match, letter) => letter.toUpperCase());
}

function addReviewOnlyBooleanFlag(args, argv, index, option, enabledMessage) {
  const value = readOptionalBoolean(argv, index);
  if (value) {
    args.compatibilityWarnings.push(`${option}: ${enabledMessage}`);
  }
  return value;
}

function hasOptionalValue(argv, index) {
  const value = argv[index];
  return !!value && !value.startsWith("--");
}

function readOptionalBoolean(argv, index) {
  if (!hasOptionalValue(argv, index)) return true;
  return parseOptionValue(argv[index]) !== false;
}

function addStringArrayEncodingOption(args, value) {
  const values = String(value).split(",").map((entry) => entry.trim()).filter(Boolean);
  if (values.some((entry) => entry.toLowerCase() === "rc4")) {
    args.options.push("EncryptStrings=true");
  } else if (values.length) {
    args.options.push("EncodeStrings=true");
  }
}

function deadCodeLevelFromThreshold(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    throw new Error("--dead-code-injection-threshold must be a number");
  }
  return number >= 0.66 ? "High" : number >= 0.33 ? "Medium" : "Low";
}

function normalizeDebugProtectionInterval(value, label = "debugProtectionInterval") {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || (number > 0 && number < 100) || number > 60000) {
    throw new Error(`${label} must be 0 or an integer from 100 through 60000 milliseconds`);
  }
  return number;
}

function normalizeRuntimeRedirectUrl(value, label = "domainLockRedirectUrl") {
  const text = String(value || "").trim();
  const safeRelative = text.startsWith("/") && !text.startsWith("//") && !text.includes("\\");
  let safeAbsolute = false;
  try {
    const parsed = new URL(text);
    safeAbsolute = parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch { }
  if (!safeRelative && !safeAbsolute) throw new Error(`${label} must be an HTTP(S) URL or same-origin root-relative path`);
  return text;
}

function normalizeSeedValue(value, label = "seed") {
  if ((typeof value !== "string" && typeof value !== "number") || (typeof value === "number" && !Number.isFinite(value))) {
    throw new Error(`${label} must be a finite number or non-empty string`);
  }
  const text = String(value).trim();
  if (!text) throw new Error(`${label} must be a finite number or non-empty string`);
  return text;
}

function normalizeSplitStringsChunkLength(value, label = "splitStringsChunkLength") {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 1024) throw new Error(`${label} must be an integer from 1 through 1024`);
  return number;
}

function normalizeProbability(value, label) {
	const number = Number(value);
	if (!Number.isFinite(number) || number < 0 || number > 1) throw new Error(`${label} must be a number from 0 through 1`);
	return number;
}

function normalizeIntegerRange(value, label, minimum, maximum) {
	const number = Number(value);
	if (!Number.isInteger(number) || number < minimum || number > maximum) throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
	return number;
}

function normalizeStringArrayWrappersType(value) {
	const normalized = String(value || "").trim().toLowerCase();
	if (normalized !== "variable" && normalized !== "function") throw new Error("stringArrayWrappersType supports only variable or function");
	return normalized;
}

function normalizeReservedStringPatterns(value, label = "reservedStrings") {
	const raw = Array.isArray(value) ? value : String(value || "").split(",");
	const patterns = raw.map((item) => String(item).trim()).filter(Boolean);
	if (patterns.length > 100) throw new Error(`${label} accepts at most 100 patterns`);
	if (patterns.some((pattern) => pattern.length > 512)) throw new Error(`${label} patterns must be at most 512 characters`);
	return patterns;
}

function normalizeStringArrayIndexesType(value, label = "stringArrayIndexesType") {
	const raw = Array.isArray(value) ? value : String(value || "").split(",");
	const values = raw.map((item) => String(item).trim().toLowerCase()).filter(Boolean);
	if (!values.length) throw new Error(`${label} must include at least one supported value`);
	const supported = new Set(["hexadecimal-number", "hexadecimal-numeric-string"]);
	if (values.some((item) => !supported.has(item))) throw new Error(`${label} supports only hexadecimal-number and hexadecimal-numeric-string`);
	return [...new Set(values)];
}

function identityStyleFromGenerator(value) {
  return String(value || "").toLowerCase().includes("hex") ? "v1hex" : "v2abcd";
}

function optimizationModeFromTarget(value) {
  return String(value || "").toLowerCase().includes("node") ? "NodeJS" : "Web";
}

function normalizeDomainLockList(value) {
  const raw = Array.isArray(value) ? value : String(value || "").split(/[,\n]/);
  return raw.map((entry) => String(entry).trim()).filter(Boolean);
}

function translateJavascriptObfuscatorConfigOptions(source = {}) {
  const translated = {
    options: {}
  };

  if (source.optionsPreset !== undefined) {
    translated.preset = presetFromJavascriptObfuscatorPreset(source.optionsPreset);
  }

  mapBooleanConfigOption(source, "stringArray", translated.options, "MoveStrings");
  mapBooleanConfigOption(source, "stringArrayIndexShift", translated.options, "StringArrayIndexShift");
  mapBooleanConfigOption(source, "stringArrayShuffle", translated.options, "StringArrayShuffle");
  mapBooleanConfigOption(source, "stringArrayRotate", translated.options, "StringArrayRotate");
  if (source.stringArrayIndexesType !== undefined) translated.options.StringArrayIndexesType = normalizeStringArrayIndexesType(source.stringArrayIndexesType).join("\n");
  mapBooleanConfigOption(source, "stringArrayCallsTransform", translated.options, "StringArrayCallsTransform");
  if (source.stringArrayCallsTransformThreshold !== undefined) translated.options.StringArrayCallsTransformThreshold = normalizeProbability(source.stringArrayCallsTransformThreshold, "stringArrayCallsTransformThreshold");
  if (source.stringArrayWrappersCount !== undefined) translated.options.StringArrayWrappersCount = normalizeIntegerRange(source.stringArrayWrappersCount, "stringArrayWrappersCount", 0, 10);
  mapExplicitBooleanConfigOption(source, "stringArrayWrappersChainedCalls", translated.options, "StringArrayWrappersChainedCalls");
  if (source.stringArrayWrappersParametersMaxCount !== undefined) translated.options.StringArrayWrappersParametersMaxCount = normalizeIntegerRange(source.stringArrayWrappersParametersMaxCount, "stringArrayWrappersParametersMaxCount", 2, 5);
  if (source.stringArrayWrappersType !== undefined) translated.options.StringArrayWrappersType = normalizeStringArrayWrappersType(source.stringArrayWrappersType);
  mapBooleanConfigOption(source, "transformObjectKeys", translated.options, "TransformObjectKeys");
  mapBooleanConfigOption(source, "splitStrings", translated.options, "SplitStrings");
  if (source.splitStringsChunkLength !== undefined) translated.options.SplitStringsChunkLength = normalizeSplitStringsChunkLength(source.splitStringsChunkLength);
  mapBooleanConfigOption(source, "unicodeEscapeSequence", translated.options, "EncodeStrings");
  mapBooleanConfigOption(source, "controlFlowFlattening", translated.options, "DeepObfuscate");
  mapBooleanConfigOption(source, "controlFlowFlattening", translated.options, "FlatTransform");
  mapBooleanConfigOption(source, "deadCodeInjection", translated.options, "AddDeadCode");
  mapBooleanConfigOption(source, "renameGlobals", translated.options, "RenameGlobals");
  mapBooleanConfigOption(source, "renameProperties", translated.options, "RenameMembers");
  mapExplicitBooleanConfigOption(source, "selfDefending", translated.options, "SelfDefending");
  mapExplicitBooleanConfigOption(source, "debugProtection", translated.options, "DebugProtection");
  if (source.debugProtectionInterval !== undefined) translated.options.DebugProtectionIntervalMilliseconds = normalizeDebugProtectionInterval(source.debugProtectionInterval);
  mapExplicitBooleanConfigOption(source, "disableConsoleOutput", translated.options, "DisableConsoleOutput");
  mapExplicitBooleanConfigOption(source, "numbersToExpressions", translated.options, "EncodeNumbers");
  if (source.domainLockRedirectUrl !== undefined) translated.options.LockDomainRedirectUrl = normalizeRuntimeRedirectUrl(source.domainLockRedirectUrl);
  if (source.seed !== undefined) translated.options.Seed = normalizeSeedValue(source.seed);
  if (source.reservedStrings !== undefined) translated.options.ReservedStrings = normalizeReservedStringPatterns(source.reservedStrings).join("\n");
  if (source.forceTransformStrings !== undefined) translated.options.ForceTransformStrings = normalizeReservedStringPatterns(source.forceTransformStrings, "forceTransformStrings").join("\n");

  if (source.stringArrayEncoding !== undefined) {
    const encodings = Array.isArray(source.stringArrayEncoding) ? source.stringArrayEncoding : [source.stringArrayEncoding];
    if (encodings.some((encoding) => String(encoding).toLowerCase() === "rc4")) {
      translated.options.EncryptStrings = true;
    } else if (encodings.length) {
      translated.options.EncodeStrings = true;
    }
  }

  if (source.stringArrayThreshold !== undefined) {
    const threshold = normalizeProbability(source.stringArrayThreshold, "stringArrayThreshold");
    translated.options.StringArrayThreshold = threshold;
    if (source.stringArray !== false) translated.options.MoveStrings = threshold > 0;
  }

  if (source.deadCodeInjectionThreshold !== undefined) {
    translated.options.DeadcodeLevel = deadCodeLevelFromThreshold(source.deadCodeInjectionThreshold);
  }

  if (source.identifierNamesGenerator !== undefined) {
    translated.options.IdentityStyle = identityStyleFromGenerator(source.identifierNamesGenerator);
  }

  if (source.compact === true) {
    translated.options.SelfCompression = true;
    translated.options.CompressionRatio = "Best";
  } else if (source.compact === false) {
    translated.options.SelfCompression = false;
    translated.options.WriteFormats = true;
  }

  if (source.target !== undefined) {
    translated.options.OptimizationMode = optimizationModeFromTarget(source.target);
  }

  if (source.parseHtml !== undefined) {
    translated.parseHtml = source.parseHtml === true;
  }

  if (source.ignoreImports !== undefined) {
    translated.ignoreImports = source.ignoreImports === true;
  }

  if (source.domainLock !== undefined) {
    const domains = normalizeDomainLockList(source.domainLock);
    if (domains.length) {
      translated.options.LockDomain = true;
      translated.options.LockDomainList = domains.join("\n");
    }
  }

  return translated;
}

function presetFromJsConfuserPreset(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized || normalized === "low") return "standard";
  if (normalized === "medium") return "balanced";
  if (normalized === "high") return "maximum";
  throw new Error(`Unknown JS-Confuser preset "${value}". Use low, medium, or high.`);
}

function translateJsConfuserConfigOptions(source = {}) {
  if (!hasJsConfuserCompatibilityOptions(source)) {
    return { options: {} };
  }

  const translated = {
    options: {}
  };

  if (source.preset !== undefined) {
    translated.preset = presetFromJsConfuserPreset(source.preset);
  }

  mapBooleanConfigOption(source, "renameVariables", translated.options, "ReplaceNames");
  mapBooleanConfigOption(source, "renameGlobals", translated.options, "RenameGlobals");
  mapBooleanConfigOption(source, "globalConcealing", translated.options, "RenameGlobals");
  mapBooleanConfigOption(source, "stringEncoding", translated.options, "EncodeStrings");
  mapBooleanConfigOption(source, "stringConcealing", translated.options, "EncryptStrings");
  mapBooleanConfigOption(source, "duplicateLiteralsRemoval", translated.options, "MoveStrings");
  if (typeof source.stringSplitting === "function") throw new Error("stringSplitting selector functions require manual migration review");
  if (source.stringSplitting !== undefined) translated.options.SplitStrings = jsConfuserLockEnabled(source.stringSplitting);
  mapBooleanConfigOption(source, "controlFlowFlattening", translated.options, "DeepObfuscate");
  mapBooleanConfigOption(source, "controlFlowFlattening", translated.options, "FlatTransform");
  mapBooleanConfigOption(source, "deadCode", translated.options, "AddDeadCode");
  mapExplicitBooleanConfigOption(source, "hexadecimalNumbers", translated.options, "EncodeNumbers");

  if (source.stringCompression === true || source.minify === true || source.compact === true) {
    translated.options.SelfCompression = true;
    translated.options.CompressionRatio = "Best";
  } else if (source.minify === false || source.compact === false) {
    translated.options.WriteFormats = true;
  }

  if (source.identifierGenerator !== undefined) {
    translated.options.IdentityStyle = identityStyleFromGenerator(source.identifierGenerator);
  }

  if (source.target !== undefined) {
    translated.options.OptimizationMode = optimizationModeFromTarget(source.target);
  }

  if (source.lock && typeof source.lock === "object" && !Array.isArray(source.lock)) {
    const lock = source.lock;
    if (lock.domainLock !== undefined) {
      const domains = normalizeDomainLockList(lock.domainLock);
      if (domains.length) {
        translated.options.LockDomain = true;
        translated.options.LockDomainList = domains.join("\n");
      }
    }
    if (lock.endDate !== undefined) {
      translated.options.LockDate = true;
      translated.options.LockDateValue = formatLockDateValue(lock.endDate);
    }
	mapJsConfuserRuntimeLocks(lock, translated.options);
  }

	if (source.jsConfuserLockAntiDebug !== undefined) translated.options.DebugProtection = jsConfuserLockEnabled(source.jsConfuserLockAntiDebug);
	if (source.jsConfuserLockIntegrity !== undefined || source.jsConfuserLockSelfDefending !== undefined) {
		translated.options.SelfDefending = jsConfuserLockEnabled(source.jsConfuserLockIntegrity) || jsConfuserLockEnabled(source.jsConfuserLockSelfDefending);
	}
	if (source.jsConfuserLockStartDate !== undefined) {
		translated.options.LockStartDate = true;
		translated.options.LockStartDateValue = formatLockDateValue(source.jsConfuserLockStartDate);
	}
	if (source.jsConfuserLockTamperProtection !== undefined) translated.options.AntiMonkeyPatching = jsConfuserLockEnabled(source.jsConfuserLockTamperProtection);

  return translated;
}

function jsConfuserLockEnabled(value) {
	return value === true || (typeof value === "number" && Number.isFinite(value) && value > 0);
}

function mapJsConfuserRuntimeLocks(lock, target) {
	if (!lock || typeof lock !== "object") return;
	if (lock.antiDebug !== undefined) target.DebugProtection = jsConfuserLockEnabled(lock.antiDebug);
	if (lock.integrity !== undefined || lock.selfDefending !== undefined) {
		target.SelfDefending = jsConfuserLockEnabled(lock.integrity) || jsConfuserLockEnabled(lock.selfDefending);
	}
	if (lock.startDate !== undefined) {
		target.LockStartDate = true;
		target.LockStartDateValue = formatLockDateValue(lock.startDate);
	}
	if (lock.tamperProtection !== undefined) target.AntiMonkeyPatching = jsConfuserLockEnabled(lock.tamperProtection);
}

function hasJsConfuserCompatibilityOptions(source = {}) {
  if (!source || typeof source !== "object") return false;
  if (JS_CONFUSER_CONFIG_MAPPED_FIELDS.some((key) => Object.prototype.hasOwnProperty.call(source, key))) return true;
  if (JS_CONFUSER_DETECT_KEYS.some((key) => Object.prototype.hasOwnProperty.call(source, key))) {
    return true;
  }
  const preset = String(source.preset || "").trim().toLowerCase();
  return preset === "low" || preset === "medium" || preset === "high";
}

function formatLockDateValue(value) {
  const text = String(value || "").trim();
  if (/^\d{8}$/.test(text)) return text;
  const date = new Date(text);
  if (!Number.isFinite(date.getTime())) return text;
  const year = String(date.getUTCFullYear()).padStart(4, "0");
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}${month}${day}`;
}

function formatReviewString(value) {
  if (typeof value === "function") {
    return value.name ? `[Function ${value.name}]` : "[Function]";
  }
  return String(value);
}

function mapBooleanConfigOption(source, sourceKey, target, targetKey) {
  if (source[sourceKey] === true) target[targetKey] = true;
}

function mapExplicitBooleanConfigOption(source, sourceKey, target, targetKey) {
  if (typeof source[sourceKey] === "boolean") target[targetKey] = source[sourceKey];
}

function presetFromJavascriptObfuscatorPreset(value) {
  const normalized = String(value || "").trim().toLowerCase().replace(/[\s_]+/g, "-");
  if (
    !normalized ||
    normalized === "default" ||
    normalized === "low" ||
    normalized === "low-obfuscation" ||
    normalized === "standard" ||
    normalized === "vm-default" ||
    normalized === "vm-low" ||
    normalized === "vm-low-obfuscation"
  ) {
    return "standard";
  }
  if (
    normalized === "medium" ||
    normalized === "medium-obfuscation" ||
    normalized === "balanced" ||
    normalized === "vm-medium" ||
    normalized === "vm-medium-obfuscation"
  ) {
    return "balanced";
  }
  if (
    normalized === "high" ||
    normalized === "high-obfuscation" ||
    normalized === "maximum" ||
    normalized === "vm-high" ||
    normalized === "vm-high-obfuscation" ||
    normalized === "vm-ultra-high-obfuscation" ||
    normalized === "vm-anti-llm"
  ) {
    return "maximum";
  }
  throw new Error(`Unknown javascript-obfuscator options preset "${value}". Use default, low-obfuscation, medium-obfuscation, high-obfuscation, or one of the vm-* presets.`);
}

function writeCompatibilityWarnings(args) {
  for (const warning of args.compatibilityWarnings || []) {
    process.stderr.write(`Compatibility warning: ${warning}\n`);
  }
}

function requireValue(argv, index, option) {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`Missing value for ${option}`);
  }
  return value;
}

function parsePositiveNumber(value, option) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    throw new Error(`${option} must be a positive number`);
  }
  return number;
}

function createConfigLoadContext(context = {}) {
  return {
    cwd: process.cwd(),
    env: process.env,
    mode: context.mode || process.env.NODE_ENV || null
  };
}

function readConfig(configPath, context = {}) {
  if (!configPath) {
    configPath = DEFAULT_CONFIG_FILES.map((fileName) => path.resolve(fileName)).find((filePath) => fs.existsSync(filePath));
    if (!configPath) return {};
  }

  const resolved = path.resolve(configPath);
  const config = { ...loadConfigFile(resolved, createConfigLoadContext(context)) };
  config.__configDir = path.dirname(resolved);
  return config;
}

function loadConfigFile(resolved, context) {
  const extension = path.extname(resolved).toLowerCase();
  if (extension === ".mjs" || (extension === ".js" && isTypeModuleConfig(resolved))) {
    return loadEsmConfig(resolved, context);
  }
  if (extension === ".js" || extension === ".cjs") {
    return loadCommonJsConfig(resolved, context);
  }

  const raw = fs.readFileSync(resolved, "utf8");
  return JSON.parse(raw);
}

function loadCommonJsConfig(resolved, context) {
  try {
    delete require.cache[require.resolve(resolved)];
    const exported = require(resolved);
    const config = typeof exported === "function" ? exported(context) : exported;
    if (!config || typeof config !== "object" || Array.isArray(config)) {
      throw new Error("JavaScript config must export an object or a function that returns an object.");
    }
    return config;
  } catch (error) {
    if (error && error.code === "ERR_REQUIRE_ESM") {
      return loadEsmConfig(resolved);
    }
    throw error;
  }
}

function isTypeModuleConfig(resolved) {
  let currentDir = path.dirname(resolved);
  const { root } = path.parse(currentDir);

  while (true) {
    const packageJsonPath = path.join(currentDir, "package.json");
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
        return packageJson && packageJson.type === "module";
      } catch (_error) {
        return false;
      }
    }

    if (currentDir === root) return false;
    currentDir = path.dirname(currentDir);
  }
}

function loadEsmConfig(resolved, context) {
  const raw = fs.readFileSync(resolved, "utf8");
  if (!/\bexport\s+default\b/.test(raw)) {
    throw new Error("ES module config files must use a default export object or function.");
  }

  const compiledSource = raw.replace(/\bexport\s+default\b/, "module.exports =");
  const esmModule = new Module(resolved, module);
  esmModule.filename = resolved;
  esmModule.paths = Module._nodeModulePaths(path.dirname(resolved));

  try {
    esmModule._compile(compiledSource, resolved);
    const exported = esmModule.exports;
    const config = typeof exported === "function"
      ? exported(context)
      : exported;

    if (!config || typeof config !== "object" || Array.isArray(config)) {
      throw new Error("JavaScript config must export an object or a function that returns an object.");
    }
    return config;
  } catch (error) {
    throw new Error(`Failed to load ES module config ${resolved}: ${error.message}`);
  }
}

function mergeConfig(config, args = {}) {
  const baseDir = config.__configDir || process.cwd();
  const webPreset = loadWebPreset(config, args, baseDir);
  const compatibility = translateJavascriptObfuscatorConfigOptions(config);
  const jsConfuserCompatibility = translateJsConfuserConfigOptions(config);
  const preset = normalizePresetName(args.preset || config.preset || jsConfuserCompatibility.preset || compatibility.preset || (webPreset && webPreset.preset) || "standard");
  const output = args.output || config.output || getCompatibilityDefaultOutput(args, config, baseDir) || "dist-protected";
  const convenienceOptions = mapConvenienceOptions(config, args);
  const options = {
    ...getPresetOptions(preset),
    ...mapWebPresetToOptions(webPreset),
    ...(compatibility.options || {}),
    ...(jsConfuserCompatibility.options || {}),
    ...convenienceOptions,
    ...(config.options || {}),
    ...parseOptionOverrides(args.options || [])
  };
  applyReservedNames(options, {
    ...config,
    reservedNames: (args.reservedNames && args.reservedNames.length) ? args.reservedNames : config.reservedNames
  });

  const merged = {
    mode: args.mode || config.mode || readEnv(["NODE_ENV"]) || null,
    endpoint: args.endpoint || config.endpoint || readEnv(["JSO_ENDPOINT", "JAVASCRIPT_OBFUSCATOR_ENDPOINT"]) || DEFAULT_ENDPOINT,
    apiKey: resolveEnv(args.apiKey || config.apiKey || readEnv(["JSO_API_KEY", "JAVASCRIPT_OBFUSCATOR_API_KEY"]) || ""),
    apiPassword: resolveEnv(args.apiPassword || config.apiPassword || readEnv(["JSO_API_PASSWORD", "JAVASCRIPT_OBFUSCATOR_API_PASSWORD"]) || ""),
    projectName: config.projectName || "jso-protector",
    preset,
    input: args.input || config.input || "dist",
    output,
    include: (args.include && args.include.length) ? args.include : (config.include || []),
    extensions: normalizeExtensions(config.extensions || DEFAULT_EXTENSIONS),
    markupExtensions: normalizeExtensions(config.markupExtensions || DEFAULT_MARKUP_EXTENSIONS),
    exclude: mergePatternLists(config.exclude || DEFAULT_EXCLUDE, args.exclude || []),
    assetExclude: mergePatternLists(config.assetExclude || DEFAULT_ASSET_EXCLUDE, args.assetExclude || []),
    copyAssets: args.noCopyAssets ? false : config.copyAssets !== false,
    mixedServer: !!config.mixedServer,
    parseHtml: args.parseHtml !== undefined && args.parseHtml !== null ? !!args.parseHtml : !!(config.parseHtml || compatibility.parseHtml),
    honorConditionalComments: !!(args.honorConditionalComments || config.honorConditionalComments),
    protectMarkedComments: !!(args.protectMarkedComments || config.protectMarkedComments),
    ignoreImports: args.ignoreImports !== undefined && args.ignoreImports !== null ? !!args.ignoreImports : !!(config.ignoreImports || compatibility.ignoreImports),
    manifest: args.manifest || config.manifest || null,
    report: args.report || config.report || null,
    label: args.label || config.label || readEnv(["JSO_LABEL", "JAVASCRIPT_OBFUSCATOR_LABEL"]) || null,
    watermark: args.watermark || config.watermark || null,
    watermarkKey: args.watermarkKey || config.watermarkKey || readEnv(["JSO_WATERMARK_KEY"]) || null,
    maxOutputBytes: args.maxOutputBytes || config.maxOutputBytes || null,
    maxGrowthRatio: args.maxGrowthRatio || config.maxGrowthRatio || null,
    removeSourceMaps: config.removeSourceMaps !== false,
    // Source-local protection: run the bundled jso-local executable instead of
    // POSTing source to the hosted endpoint. The plan/option check still goes
    // online (source-free); only the source body stays on this machine.
    local: args.local !== undefined && args.local !== null ? !!args.local : !!config.local,
    localExe: args.localExe || config.localExe || readEnv(["JSO_LOCAL_EXE"]) || null,
    namedSets: (config.namedSets && typeof config.namedSets === "object" && !Array.isArray(config.namedSets)) ? config.namedSets : null,
    options
  };

  for (const field of Object.keys(JS_CONFUSER_CONFIG_REVIEW_FIELDS)) {
    if (config[field] !== undefined) {
      merged[field] = config[field];
    } else if (jsConfuserCompatibility[field] !== undefined) {
      merged[field] = jsConfuserCompatibility[field];
    }
  }

  validateStringArray("include", merged.include);
  if (merged.parseHtml) {
    merged.extensions = mergePatternLists(merged.extensions, merged.markupExtensions);
  }
  validateStringArray("extensions", merged.extensions);
  validateStringArray("markupExtensions", merged.markupExtensions);
  validateStringArray("exclude", merged.exclude);
  validateStringArray("assetExclude", merged.assetExclude);
  validateNamedSets(merged.namedSets);

  merged.input = resolvePath(baseDir, merged.input);
  merged.output = resolvePath(baseDir, merged.output);
  if (merged.manifest) merged.manifest = resolvePath(baseDir, merged.manifest);
  return merged;
}

function mergePatternLists(base, additions) {
  return Array.from(new Set([...(base || []), ...(additions || [])]));
}

function mapConvenienceOptions(config = {}, args = {}) {
  const mapped = {};
  for (const alias of CONVENIENCE_OPTION_ALIASES) {
    const value = args[alias.configKey] !== undefined && args[alias.configKey] !== null
      ? args[alias.configKey]
      : config[alias.configKey];
    if (value === undefined || value === null) continue;
    mapped[alias.optionName] = alias.type === "boolean" ? value === true : value;
  }
  return mapped;
}

function getCompatibilityDefaultOutput(args, config, baseDir) {
  if (!args.input || args.output || config.output) return null;

  const resolvedInput = resolvePath(baseDir, args.input);
  if (!fs.existsSync(resolvedInput) || !fs.statSync(resolvedInput).isFile()) return null;

  const ext = path.extname(resolvedInput) || ".js";
  const baseName = path.basename(resolvedInput, ext);
  return path.join(path.dirname(resolvedInput), `${baseName}-obfuscated${ext}`);
}

function loadWebPreset(config, args, baseDir) {
  if (config.format === WEB_PRESET_FORMAT) return config;

  const webPresetPath = args.webPreset || config.webPreset;
  if (!webPresetPath) return null;

  const resolved = resolvePath(baseDir, webPresetPath);
  const webPreset = JSON.parse(fs.readFileSync(resolved, "utf8"));
  if (webPreset.format !== WEB_PRESET_FORMAT) {
    throw new Error(`Web preset must use format "${WEB_PRESET_FORMAT}"`);
  }
  if (webPreset.version !== 1) {
    throw new Error(`Unsupported web preset version: ${webPreset.version}`);
  }
  return webPreset;
}

function normalizePresetName(value) {
  const name = String(value || "standard").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(PRESET_OPTIONS, name)) {
    throw new Error(`Unknown preset "${value}". Use standard, balanced, or maximum.`);
  }
  return name;
}

function getPresetOptions(preset) {
  return { ...PRESET_OPTIONS[normalizePresetName(preset)] };
}

function mapWebPresetToOptions(webPreset) {
  if (!webPreset) return {};
  if (webPreset.format !== WEB_PRESET_FORMAT) {
    throw new Error(`Web preset must use format "${WEB_PRESET_FORMAT}"`);
  }
  if (webPreset.version !== 1) {
    throw new Error(`Unsupported web preset version: ${webPreset.version}`);
  }

  const options = {};
  const standard = webPreset.standardOptions || {};
  if (standard.keepLinefeeds || standard.keepIndentations) options.WriteFormats = true;
  if (standard.keepIndentations) options.WriteFormats_KeepIndent = true;
  if (standard.encodeStrings) options.EncodeStrings = true;
  if (standard.moveStrings) options.MoveStrings = true;
  if (standard.replaceNames) options.ReplaceNames = true;

  for (const feature of webPreset.advancedFeatures || []) {
    Object.assign(options, WEB_FEATURE_OPTIONS[feature] || {});
  }

  if (typeof webPreset.variableExclusionList === "string" && webPreset.variableExclusionList.trim()) {
    options.VariableExclusion = webPreset.variableExclusionList;
  }

  return options;
}

function applyReservedNames(options, config) {
  const optionReservedNames = Array.isArray(options.reservedNames) ? options.reservedNames : null;
  delete options.reservedNames;

  if (options.VariableExclusion) return;
  if (typeof config.variableExclusion === "string" && config.variableExclusion.trim()) {
    options.VariableExclusion = config.variableExclusion;
    return;
  }
  if (Array.isArray(config.reservedNames) && config.reservedNames.length) {
    options.VariableExclusion = config.reservedNames.join("\n");
    return;
  }
  if (optionReservedNames && optionReservedNames.length) {
    options.VariableExclusion = optionReservedNames.join("\n");
  }
}

function parseOptionOverrides(values) {
  const options = {};
  for (const entry of values || []) {
    const index = String(entry).indexOf("=");
    if (index <= 0) {
      throw new Error(`Invalid --option value "${entry}". Use Name=value.`);
    }
    const key = entry.slice(0, index).trim();
    if (!key) {
      throw new Error(`Invalid --option value "${entry}". Use Name=value.`);
    }
    options[key] = parseOptionValue(entry.slice(index + 1));
  }
  return options;
}

function parseOptionValue(value) {
  const trimmed = String(value).trim();
  if (/^(true|false)$/i.test(trimmed)) return trimmed.toLowerCase() === "true";
  if (/^null$/i.test(trimmed)) return null;
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);
  return value;
}

function validateStringArray(name, value) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`${name} must be an array of strings`);
  }
}

function validateOptionalString(name, value) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new Error(`${name} must be a string`);
  }
}

function validateOptionalBoolean(name, value) {
  if (value !== undefined && value !== null && typeof value !== "boolean") {
    throw new Error(`${name} must be a boolean`);
  }
}

function validateOptionalPositiveNumber(name, value) {
  if (value !== undefined && value !== null && (!Number.isFinite(Number(value)) || Number(value) <= 0)) {
    throw new Error(`${name} must be a positive number`);
  }
}

function validateOptionalNonNegativeNumber(name, value) {
  if (value !== undefined && value !== null && (!Number.isFinite(Number(value)) || Number(value) < 0)) {
    throw new Error(`${name} must be a non-negative number`);
  }
}

function resolveEnv(value) {
  if (typeof value !== "string") return value;
  if (value.startsWith("$") && value.length > 1) {
    return process.env[value.slice(1)] || "";
  }
  return value;
}

function readEnv(names) {
  for (const name of names) {
    if (process.env[name]) return process.env[name];
  }
  return "";
}

function resolvePath(baseDir, value) {
  if (!value) return value;
  if (path.isAbsolute(value)) return value;
  return path.resolve(baseDir, value);
}

function normalizeExtensions(extensions) {
  return extensions.map((ext) => ext.startsWith(".") ? ext.toLowerCase() : `.${ext.toLowerCase()}`);
}

function createExampleConfig(initOptions = {}) {
  const normalizedOptions = typeof initOptions === "string" ? { template: initOptions } : (initOptions || {});
  const templateName = normalizeInitTemplateName(normalizedOptions.template || "browser-app");
  const template = INIT_TEMPLATE_CONFIGS[templateName];
  const config = {
    $schema: "./node_modules/jso-protector/jso.config.schema.json",
    endpoint: DEFAULT_ENDPOINT,
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    projectName: template.projectName,
    input: template.input,
    output: template.output,
    preset: template.preset,
    ...(template.include ? { include: template.include.slice() } : {}),
    extensions: template.extensions.slice(),
    exclude: template.exclude.slice(),
    copyAssets: template.copyAssets,
    assetExclude: template.assetExclude.slice(),
    mixedServer: template.mixedServer,
    parseHtml: template.parseHtml,
    honorConditionalComments: template.honorConditionalComments,
    protectMarkedComments: template.protectMarkedComments,
    ignoreImports: template.ignoreImports,
    keepHeaderComment: template.keepHeaderComment,
    protectObjectDeclaration: template.protectObjectDeclaration,
    moveNestedFunction: template.moveNestedFunction,
    formattedOutput: template.formattedOutput,
    keepIndent: template.keepIndent,
    lineNumbers: template.lineNumbers,
    reservedNames: template.reservedNames.slice(),
    options: { ...template.options }
  };

  if (normalizedOptions.input) config.input = normalizedOptions.input;
  if (normalizedOptions.output) config.output = normalizedOptions.output;
  if (normalizedOptions.preset) config.preset = normalizedOptions.preset;
  if (normalizedOptions.include && normalizedOptions.include.length) config.include = normalizedOptions.include.slice();
  if (normalizedOptions.exclude && normalizedOptions.exclude.length) config.exclude = normalizedOptions.exclude.slice();
  if (normalizedOptions.assetExclude && normalizedOptions.assetExclude.length) config.assetExclude = normalizedOptions.assetExclude.slice();
  if (normalizedOptions.parseHtml !== null && normalizedOptions.parseHtml !== undefined) config.parseHtml = !!normalizedOptions.parseHtml;
  if (normalizedOptions.honorConditionalComments !== null && normalizedOptions.honorConditionalComments !== undefined) {
    config.honorConditionalComments = !!normalizedOptions.honorConditionalComments;
  }
  if (normalizedOptions.protectMarkedComments !== null && normalizedOptions.protectMarkedComments !== undefined) {
    config.protectMarkedComments = !!normalizedOptions.protectMarkedComments;
  }
  if (normalizedOptions.ignoreImports !== null && normalizedOptions.ignoreImports !== undefined) config.ignoreImports = !!normalizedOptions.ignoreImports;
  if (normalizedOptions.manifest) config.manifest = normalizedOptions.manifest;
  if (normalizedOptions.maxOutputBytes !== null && normalizedOptions.maxOutputBytes !== undefined) config.maxOutputBytes = normalizedOptions.maxOutputBytes;
  if (normalizedOptions.maxGrowthRatio !== null && normalizedOptions.maxGrowthRatio !== undefined) config.maxGrowthRatio = normalizedOptions.maxGrowthRatio;
  if (normalizedOptions.noCopyAssets) config.copyAssets = false;
  if (normalizedOptions.reservedNames && normalizedOptions.reservedNames.length) config.reservedNames = normalizedOptions.reservedNames.slice();
  if (normalizedOptions.options && normalizedOptions.options.length) {
    config.options = {
      ...config.options,
      ...parseOptionOverrides(normalizedOptions.options)
    };
  }

  return config;
}

function initConfig(args = {}) {
  const target = path.resolve(DEFAULT_CONFIG_FILE);
  if (fs.existsSync(target)) {
    throw new Error(`${DEFAULT_CONFIG_FILE} already exists`);
  }
  const templateName = normalizeInitTemplateName(args.initTemplate || "browser-app");
  fs.writeFileSync(target, `${JSON.stringify(createExampleConfig({
    ...args,
    template: templateName
  }), null, 2)}\n`, "utf8");
  process.stdout.write(`Created ${target}\n`);
  process.stdout.write(`Template: ${templateName}\n`);
  process.stdout.write("This package is local-only. Install it from a workspace path, file: dependency, or internal npm pack tarball.\n");
  process.stdout.write("Next: jso-protector --config jso.config.json --release-check --json\n");
}

function migrateJavascriptObfuscatorConfig(sourcePath, args = {}) {
  if (!sourcePath) {
    throw new Error("--migrate-javascript-obfuscator requires a config file path");
  }
  const sourceConfigPath = path.resolve(sourcePath);
  const sourceConfig = loadConfigFile(sourceConfigPath, createConfigLoadContext(args));
  if (!sourceConfig || typeof sourceConfig !== "object" || Array.isArray(sourceConfig)) {
    throw new Error("javascript-obfuscator config must be an object");
  }

  const config = {
    $schema: "./node_modules/jso-protector/jso.config.schema.json",
    endpoint: DEFAULT_ENDPOINT,
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    projectName: "browser-release",
    input: args.input || "dist",
    output: args.output && path.extname(args.output).toLowerCase() !== ".json" ? args.output : "dist-protected",
    preset: "balanced",
    extensions: [".js", ".jsx"],
    exclude: ["**/*.map", "**/vendor/**", "**/polyfills-*.js", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: !!sourceConfig.parseHtml,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: !!sourceConfig.ignoreImports,
    reservedNames: [],
    manifest: "dist-protected/jso-manifest.json",
    maxGrowthRatio: 8,
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  };
  const notes = [];
  const mapped = [];
  const review = [];

  if (sourceConfig.optionsPreset !== undefined) {
    config.preset = presetFromJavascriptObfuscatorPreset(sourceConfig.optionsPreset);
    mapped.push({ from: "optionsPreset", to: "preset", note: `Options preset mapped to ${config.preset}.` });
  }

  mapBooleanOption(sourceConfig, "stringArray", config.options, "MoveStrings", mapped);
  mapBooleanOption(sourceConfig, "stringArrayIndexShift", config.options, "StringArrayIndexShift", mapped);
  mapBooleanOption(sourceConfig, "stringArrayShuffle", config.options, "StringArrayShuffle", mapped);
  mapBooleanOption(sourceConfig, "stringArrayRotate", config.options, "StringArrayRotate", mapped);
  if (sourceConfig.stringArrayIndexesType !== undefined) {
	config.options.StringArrayIndexesType = normalizeStringArrayIndexesType(sourceConfig.stringArrayIndexesType).join("\n");
	mapped.push({ from: "stringArrayIndexesType", to: "StringArrayIndexesType" });
  }
  mapBooleanOption(sourceConfig, "stringArrayCallsTransform", config.options, "StringArrayCallsTransform", mapped);
  if (sourceConfig.stringArrayCallsTransformThreshold !== undefined) {
	config.options.StringArrayCallsTransformThreshold = normalizeProbability(sourceConfig.stringArrayCallsTransformThreshold, "stringArrayCallsTransformThreshold");
	mapped.push({ from: "stringArrayCallsTransformThreshold", to: "StringArrayCallsTransformThreshold" });
  }
  if (sourceConfig.stringArrayWrappersCount !== undefined) {
	config.options.StringArrayWrappersCount = normalizeIntegerRange(sourceConfig.stringArrayWrappersCount, "stringArrayWrappersCount", 0, 10);
	mapped.push({ from: "stringArrayWrappersCount", to: "StringArrayWrappersCount", note: "Root-level wrapper count maps with a 0-10 bound; review per-scope placement differences." });
  }
  if (sourceConfig.stringArrayWrappersChainedCalls !== undefined) {
	if (typeof sourceConfig.stringArrayWrappersChainedCalls !== "boolean") throw new Error("stringArrayWrappersChainedCalls must be a boolean");
	config.options.StringArrayWrappersChainedCalls = sourceConfig.stringArrayWrappersChainedCalls;
	mapped.push({ from: "stringArrayWrappersChainedCalls", to: "StringArrayWrappersChainedCalls" });
  }
  if (sourceConfig.stringArrayWrappersParametersMaxCount !== undefined) {
	config.options.StringArrayWrappersParametersMaxCount = normalizeIntegerRange(sourceConfig.stringArrayWrappersParametersMaxCount, "stringArrayWrappersParametersMaxCount", 2, 5);
	mapped.push({ from: "stringArrayWrappersParametersMaxCount", to: "StringArrayWrappersParametersMaxCount" });
  }
  if (sourceConfig.stringArrayWrappersType !== undefined) {
	config.options.StringArrayWrappersType = normalizeStringArrayWrappersType(sourceConfig.stringArrayWrappersType);
	mapped.push({ from: "stringArrayWrappersType", to: "StringArrayWrappersType" });
  }
  mapBooleanOption(sourceConfig, "transformObjectKeys", config.options, "TransformObjectKeys", mapped);
  mapBooleanOption(sourceConfig, "splitStrings", config.options, "SplitStrings", mapped);
  if (sourceConfig.splitStringsChunkLength !== undefined) {
    config.options.SplitStringsChunkLength = normalizeSplitStringsChunkLength(sourceConfig.splitStringsChunkLength);
    mapped.push({ from: "splitStringsChunkLength", to: "SplitStringsChunkLength", note: "String split chunk length maps directly." });
  }
  mapBooleanOption(sourceConfig, "unicodeEscapeSequence", config.options, "EncodeStrings", mapped);
  mapBooleanOption(sourceConfig, "controlFlowFlattening", config.options, "FlatTransform", mapped);
  mapBooleanOption(sourceConfig, "controlFlowFlattening", config.options, "DeepObfuscate", mapped);
  mapBooleanOption(sourceConfig, "deadCodeInjection", config.options, "AddDeadCode", mapped);
  mapBooleanOption(sourceConfig, "renameGlobals", config.options, "RenameGlobals", mapped);
  mapBooleanOption(sourceConfig, "renameProperties", config.options, "RenameMembers", mapped);
  mapBooleanOption(sourceConfig, "selfDefending", config.options, "SelfDefending", mapped);
  mapBooleanOption(sourceConfig, "debugProtection", config.options, "DebugProtection", mapped);
  if (sourceConfig.debugProtectionInterval !== undefined) {
    config.options.DebugProtectionIntervalMilliseconds = normalizeDebugProtectionInterval(sourceConfig.debugProtectionInterval);
    mapped.push({ from: "debugProtectionInterval", to: "DebugProtectionIntervalMilliseconds", note: "Debug timing interval mapped in milliseconds." });
  }
  if (typeof sourceConfig.disableConsoleOutput === "boolean") {
    config.options.DisableConsoleOutput = sourceConfig.disableConsoleOutput;
    mapped.push({ from: "disableConsoleOutput", to: "DisableConsoleOutput", note: "Console suppression maps directly." });
  }
  if (typeof sourceConfig.numbersToExpressions === "boolean") {
    config.options.EncodeNumbers = sourceConfig.numbersToExpressions;
    mapped.push({ from: "numbersToExpressions", to: "EncodeNumbers", note: "Numeric literals map to native numeric encoding; expression shape is not preserved." });
  }
  if (sourceConfig.domainLockRedirectUrl !== undefined) {
    config.options.LockDomainRedirectUrl = normalizeRuntimeRedirectUrl(sourceConfig.domainLockRedirectUrl);
    mapped.push({ from: "domainLockRedirectUrl", to: "LockDomainRedirectUrl", note: "Domain-lock-specific redirect maps directly after scheme validation." });
  }
  if (sourceConfig.seed !== undefined) {
    config.options.Seed = normalizeSeedValue(sourceConfig.seed);
    mapped.push({ from: "seed", to: "Seed", note: "Deterministic seed maps directly; omit it for per-build polymorphism." });
  }
  if (sourceConfig.reservedStrings !== undefined) {
	config.options.ReservedStrings = normalizeReservedStringPatterns(sourceConfig.reservedStrings).join("\n");
	mapped.push({ from: "reservedStrings", to: "ReservedStrings", note: "Matching literals remain verbatim outside move/encode transforms." });
  }
  if (sourceConfig.forceTransformStrings !== undefined) {
	config.options.ForceTransformStrings = normalizeReservedStringPatterns(sourceConfig.forceTransformStrings, "forceTransformStrings").join("\n");
	mapped.push({ from: "forceTransformStrings", to: "ForceTransformStrings", note: "Matching literals override ReservedStrings and pass through enabled string transforms." });
  }

  if (sourceConfig.stringArrayEncoding !== undefined) {
    const encodings = Array.isArray(sourceConfig.stringArrayEncoding) ? sourceConfig.stringArrayEncoding : [sourceConfig.stringArrayEncoding];
    if (encodings.some((encoding) => String(encoding).toLowerCase() === "rc4")) {
      config.options.EncryptStrings = true;
      mapped.push({ from: "stringArrayEncoding", to: "EncryptStrings", note: "rc4-style string encoding maps to encrypted strings." });
    } else if (encodings.length) {
      config.options.EncodeStrings = true;
      mapped.push({ from: "stringArrayEncoding", to: "EncodeStrings", note: "String encoding maps to encoded strings." });
    }
  }

  if (sourceConfig.stringArrayThreshold !== undefined) {
    const threshold = normalizeProbability(sourceConfig.stringArrayThreshold, "stringArrayThreshold");
    config.options.StringArrayThreshold = threshold;
    if (sourceConfig.stringArray !== false) config.options.MoveStrings = threshold > 0;
    mapped.push({ from: "stringArrayThreshold", to: "StringArrayThreshold", note: "Per-unique-literal probability maps directly; zero disables moved strings." });
  }

  if (sourceConfig.deadCodeInjectionThreshold !== undefined) {
    const threshold = Number(sourceConfig.deadCodeInjectionThreshold);
    config.options.DeadcodeLevel = threshold >= 0.66 ? "High" : threshold >= 0.33 ? "Medium" : "Low";
    mapped.push({ from: "deadCodeInjectionThreshold", to: "DeadcodeLevel", note: "Threshold converted to nearest Low/Medium/High level." });
  }

  if (sourceConfig.identifierNamesGenerator !== undefined) {
    const generator = String(sourceConfig.identifierNamesGenerator).toLowerCase();
    config.options.IdentityStyle = generator.includes("hex") ? "v1hex" : "v2abcd";
    mapped.push({ from: "identifierNamesGenerator", to: "IdentityStyle", note: "Identifier generator converted to the nearest API identity style." });
  }

  if (sourceConfig.compact === true) {
    config.options.SelfCompression = true;
    config.options.CompressionRatio = "Best";
    mapped.push({ from: "compact", to: "SelfCompression", note: "Compact output maps to self-compression." });
  } else if (sourceConfig.compact === false) {
    config.options.WriteFormats = true;
    mapped.push({ from: "compact", to: "WriteFormats", note: "Non-compact output maps to formatted output for review builds." });
  }

  if (sourceConfig.target !== undefined) {
    const target = String(sourceConfig.target).toLowerCase();
    if (target.includes("node")) config.options.OptimizationMode = "NodeJS";
    else if (target.includes("browser")) config.options.OptimizationMode = "Web";
    mapped.push({ from: "target", to: "OptimizationMode", note: "Target converted to nearest runtime optimization mode." });
  }

  if (Array.isArray(sourceConfig.reservedNames) && sourceConfig.reservedNames.length) {
    config.reservedNames = sourceConfig.reservedNames.map((value) => String(value));
    mapped.push({ from: "reservedNames", to: "reservedNames", note: "Reserved name expressions are preserved." });
  }

  if (sourceConfig.domainLock !== undefined) {
    const domains = normalizeDomainLockList(sourceConfig.domainLock);
    if (domains.length) {
      config.options.LockDomain = true;
      config.options.LockDomainList = domains.join("\n");
      mapped.push({ from: "domainLock", to: "LockDomainList", note: "Domain lock entries map to LockDomain and LockDomainList; review subdomain and redirect behavior." });
    }
  }

  if (sourceConfig.parseHtml !== undefined) {
    config.parseHtml = sourceConfig.parseHtml === true;
    if (config.parseHtml) {
      mapped.push({ from: "parseHtml", to: "parseHtml", note: "Marked inline markup script protection is enabled." });
    }
  }

  for (const [key, note] of Object.entries(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS)) {
    if (Object.prototype.hasOwnProperty.call(sourceConfig, key)) {
      review.push({ option: key, note });
    }
  }

  const handled = new Set([
    "compact",
    "selfDefending",
    "debugProtection",
    "debugProtectionInterval",
	"disableConsoleOutput",
    "controlFlowFlattening",
    "deadCodeInjection",
    "deadCodeInjectionThreshold",
    "domainLock",
	"domainLockRedirectUrl",
    "identifierNamesGenerator",
    "optionsPreset",
    "parseHtml",
    "renameGlobals",
    "renameProperties",
    "selfDefending",
    "debugProtection",
    "reservedNames",
	"seed",
	"reservedStrings",
	"forceTransformStrings",
	"numbersToExpressions",
    "stringArray",
    "splitStrings",
    "splitStringsChunkLength",
    "stringArrayIndexShift",
    "stringArrayShuffle",
    "stringArrayRotate",
    "stringArrayIndexesType",
    "stringArrayCallsTransform",
    "stringArrayCallsTransformThreshold",
    "stringArrayWrappersCount",
    "stringArrayWrappersChainedCalls",
    "stringArrayWrappersParametersMaxCount",
    "stringArrayWrappersType",
    "transformObjectKeys",
    "stringArrayEncoding",
    "stringArrayThreshold",
    "target",
    "unicodeEscapeSequence",
    ...Object.keys(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS)
  ]);
  const unmapped = Object.keys(sourceConfig).filter((key) => !handled.has(key)).sort();
  if (unmapped.length) {
    notes.push(`Unmapped javascript-obfuscator option(s): ${unmapped.join(", ")}.`);
  }
  if (review.length) {
    notes.push("Some source options need manual review because they are not direct one-to-one API settings.");
  }
  notes.push("Run --validate-config after saving, then protect a separate output folder and smoke-test the result.");

  return {
    format: "jso-protector-migration",
    version: 1,
    source: sourceConfigPath,
    summary: buildMigrationReportSummary(sourceConfig, mapped, review, unmapped),
    config,
    mapped,
    review,
    unmapped,
    reviewReference: listJavascriptObfuscatorMigrationMap().review,
    nextCommands: buildMigrationNextCommands(args, review),
    notes
  };
}

function migrateJsConfuserConfig(sourcePath, args = {}) {
  if (!sourcePath) {
    throw new Error("--migrate-js-confuser requires a config file path");
  }
  const sourceConfigPath = path.resolve(sourcePath);
  const sourceConfig = loadConfigFile(sourceConfigPath, createConfigLoadContext(args));
  if (!sourceConfig || typeof sourceConfig !== "object" || Array.isArray(sourceConfig)) {
    throw new Error("JS-Confuser config must be an object");
  }

  const config = {
    $schema: "./node_modules/jso-protector/jso.config.schema.json",
    endpoint: DEFAULT_ENDPOINT,
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    projectName: "browser-release",
    input: args.input || "dist",
    output: args.output && path.extname(args.output).toLowerCase() !== ".json" ? args.output : "dist-protected",
    preset: "balanced",
    extensions: [".js", ".jsx"],
    exclude: ["**/*.map", "**/vendor/**", "**/polyfills-*.js", "**/*-obfuscated.js"],
    copyAssets: true,
    assetExclude: ["**/*.map"],
    mixedServer: false,
    parseHtml: false,
    honorConditionalComments: false,
    protectMarkedComments: false,
    ignoreImports: false,
    reservedNames: [],
    manifest: "dist-protected/jso-manifest.json",
    maxGrowthRatio: 8,
    options: {
      OptimizationMode: "Web",
      LockDomain: false,
      LockDate: false
    }
  };
  const notes = [];
  const mapped = [];
  const review = [];

  if (sourceConfig.preset !== undefined) {
    config.preset = presetFromJsConfuserPreset(sourceConfig.preset);
    mapped.push({ from: "preset", to: "preset", note: `JS-Confuser preset mapped to ${config.preset}.` });
  }

  mapBooleanOption(sourceConfig, "renameVariables", config.options, "ReplaceNames", mapped);
  mapBooleanOption(sourceConfig, "renameGlobals", config.options, "RenameGlobals", mapped);
  mapBooleanOption(sourceConfig, "globalConcealing", config.options, "RenameGlobals", mapped);
  mapBooleanOption(sourceConfig, "stringEncoding", config.options, "EncodeStrings", mapped);
  mapBooleanOption(sourceConfig, "stringConcealing", config.options, "EncryptStrings", mapped);
  mapBooleanOption(sourceConfig, "duplicateLiteralsRemoval", config.options, "MoveStrings", mapped);
  if (sourceConfig.stringSplitting !== undefined && typeof sourceConfig.stringSplitting !== "function") {
    config.options.SplitStrings = jsConfuserLockEnabled(sourceConfig.stringSplitting);
    mapped.push({ from: "stringSplitting", to: "SplitStrings", note: "String-splitting probability collapses to enabled/disabled; native chunk length defaults to 10." });
  }
  if (typeof sourceConfig.stringSplitting === "function") {
    review.push({ option: "stringSplitting", note: "Custom selector functions cannot be serialized or mapped one-to-one; review literal-selection policy manually." });
  }
  mapBooleanOption(sourceConfig, "controlFlowFlattening", config.options, "FlatTransform", mapped);
  mapBooleanOption(sourceConfig, "controlFlowFlattening", config.options, "DeepObfuscate", mapped);
  mapBooleanOption(sourceConfig, "deadCode", config.options, "AddDeadCode", mapped);
  if (typeof sourceConfig.hexadecimalNumbers === "boolean") {
    config.options.EncodeNumbers = sourceConfig.hexadecimalNumbers;
    mapped.push({ from: "hexadecimalNumbers", to: "EncodeNumbers", note: "Numeric literals map to native numeric encoding; hexadecimal formatting is not guaranteed." });
  }

  if (sourceConfig.stringCompression === true || sourceConfig.minify === true || sourceConfig.compact === true) {
    config.options.SelfCompression = true;
    config.options.CompressionRatio = "Best";
    mapped.push({ from: sourceConfig.stringCompression === true ? "stringCompression" : sourceConfig.minify === true ? "minify" : "compact", to: "SelfCompression", note: "Compression/minify maps to self-compression." });
  } else if (sourceConfig.minify === false || sourceConfig.compact === false) {
    config.options.WriteFormats = true;
    mapped.push({ from: sourceConfig.minify === false ? "minify" : "compact", to: "WriteFormats", note: "Disabled minify/compact maps to formatted output for review builds." });
  }

  if (sourceConfig.identifierGenerator !== undefined) {
    config.options.IdentityStyle = identityStyleFromGenerator(sourceConfig.identifierGenerator);
    mapped.push({ from: "identifierGenerator", to: "IdentityStyle", note: "Identifier generator converted to the nearest API identity style." });
  }

  if (sourceConfig.target !== undefined) {
    config.options.OptimizationMode = optimizationModeFromTarget(sourceConfig.target);
    mapped.push({ from: "target", to: "OptimizationMode", note: "Target converted to the nearest runtime optimization mode." });
  }

  if (sourceConfig.lock && typeof sourceConfig.lock === "object" && !Array.isArray(sourceConfig.lock)) {
    const lock = sourceConfig.lock;
    if (lock.domainLock !== undefined) {
      const domains = normalizeDomainLockList(lock.domainLock);
      if (domains.length) {
        config.options.LockDomain = true;
        config.options.LockDomainList = domains.join("\n");
        mapped.push({ from: "lock.domainLock", to: "LockDomainList", note: "Domain lock entries map to LockDomain and LockDomainList; review subdomain behavior." });
      }
    }
    if (lock.endDate !== undefined) {
      config.options.LockDate = true;
      config.options.LockDateValue = formatLockDateValue(lock.endDate);
      mapped.push({ from: "lock.endDate", to: "LockDateValue", note: "End-date locks map to LockDate and LockDateValue." });
    }
    if (lock.antiDebug !== undefined) {
	  config.options.DebugProtection = jsConfuserLockEnabled(lock.antiDebug);
	  mapped.push({ from: "lock.antiDebug", to: "DebugProtection", note: "Anti-debug enablement maps to the native debugger guard; numeric probability collapses to enabled/disabled." });
    }
    if (lock.integrity !== undefined) {
	  config.options.SelfDefending = jsConfuserLockEnabled(lock.integrity) || config.options.SelfDefending === true;
	  mapped.push({ from: "lock.integrity", to: "SelfDefending", note: "Integrity enablement maps to native self-integrity monitoring; numeric probability collapses to enabled/disabled." });
    }
    if (lock.selfDefending !== undefined) {
	  config.options.SelfDefending = jsConfuserLockEnabled(lock.selfDefending) || config.options.SelfDefending === true;
	  mapped.push({ from: "lock.selfDefending", to: "SelfDefending", note: "Self-defending enablement maps to native self-integrity monitoring." });
    }
    if (lock.startDate !== undefined) {
      config.options.LockStartDate = true;
      config.options.LockStartDateValue = formatLockDateValue(lock.startDate);
      mapped.push({ from: "lock.startDate", to: "LockStartDateValue", note: "Start-date locks map to LockStartDate and LockStartDateValue; validate the activation boundary in the target browser." });
    }
    if (lock.countermeasures !== undefined) {
      config.jsConfuserLockCountermeasures = formatReviewString(lock.countermeasures);
    }
    if (lock.tamperProtection !== undefined) {
	  config.options.AntiMonkeyPatching = jsConfuserLockEnabled(lock.tamperProtection);
	  mapped.push({ from: "lock.tamperProtection", to: "AntiMonkeyPatching", note: "Tamper-protection enablement maps to security-relevant global integrity checks; numeric probability collapses to enabled/disabled." });
    }

    for (const [key, note] of Object.entries(JS_CONFUSER_REVIEW_OPTIONS)) {
      if (!key.startsWith("lock.")) continue;
      const lockKey = key.slice("lock.".length);
      if (Object.prototype.hasOwnProperty.call(lock, lockKey)) {
        review.push({ option: key, note });
      }
    }
  }

  for (const [key, note] of Object.entries(JS_CONFUSER_REVIEW_OPTIONS)) {
    if (key.startsWith("lock.")) continue;
    if (Object.prototype.hasOwnProperty.call(sourceConfig, key)) {
      review.push({ option: key, note });
    }
  }

  const handled = new Set([
    "compact",
    "selfDefending",
    "debugProtection",
	"debugProtectionInterval",
	"debugProtectionIntervalMilliseconds",
	"disableConsoleOutput",
	"domainLockRedirectUrl",
    "controlFlowFlattening",
    "deadCode",
    "duplicateLiteralsRemoval",
    "globalConcealing",
    "identifierGenerator",
    "hexadecimalNumbers",
    "lock",
    "minify",
    "preset",
    "renameGlobals",
    "renameVariables",
    "stringCompression",
    "stringConcealing",
    "stringEncoding",
    "stringSplitting",
    "target",
    ...Object.keys(JS_CONFUSER_REVIEW_OPTIONS).filter((key) => !key.startsWith("lock."))
  ]);
  const unmapped = Object.keys(sourceConfig).filter((key) => !handled.has(key)).sort();
  if (unmapped.length) {
    notes.push(`Unmapped JS-Confuser option(s): ${unmapped.join(", ")}.`);
  }
  if (review.length) {
    notes.push("Some JS-Confuser options need manual review because they are not direct one-to-one hosted API settings.");
  }
  notes.push("Run --validate-config after saving, then protect a separate output folder and smoke-test the result.");

  return {
    format: "jso-protector-migration",
    version: 1,
    source: sourceConfigPath,
    summary: buildMigrationReportSummaryFromMap(sourceConfig, mapped, review, unmapped, JS_CONFUSER_MIGRATION_MAP),
    config,
    mapped,
    review,
    unmapped,
    reviewReference: listJsConfuserMigrationMap().review,
    nextCommands: buildMigrationNextCommands(args, review),
    notes
  };
}

function buildMigrationNextCommands(args = {}, review = []) {
  const configPath = args.output ? path.resolve(args.output) : "jso.config.json";
  const configArg = quoteCommandArg(configPath);
  const commands = [
    {
      label: "validate",
      command: `jso-protector --config ${configArg} --validate-config --json`
    },
    {
      label: "preview",
      command: `jso-protector --config ${configArg} --dry-run --json`
    },
    {
      label: "doctor",
      command: `jso-protector --config ${configArg} --doctor --json`
    },
    {
      label: "release-check",
      command: `jso-protector --config ${configArg} --release-check --json`
    },
    {
      label: "competitor-gap",
      command: `jso-protector --config ${configArg} --competitor-gap-report --json`
    }
  ];

  if (migrationReviewNeedsIdentifierCachePacket(review)) {
    commands.push({
      label: "migration-review",
      command: `jso-protector --config ${configArg} --migration-review --migration-review-output reports/migration-review.md`
    });
    commands.push({
      label: "identifier-cache-review",
      command: `jso-protector --config ${configArg} --identifier-cache-review --identifier-cache-review-output reports/identifier-cache-review.md`
    });
  } else if (migrationReviewNeedsRuntimeDefensePacket(review) || migrationReviewNeedsSourceMapEvidence(review) || migrationReviewNeedsGeneralPacket(review)) {
    commands.push({
      label: "migration-review",
      command: `jso-protector --config ${configArg} --migration-review --migration-review-output reports/migration-review.md`
    });
  }

  if (migrationReviewNeedsRuntimeDefensePacket(review)) {
    commands.push({
      label: "runtime-defense-review",
      command: `jso-protector --config ${configArg} --runtime-defense-review --runtime-defense-review-output reports/runtime-defense-review.md`
    });
  }

  commands.push({
    label: "protect",
    command: `jso-protector --config ${configArg} --manifest dist-protected/jso-manifest.json`
  });

  if (migrationReviewNeedsSourceMapEvidence(review)) {
    commands.push({
      label: "source-map-evidence",
      command: "jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md"
    });
  }

  return commands;
}

function migrationReviewNeedsSourceMapEvidence(review = []) {
  const names = new Set((review || []).map((item) => item && item.option).filter(Boolean));
  return [
    "sourceMap",
    "sourceMapBaseUrl",
    "sourceMapFileName",
    "sourceMapMode",
    "sourceMapSourcesMode",
    "inputFileName"
  ].some((name) => names.has(name));
}

function migrationReviewNeedsGeneralPacket(review = []) {
  return (review || []).some((item) => item && item.option);
}

function migrationReviewNeedsIdentifierCachePacket(review = []) {
  const names = new Set((review || []).map((item) => item && item.option).filter(Boolean));
  return [
    "identifierNamesCache",
    "identifierNamesCachePath",
    "identifiersDictionary",
    "identifiersPrefix"
  ].some((name) => names.has(name));
}

function migrationReviewNeedsRuntimeDefensePacket(review = []) {
  const names = new Set((review || []).map((item) => item && item.option).filter(Boolean));
  return RUNTIME_DEFENSE_REVIEW_OPTIONS.some((name) => names.has(name));
}

function quoteCommandArg(value) {
  const text = String(value || "");
  if (/^[A-Za-z0-9_./:\\-]+$/.test(text)) return text;
  return `"${text.replace(/"/g, '\\"')}"`;
}

function buildMigrationReportSummary(sourceConfig, mapped, review, unmapped) {
  const sourceOptions = Object.keys(sourceConfig || {}).length;
  const mappedSources = Array.from(new Set((mapped || []).map((item) => item.from)));
  const confidenceBySource = new Map(JAVASCRIPT_OBFUSCATOR_MIGRATION_MAP.map((entry) => [entry.source, entry.confidence]));
  const direct = mappedSources.filter((source) => confidenceBySource.get(source) === "direct").length;
  const approximate = mappedSources.filter((source) => confidenceBySource.get(source) === "approximate").length;
  return {
    sourceOptions,
    mappedOptions: mappedSources.length,
    direct,
    approximate,
    reviewOnly: (review || []).length,
    unmapped: (unmapped || []).length,
    automaticCoverage: sourceOptions ? Number((mappedSources.length / sourceOptions).toFixed(4)) : 1
  };
}

function buildMigrationReportSummaryFromMap(sourceConfig, mapped, review, unmapped, migrationMap) {
  const sourceKeys = Object.keys(sourceConfig || {});
  const lock = sourceConfig && sourceConfig.lock && typeof sourceConfig.lock === "object" && !Array.isArray(sourceConfig.lock)
    ? sourceConfig.lock
    : null;
  // JS-Confuser's lock bag is a namespace, not one option. Count each lock
  // leaf so mappedOptions and automaticCoverage use the same unit and can
  // never report impossible >100% coverage.
  const sourceOptions = sourceKeys.filter((key) => key !== "lock").length + (lock ? Object.keys(lock).length : (sourceKeys.includes("lock") ? 1 : 0));
  const mappedSources = Array.from(new Set((mapped || []).map((item) => item.from)));
  const confidenceBySource = new Map((migrationMap || []).map((entry) => [entry.source, entry.confidence]));
  const direct = mappedSources.filter((source) => confidenceBySource.get(source) === "direct").length;
  const approximate = mappedSources.filter((source) => confidenceBySource.get(source) === "approximate").length;
  return {
    sourceOptions,
    mappedOptions: mappedSources.length,
    direct,
    approximate,
    reviewOnly: (review || []).length,
    unmapped: (unmapped || []).length,
    automaticCoverage: sourceOptions ? Number((mappedSources.length / sourceOptions).toFixed(4)) : 1
  };
}

function listJavascriptObfuscatorMigrationMap() {
  const mappings = JAVASCRIPT_OBFUSCATOR_MIGRATION_MAP.map((entry) => ({
    source: entry.source,
    target: entry.target.slice(),
    confidence: entry.confidence,
    note: entry.note
  }));
  const review = Object.entries(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS).map(([option, note]) => ({
    option,
    note
  }));

  return {
    summary: buildMigrationMapSummary(mappings, review),
    mappings,
    review
  };
}

function listJsConfuserMigrationMap() {
  const mappings = JS_CONFUSER_MIGRATION_MAP.map((entry) => ({
    source: entry.source,
    target: entry.target.slice(),
    confidence: entry.confidence,
    note: entry.note
  }));
  const review = Object.entries(JS_CONFUSER_REVIEW_OPTIONS).map(([option, note]) => ({
    option,
    note
  }));

  return {
    summary: buildMigrationMapSummary(mappings, review),
    mappings,
    review
  };
}

function normalizeCompatibilityOptionName(option) {
  const text = String(option || "").trim();
  if (!text) return "";
  const withoutPrefix = text.replace(/^--/, "");
  if (!withoutPrefix.includes("-")) return withoutPrefix;
  return withoutPrefix.replace(/-([a-z0-9])/g, (_match, letter) => letter.toUpperCase());
}

function explainCompatibilityOption(option) {
  const normalized = normalizeCompatibilityOptionName(option);
  const mapped = JAVASCRIPT_OBFUSCATOR_MIGRATION_MAP.find((entry) => entry.source.toLowerCase() === normalized.toLowerCase());
  if (mapped) {
    return {
      option: normalized,
      status: "mapped",
      target: mapped.target.slice(),
      confidence: mapped.confidence,
      note: mapped.note
    };
  }

  const reviewKey = Object.keys(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS).find((key) => key.toLowerCase() === normalized.toLowerCase());
  if (reviewKey) {
    return {
      option: reviewKey,
      status: "review-only",
      target: [],
      confidence: "review",
      note: JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS[reviewKey]
    };
  }

  return {
    option: normalized || option,
    status: "unknown",
    target: [],
    confidence: "unknown",
    note: "No local compatibility mapping is known yet. Run --list-migration-map --json to inspect supported mappings and review-only options."
  };
}

function explainJsConfuserCompatibilityOption(option) {
  const normalized = String(option || "").trim().replace(/^--/, "");
  const mapped = JS_CONFUSER_MIGRATION_MAP.find((entry) => entry.source.toLowerCase() === normalized.toLowerCase());
  if (mapped) {
    return {
      option: mapped.source,
      status: "mapped",
      target: mapped.target.slice(),
      confidence: mapped.confidence,
      note: mapped.note
    };
  }

  const reviewKey = Object.keys(JS_CONFUSER_REVIEW_OPTIONS).find((key) => key.toLowerCase() === normalized.toLowerCase());
  if (reviewKey) {
    return {
      option: reviewKey,
      status: "review-only",
      target: [],
      confidence: "review",
      note: JS_CONFUSER_REVIEW_OPTIONS[reviewKey]
    };
  }

  return {
    option: normalized || option,
    status: "unknown",
    target: [],
    confidence: "unknown",
    note: "No local JS-Confuser compatibility mapping is known yet. Run --list-js-confuser-migration-map --json to inspect supported mappings and review-only options."
  };
}

function writeCompatibilityExplanation(option, json) {
  const explanation = explainCompatibilityOption(option);
  if (json) {
    process.stdout.write(`${JSON.stringify(explanation, null, 2)}\n`);
    return;
  }
  process.stdout.write(`${explanation.option}: ${explanation.status}\n`);
  if (explanation.target.length) process.stdout.write(`Targets: ${explanation.target.join(", ")}\n`);
  process.stdout.write(`${explanation.note}\n`);
}

function writeJsConfuserCompatibilityExplanation(option, json) {
  const explanation = explainJsConfuserCompatibilityOption(option);
  if (json) {
    process.stdout.write(`${JSON.stringify(explanation, null, 2)}\n`);
    return;
  }
  process.stdout.write(`${explanation.option}: ${explanation.status}\n`);
  if (explanation.target.length) process.stdout.write(`Targets: ${explanation.target.join(", ")}\n`);
  process.stdout.write(`${explanation.note}\n`);
}

function buildMigrationMapSummary(mappings, review) {
  const direct = mappings.filter((entry) => entry.confidence === "direct").length;
  const approximate = mappings.filter((entry) => entry.confidence === "approximate").length;
  return {
    mapped: mappings.length,
    direct,
    approximate,
    reviewOnly: review.length,
    totalKnown: mappings.length + review.length
  };
}

function writeMigrationMap(json) {
  const map = listJavascriptObfuscatorMigrationMap();
  if (json) {
    process.stdout.write(`${JSON.stringify(map, null, 2)}\n`);
    return;
  }

  process.stdout.write("javascript-obfuscator migration map:\n");
  process.stdout.write(`Mapped: ${map.summary.mapped} (${map.summary.direct} direct, ${map.summary.approximate} approximate). Review-only: ${map.summary.reviewOnly}. Total known: ${map.summary.totalKnown}.\n`);
  for (const item of map.mappings) {
    process.stdout.write(`- ${item.source} -> ${item.target.join(", ")} (${item.confidence}) - ${item.note}\n`);
  }
  process.stdout.write("Manual review options:\n");
  for (const item of map.review) {
    process.stdout.write(`- ${item.option}: ${item.note}\n`);
  }
}

function writeJsConfuserMigrationMap(json) {
  const map = listJsConfuserMigrationMap();
  if (json) {
    process.stdout.write(`${JSON.stringify(map, null, 2)}\n`);
    return;
  }

  process.stdout.write("JS-Confuser migration map:\n");
  process.stdout.write(`Mapped: ${map.summary.mapped} (${map.summary.direct} direct, ${map.summary.approximate} approximate). Review-only: ${map.summary.reviewOnly}. Total known: ${map.summary.totalKnown}.\n`);
  for (const item of map.mappings) {
    process.stdout.write(`- ${item.source} -> ${item.target.join(", ")} (${item.confidence}) - ${item.note}\n`);
  }
  process.stdout.write("Manual review options:\n");
  for (const item of map.review) {
    process.stdout.write(`- ${item.option}: ${item.note}\n`);
  }
}

function mapBooleanOption(source, sourceKey, target, targetKey, mapped) {
  if (source[sourceKey] === true) {
    target[targetKey] = true;
    mapped.push({ from: sourceKey, to: targetKey });
  }
}

function writeMigrationReport(report, args = {}) {
  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  const targetPath = args.output ? path.resolve(args.output) : null;
  if (targetPath) {
    if (fs.existsSync(targetPath)) {
      throw new Error(`Output config already exists: ${targetPath}`);
    }
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, `${JSON.stringify(report.config, null, 2)}\n`, "utf8");
    process.stdout.write(`Created ${targetPath}\n`);
  } else {
    process.stdout.write(`${JSON.stringify(report.config, null, 2)}\n`);
  }

  if (report.mapped.length) {
    process.stderr.write(`Mapped ${report.mapped.length} option(s).\n`);
  }
  process.stderr.write(`Migration summary: ${report.summary.mappedOptions}/${report.summary.sourceOptions} source option(s) mapped (${report.summary.direct} direct, ${report.summary.approximate} approximate), ${report.summary.reviewOnly} review-only, ${report.summary.unmapped} unmapped.\n`);
  for (const item of report.review) {
    process.stderr.write(`Review ${item.option}: ${item.note}\n`);
  }
  if (report.unmapped.length) {
    process.stderr.write(`Unmapped option(s): ${report.unmapped.join(", ")}\n`);
  }
  for (const note of report.notes) {
    process.stderr.write(`${note}\n`);
  }
  if (report.nextCommands && report.nextCommands.length) {
    process.stderr.write("Next commands:\n");
    for (const entry of report.nextCommands) {
      process.stderr.write(`- ${entry.label}: ${entry.command}\n`);
    }
  }
}

function collectFiles(inputPath, outputPath, extensions, excludePatterns, includePatterns = [], markupExtensions = DEFAULT_MARKUP_EXTENSIONS) {
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Input path does not exist: ${inputPath}`);
  }

  const inputStat = fs.statSync(inputPath);
  const files = [];
  const outputRelative = inputStat.isDirectory() ? getNestedOutputRelative(inputPath, outputPath) : null;

  if (inputStat.isFile()) {
    const ext = path.extname(inputPath).toLowerCase();
    if (!extensions.includes(ext)) return files;
    if (isMarkupFilePath(inputPath, markupExtensions) && !hasHtmlProtectionMarkers(inputPath)) return files;
    if (!isIncluded(path.basename(inputPath), includePatterns)) return files;
    files.push({
      source: inputPath,
      relative: path.basename(inputPath),
      target: fs.existsSync(outputPath) && fs.statSync(outputPath).isDirectory()
        ? path.join(outputPath, path.basename(inputPath))
        : outputPath
    });
    return files;
  }

  walk(inputPath, (filePath) => {
    const relative = path.relative(inputPath, filePath).replace(/\\/g, "/");
    const ext = path.extname(filePath).toLowerCase();
    if (!extensions.includes(ext)) return;
    if (isMarkupFilePath(filePath, markupExtensions) && !hasHtmlProtectionMarkers(filePath)) return;
    if (!isIncluded(relative, includePatterns)) return;
    if (isInsideRelativePath(relative, outputRelative)) return;
    if (isExcluded(relative, excludePatterns)) return;
    files.push({
      source: filePath,
      relative,
      target: path.join(outputPath, relative)
    });
  });

  return files;
}

// ── Named configuration sets ──────────────────────────────────────────────
//
// The granularity layer between "one option set per project" and the
// per-function markers (@virtualize, protect-begin/end): apply a different
// protection profile to different parts of one app in a single build. The
// config surface, schema and pure resolver (config/named-sets.js, tested in
// test/named-sets.test.js) predate this wiring — this is where they finally
// reach the protect flow. Semantics are the resolver's: FIRST matching set
// wins per file (write sets in priority order), a set's options merge on top
// of the baseline, and a set's preset contributes that preset's option block
// before the set's own options. Files matching no set keep the baseline.
//
// Each named set becomes its own API round; the hosted plan gate prices each
// round on the options it actually carries, so a "maximum" set on a plan
// that cannot afford it fails THAT group with the normal API error and the
// other groups are untouched.

function hasNamedSets(config) {
  return !!(config && config.namedSets && Object.keys(config.namedSets).length);
}

function validateNamedSets(sets) {
  if (sets === null || sets === undefined) return;
  if (typeof sets !== "object" || Array.isArray(sets)) throw new Error("namedSets must be an object of named set definitions.");
  for (const name of Object.keys(sets)) {
    const set = sets[name];
    if (!set || typeof set !== "object" || Array.isArray(set)) throw new Error(`namedSets.${name} must be an object.`);
    if (!Array.isArray(set.match) || !set.match.length || set.match.some((p) => typeof p !== "string" || !p.length)) {
      throw new Error(`namedSets.${name}.match must be a non-empty array of glob strings.`);
    }
    if (set.preset !== undefined && !Object.prototype.hasOwnProperty.call(PRESET_OPTIONS, String(set.preset).toLowerCase())) {
      throw new Error(`namedSets.${name}.preset "${set.preset}" is unknown. Use standard, balanced, or maximum.`);
    }
    if (set.options !== undefined && (typeof set.options !== "object" || set.options === null || Array.isArray(set.options))) {
      throw new Error(`namedSets.${name}.options must be an object of API option values.`);
    }
    for (const key of Object.keys(set)) {
      if (key !== "match" && key !== "preset" && key !== "options" && key !== "countermeasures") {
        throw new Error(`namedSets.${name} has unknown key "${key}" (allowed: match, preset, options, countermeasures).`);
      }
    }
  }
}

function groupFilesByNamedSets(config, files) {
  const resolved = namedSetsResolver.resolveForFiles(config, files.map((file) => file.relative));
  const groups = new Map();
  for (const file of files) {
    const resolution = resolved[file.relative];
    const key = resolution.set || "";
    if (!groups.has(key)) groups.set(key, { setName: resolution.set, files: [] });
    groups.get(key).files.push(file);
  }
  return Array.from(groups.values());
}

function applyNamedSetToConfig(config, setName) {
  if (!setName) return config;
  const set = config.namedSets[setName];
  const presetName = set.preset ? String(set.preset).toLowerCase() : null;
  const presetOptions = presetName ? PRESET_OPTIONS[presetName] || {} : {};
  const groupConfig = {
    ...config,
    preset: presetName || config.preset,
    options: { ...config.options, ...presetOptions, ...(set.options || {}) }
  };
  if (set.countermeasures !== undefined) groupConfig.countermeasures = set.countermeasures;
  return groupConfig;
}

// Runs one protection round per named-set group and writes each group's
// outputs as it completes. Returns a MERGED result whose Items span every
// group (file names are relative paths, disjoint across groups, so no
// collisions), with the first group's Report kept as .Report for shape
// compatibility and every group's report collected in .Reports.
async function protectGroupedFiles(config, files) {
  validateNamedSets(config.namedSets);
  const groups = groupFilesByNamedSets(config, files);
  const merged = { Type: "Succeed", Items: [], Report: null, Reports: [] };
  const transforms = new Map();
  const groupSummaries = [];
  for (const group of groups) {
    const groupConfig = applyNamedSetToConfig(config, group.setName);
    const groupProtection = buildProtectionItems(groupConfig, group.files);
    const groupResult = await protectItems(groupConfig, groupProtection.items);
    writeResults(group.files, groupResult, groupProtection.transforms, groupConfig);
    merged.Items.push(...(groupResult.Items || []));
    if (groupResult.Report) {
      merged.Reports.push(groupResult.Report);
      if (!merged.Report) merged.Report = groupResult.Report;
    }
    for (const [name, transform] of groupProtection.transforms) transforms.set(name, transform);
    groupSummaries.push({
      set: group.setName,
      files: group.files.map((file) => file.relative),
      preset: groupConfig.preset,
      options: Object.keys(groupConfig.options).filter((key) => key !== "reservedNames").sort()
    });
  }
  return { result: merged, transforms, groups: groupSummaries };
}

function collectAssets(inputPath, outputPath, protectedFiles, assetExcludePatterns) {
  const assets = [];
  if (!fs.existsSync(inputPath) || fs.statSync(inputPath).isFile()) {
    return assets;
  }

  const protectedSources = new Set(protectedFiles.map((file) => path.resolve(file.source)));
  const outputRelative = getNestedOutputRelative(inputPath, outputPath);

  walk(inputPath, (filePath) => {
    if (protectedSources.has(path.resolve(filePath))) return;

    const relative = path.relative(inputPath, filePath).replace(/\\/g, "/");
    if (isInsideRelativePath(relative, outputRelative)) return;
    if (isExcluded(relative, assetExcludePatterns)) return;

    assets.push({
      source: filePath,
      relative,
      target: path.join(outputPath, relative)
    });
  });

  return assets;
}

function getNestedOutputRelative(inputPath, outputPath) {
  const relative = path.relative(path.resolve(inputPath), path.resolve(outputPath)).replace(/\\/g, "/");
  if (!relative || relative === "." || relative.startsWith("../") || path.isAbsolute(relative)) return null;
  return relative;
}

function isInsideRelativePath(relativePath, parentRelativePath) {
  if (!parentRelativePath) return false;
  return relativePath === parentRelativePath || relativePath.startsWith(`${parentRelativePath}/`);
}

function walk(dir, visit) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(entryPath, visit);
    else if (entry.isFile()) visit(entryPath);
  }
}

function isExcluded(relativePath, patterns) {
  const normalized = relativePath.replace(/\\/g, "/");
  return patterns.some((pattern) => globLikeMatch(normalized, pattern));
}

function isIncluded(relativePath, patterns) {
  if (!patterns || !patterns.length) return true;
  const normalized = relativePath.replace(/\\/g, "/");
  return patterns.some((pattern) => globLikeMatch(normalized, pattern));
}

function globLikeMatch(value, pattern) {
  const normalizedPattern = pattern.replace(/\\/g, "/");
  const escaped = normalizedPattern
    .replace(/\\/g, "/")
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*");
  if (new RegExp(`^${escaped}$`).test(value)) return true;
  if (normalizedPattern.startsWith("**/")) {
    const withoutPrefix = escaped.replace(/^\.\*\//, "");
    return new RegExp(`(^|/)${withoutPrefix}$`).test(value);
  }
  return false;
}

function buildRequest(config, files) {
  return buildRequestFromItems(config, buildProtectionItems(config, files).items);
}

function buildProtectionItems(config, files) {
  const items = [];
  const transforms = new Map();

  // Watermark injection happens once per build, BEFORE anything else
  // touches the source. We prepend an HMAC-signed header comment that
  // the obfuscator's KeepComment option preserves through every
  // transform, so a verifier can later read the protected output and
  // confirm "this artifact came from a build with this key". When
  // --watermark is set we also force-enable KeepComment, otherwise
  // strict configs that disabled it would silently lose the marker.
  if (config.watermark) {
    if (!config.watermarkKey) {
      throw new Error("--watermark requires --watermark-key (or JSO_WATERMARK_KEY env)");
    }
    if (config.options && config.options.KeepComment === false) {
      // Explicit opt-out wins; warn rather than silently overriding.
      throw new Error("--watermark conflicts with KeepComment=false; the header comment must be preserved");
    }
    if (config.options) config.options.KeepComment = true;
  }

  for (const file of files) {
    let code = fs.readFileSync(file.source, "utf8");
    if (config.watermark) {
      code = watermark.injectInto(code, config.watermark, config.watermarkKey);
    }
    const plan = buildFileProtectionPlan(config, file.relative, code);
    items.push(...plan.items);
    if (plan.transform) {
      transforms.set(normalizeName(file.relative), plan.transform);
    }
  }

  return { items, transforms };
}

function buildProtectionItemsFromInputItems(config, inputItems) {
  const items = [];
  const transforms = new Map();

  for (const input of inputItems || []) {
    const fileName = input.FileName;
    const code = String(input.FileCode || "");
    const plan = buildFileProtectionPlan(config, fileName, code);
    items.push(...plan.items);
    if (plan.transform) {
      transforms.set(normalizeName(fileName), plan.transform);
    }
  }

  return { items, transforms };
}

function describeProtectionTransforms(protection) {
  const items = protection && Array.isArray(protection.items) ? protection.items : [];
  const transforms = protection && protection.transforms instanceof Map ? protection.transforms : new Map();
  return {
    apiItems: items.length,
    transformedFiles: Array.from(transforms.entries()).map(([fileName, transform]) => {
      const pieces = Array.isArray(transform && transform.pieces) ? transform.pieces : [];
      return {
        fileName,
        type: transform && transform.type ? transform.type : "unknown",
        apiItems: pieces.filter((piece) => piece.type === "item").length,
        preservedParts: pieces.filter((piece) => piece.type === "raw" && piece.code).length
      };
    })
  };
}

function addProtectionSummary(summary, protection) {
  return {
    ...summary,
    processing: describeProtectionTransforms(protection)
  };
}

function buildFileProtectionPlan(config, fileName, code) {
  if (isMarkupFile(fileName, config.markupExtensions)) {
    if (!config.parseHtml) {
      throw new Error(`${fileName} is a markup/template file. Pass --parse-html and mark inline scripts with data-javascript-obfuscator, or remove the markup extension from protected extensions.`);
    }
    return buildHtmlProtectionPlan(config, fileName, code);
  }
  return buildCodeProtectionPlan(config, fileName, code);
}

function buildCodeProtectionPlan(config, fileName, code) {
  const preservedRanges = collectPreservedCodeRanges(config, fileName, code);
  if (!preservedRanges.length) {
    return {
      items: [{ FileName: fileName, FileCode: code }],
      transform: null
    };
  }

  const items = [];
  const pieces = [];
  let cursor = 0;

  for (const range of preservedRanges) {
    if (range.start > cursor) {
      const segment = code.slice(cursor, range.start);
      if (segment.trim()) {
        const itemName = makePartFileName(fileName, items.length + 1);
        items.push({ FileName: itemName, FileCode: segment });
        pieces.push({ type: "item", itemName });
      } else {
        pieces.push({ type: "raw", code: segment });
      }
    }
    pieces.push({ type: "raw", code: code.slice(range.start, range.end) });
    cursor = range.end;
  }

  if (cursor < code.length) {
    const segment = code.slice(cursor);
    if (segment.trim()) {
      const itemName = makePartFileName(fileName, items.length + 1);
      items.push({ FileName: itemName, FileCode: segment });
      pieces.push({ type: "item", itemName });
    } else {
      pieces.push({ type: "raw", code: segment });
    }
  }

  return {
    items,
    transform: { type: "parts", fileName, pieces }
  };
}

function collectPreservedCodeRanges(config, fileName, code) {
  const ranges = [];
  const hasConditional = hasConditionalMarkers(code);
  const hasProtect = hasProtectMarkers(code);

  if (hasConditional && hasProtect) {
    throw new Error(`${fileName} mixes javascript-obfuscator:disable/enable markers with javascript-obfuscator:protect-begin/end markers. Use one marker style per file.`);
  }

  if (hasConditional) {
    if (!config.honorConditionalComments) {
      const markerIndex = findFirstConditionalMarkerIndex(code);
      const location = markerIndex >= 0 ? `:${formatSourceLocation(code, markerIndex)}` : "";
      throw new Error(`${fileName}${location} contains javascript-obfuscator conditional comments. Pass --honor-conditional-comments to preserve disabled regions, or remove the markers.`);
    }

    validateConditionalMarkers(fileName, code);
    ranges.push(...getDisabledConditionalRanges(code));
  }

  if (hasProtect) {
    if (!config.protectMarkedComments) {
      const markerIndex = findFirstProtectMarkerIndex(code);
      const location = markerIndex >= 0 ? `:${formatSourceLocation(code, markerIndex)}` : "";
      throw new Error(`${fileName}${location} contains javascript-obfuscator protect markers. Pass --protect-marked-comments to protect only marked regions, or remove the markers.`);
    }

    validateProtectMarkers(fileName, code);
    ranges.push(...getUnprotectedMarkedRanges(code));
  }

  if (config.ignoreImports) {
    ranges.push(...findIgnoredImportRanges(code));
  }

  return mergeRanges(ranges);
}

function getDisabledConditionalRanges(code) {
  return splitConditionalCodeWithOffsets(code)
    .filter((piece) => !piece.enabled && piece.end > piece.start)
    .map((piece) => ({ start: piece.start, end: piece.end }));
}

function getUnprotectedMarkedRanges(code) {
  return splitProtectMarkedCodeWithOffsets(code)
    .filter((piece) => !piece.enabled && piece.end > piece.start)
    .map((piece) => ({ start: piece.start, end: piece.end }));
}

function buildHtmlProtectionPlan(config, fileName, html) {
  validateMarkedHtmlScripts(fileName, html);
  const blocks = findMarkedHtmlScripts(html);
  if (!blocks.length) {
    return {
      items: [],
      transform: {
        type: "static",
        fileName,
        code: html
      }
    };
  }

  const items = [];
  const pieces = [];
  let cursor = 0;

  blocks.forEach((block, index) => {
    pieces.push({ type: "raw", code: html.slice(cursor, block.contentStart) });
    const scriptPlan = buildCodeProtectionPlan(config, `${fileName}.script${index + 1}.js`, block.code);
    for (const item of scriptPlan.items) items.push(item);
    if (scriptPlan.transform) {
      pieces.push(...scriptPlan.transform.pieces);
    } else if (scriptPlan.items[0]) {
      pieces.push({ type: "item", itemName: scriptPlan.items[0].FileName });
    }
    cursor = block.contentEnd;
  });
  pieces.push({ type: "raw", code: html.slice(cursor) });

  return {
    items,
    transform: { type: "parts", fileName, pieces }
  };
}

function composeProtectionOutput(transform, byName) {
  if (!transform) return null;
  if (transform.type === "static") return transform.code;
  return (transform.pieces || []).map((piece) => {
    if (piece.type === "raw") return piece.code;
    const item = byName.get(normalizeName(piece.itemName));
    if (!item) {
      throw new Error(`API response did not include output for ${piece.itemName}`);
    }
    return item.FileCode || "";
  }).join("");
}

function stripSourceMapComments(code) {
  const text = String(code || "");
  return text
    .replace(SOURCE_MAP_COMMENT_LINE_PATTERN, "")
    .replace(SOURCE_MAP_COMMENT_BLOCK_PATTERN, "");
}

function finalizeProtectedCode(code, config = null) {
  if (!config || config.removeSourceMaps !== false) {
    return stripSourceMapComments(code);
  }
  return String(code || "");
}

function composeProtectionItemOutput(fileName, result, transforms = new Map(), config = null) {
  const byName = new Map((result.Items || []).map((item) => [normalizeName(item.FileName), item]));
  const transform = transforms instanceof Map ? transforms.get(normalizeName(fileName)) : null;
  if (transform) return finalizeProtectedCode(composeProtectionOutput(transform, byName), config);
  const item = byName.get(normalizeName(fileName));
  if (!item) {
    throw new Error(`API response did not include output for ${fileName}`);
  }
  return finalizeProtectedCode(item.FileCode || "", config);
}

function makePartFileName(fileName, index) {
  const normalized = normalizeName(fileName);
  const ext = path.posix.extname(normalized) || ".js";
  const base = normalized.slice(0, normalized.length - ext.length).replace(/[^A-Za-z0-9_./-]/g, "_");
  return `${base}.jso-part-${index}${DEFAULT_MARKUP_EXTENSIONS.includes(ext) ? ".js" : ext}`;
}

function hasConditionalMarkers(code) {
  CONDITIONAL_MARKER_PATTERN.lastIndex = 0;
  return CONDITIONAL_MARKER_PATTERN.test(code);
}

function hasProtectMarkers(code) {
  PROTECT_MARKER_PATTERN.lastIndex = 0;
  return PROTECT_MARKER_PATTERN.test(code);
}

function findFirstConditionalMarkerIndex(code) {
  CONDITIONAL_MARKER_PATTERN.lastIndex = 0;
  const match = CONDITIONAL_MARKER_PATTERN.exec(code);
  return match ? match.index : -1;
}

function findFirstProtectMarkerIndex(code) {
  PROTECT_MARKER_PATTERN.lastIndex = 0;
  const match = PROTECT_MARKER_PATTERN.exec(code);
  return match ? match.index : -1;
}

function validateConditionalMarkers(fileName, code) {
  let disabled = false;
  let disabledAt = -1;
  CONDITIONAL_MARKER_PATTERN.lastIndex = 0;
  let match;
  while ((match = CONDITIONAL_MARKER_PATTERN.exec(code)) !== null) {
    const action = match[1] || match[2];
    if (action === "disable") {
      if (disabled) {
        throw new Error(`${fileName}:${formatSourceLocation(code, match.index)} has nested javascript-obfuscator:disable markers. Close the disabled region with javascript-obfuscator:enable before starting another disabled region.`);
      }
      disabled = true;
      disabledAt = match.index;
    } else if (!disabled) {
      throw new Error(`${fileName}:${formatSourceLocation(code, match.index)} has javascript-obfuscator:enable without a matching javascript-obfuscator:disable marker.`);
    } else {
      disabled = false;
      disabledAt = -1;
    }
  }
  if (disabled) {
    throw new Error(`${fileName}:${formatSourceLocation(code, disabledAt)} has javascript-obfuscator:disable without a matching javascript-obfuscator:enable marker.`);
  }
}

function validateProtectMarkers(fileName, code) {
  let protecting = false;
  let protectingAt = -1;
  PROTECT_MARKER_PATTERN.lastIndex = 0;
  let match;
  while ((match = PROTECT_MARKER_PATTERN.exec(code)) !== null) {
    const action = match[1] || match[2];
    if (action === "begin") {
      if (protecting) {
        throw new Error(`${fileName}:${formatSourceLocation(code, match.index)} has nested javascript-obfuscator:protect-begin markers. Close the protected region with javascript-obfuscator:protect-end before starting another protected region.`);
      }
      protecting = true;
      protectingAt = match.index;
    } else if (!protecting) {
      throw new Error(`${fileName}:${formatSourceLocation(code, match.index)} has javascript-obfuscator:protect-end without a matching javascript-obfuscator:protect-begin marker.`);
    } else {
      protecting = false;
      protectingAt = -1;
    }
  }
  if (protecting) {
    throw new Error(`${fileName}:${formatSourceLocation(code, protectingAt)} has javascript-obfuscator:protect-begin without a matching javascript-obfuscator:protect-end marker.`);
  }
}

function splitConditionalCode(code) {
  return splitConditionalCodeWithOffsets(code).map((piece) => ({
    enabled: piece.enabled,
    code: piece.code
  }));
}

function splitConditionalCodeWithOffsets(code) {
  const pieces = [];
  let enabled = true;
  let cursor = 0;
  CONDITIONAL_MARKER_PATTERN.lastIndex = 0;
  let match;
  while ((match = CONDITIONAL_MARKER_PATTERN.exec(code)) !== null) {
    if (match.index > cursor) {
      pieces.push({ enabled, code: code.slice(cursor, match.index), start: cursor, end: match.index });
    }
    const marker = match[0];
    const action = match[1] || match[2];
    pieces.push({ enabled: false, code: marker, start: match.index, end: match.index + marker.length });
    enabled = action === "enable";
    cursor = match.index + marker.length;
  }
  if (cursor < code.length) {
    pieces.push({ enabled, code: code.slice(cursor), start: cursor, end: code.length });
  }
  return pieces;
}

function splitProtectMarkedCode(code) {
  return splitProtectMarkedCodeWithOffsets(code).map((piece) => ({
    enabled: piece.enabled,
    code: piece.code
  }));
}

function splitProtectMarkedCodeWithOffsets(code) {
  const pieces = [];
  let enabled = false;
  let cursor = 0;
  PROTECT_MARKER_PATTERN.lastIndex = 0;
  let match;
  while ((match = PROTECT_MARKER_PATTERN.exec(code)) !== null) {
    if (match.index > cursor) {
      pieces.push({ enabled, code: code.slice(cursor, match.index), start: cursor, end: match.index });
    }
    const marker = match[0];
    const action = match[1] || match[2];
    pieces.push({ enabled: false, code: marker, start: match.index, end: match.index + marker.length });
    enabled = action === "begin";
    cursor = match.index + marker.length;
  }
  if (cursor < code.length) {
    pieces.push({ enabled, code: code.slice(cursor), start: cursor, end: code.length });
  }
  return pieces;
}

function findIgnoredImportRanges(code) {
  const ranges = [];
  ranges.push(...findModuleImportStatementRanges(code));
  ranges.push(...findStaticCallStatementRanges(code, "require"));
  ranges.push(...findStaticCallStatementRanges(code, "import"));
  return mergeRanges(ranges);
}

function findModuleImportStatementRanges(code) {
  const ranges = [];
  let cursor = 0;

  while (cursor < code.length) {
    const lineStart = cursor;
    const statementStart = skipHorizontalWhitespace(code, lineStart);
    if (
      startsWithWord(code, statementStart, "import") ||
      startsWithWord(code, statementStart, "export")
    ) {
      const statementEnd = findStatementEnd(code, statementStart);
      if (statementEnd > statementStart) {
        const statement = code.slice(statementStart, statementEnd);
        if (/^\s*import\b/.test(statement) || /^\s*export\b[\s\S]*\bfrom\b/.test(statement)) {
          ranges.push({ start: lineStart, end: statementEnd });
          cursor = statementEnd;
          continue;
        }
      }
    }
    cursor = advanceToNextLine(code, lineStart);
  }

  return ranges;
}

function findStaticCallStatementRanges(code, calleeName) {
  const ranges = [];
  let searchIndex = 0;

  while (searchIndex < code.length) {
    const callIndex = code.indexOf(`${calleeName}(`, searchIndex);
    if (callIndex === -1) break;
    if (isInsideStringOrComment(code, callIndex) || !startsWithWord(code, callIndex, calleeName)) {
      searchIndex = callIndex + calleeName.length;
      continue;
    }

    const openParenIndex = skipHorizontalWhitespace(code, callIndex + calleeName.length);
    if (code[openParenIndex] !== "(") {
      searchIndex = callIndex + calleeName.length;
      continue;
    }

    const firstArgIndex = skipWhitespace(code, openParenIndex + 1);
    const quote = code[firstArgIndex];
    if (quote !== "'" && quote !== "\"") {
      searchIndex = callIndex + calleeName.length;
      continue;
    }

    const statementStart = findStatementStart(code, callIndex);
    const statementEnd = findStatementEnd(code, callIndex);
    if (statementEnd > statementStart) {
      ranges.push({ start: statementStart, end: statementEnd });
    }
    searchIndex = statementEnd > callIndex ? statementEnd : callIndex + calleeName.length;
  }

  return ranges;
}

function mergeRanges(ranges) {
  if (!ranges.length) return [];
  const sorted = ranges
    .filter((range) => range && Number.isInteger(range.start) && Number.isInteger(range.end) && range.end > range.start)
    .sort((a, b) => a.start - b.start || a.end - b.end);
  if (!sorted.length) return [];

  const merged = [sorted[0]];
  for (let i = 1; i < sorted.length; i += 1) {
    const current = sorted[i];
    const last = merged[merged.length - 1];
    if (current.start <= last.end) {
      last.end = Math.max(last.end, current.end);
    } else {
      merged.push({ ...current });
    }
  }
  return merged;
}

function startsWithWord(code, index, word) {
  const text = String(code || "");
  if (text.slice(index, index + word.length) !== word) return false;
  const before = text[index - 1];
  const after = text[index + word.length];
  return !isIdentifierChar(before) && !isIdentifierChar(after);
}

function isIdentifierChar(value) {
  return typeof value === "string" && /[A-Za-z0-9_$]/.test(value);
}

function skipHorizontalWhitespace(code, index) {
  let cursor = index;
  while (cursor < code.length && (code[cursor] === " " || code[cursor] === "\t")) cursor += 1;
  return cursor;
}

function skipWhitespace(code, index) {
  let cursor = index;
  while (cursor < code.length && /\s/.test(code[cursor])) cursor += 1;
  return cursor;
}

function advanceToNextLine(code, index) {
  const nextNewline = code.indexOf("\n", index);
  return nextNewline === -1 ? code.length : nextNewline + 1;
}

function findStatementStart(code, index) {
  let cursor = index;
  while (cursor > 0) {
    const previous = code[cursor - 1];
    if (previous === "\n" || previous === "\r" || previous === ";" || previous === "{") break;
    cursor -= 1;
  }
  return cursor;
}

function findStatementEnd(code, index) {
  let cursor = index;
  let depth = 0;
  let stringQuote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  while (cursor < code.length) {
    const char = code[cursor];
    const next = code[cursor + 1];

    if (lineComment) {
      if (char === "\n") lineComment = false;
      cursor += 1;
      continue;
    }

    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        cursor += 2;
        continue;
      }
      cursor += 1;
      continue;
    }

    if (stringQuote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === stringQuote) {
        stringQuote = null;
      }
      cursor += 1;
      continue;
    }

    if (char === "/" && next === "/") {
      lineComment = true;
      cursor += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      cursor += 2;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      stringQuote = char;
      cursor += 1;
      continue;
    }
    if (char === "(" || char === "[" || char === "{") {
      depth += 1;
      cursor += 1;
      continue;
    }
    if ((char === ")" || char === "]" || char === "}") && depth > 0) {
      depth -= 1;
      cursor += 1;
      continue;
    }
    if (char === ";" && depth === 0) {
      return cursor + 1;
    }
    if ((char === "\n" || char === "\r") && depth === 0) {
      return cursor;
    }
    cursor += 1;
  }

  return code.length;
}

function isInsideStringOrComment(code, index) {
  let cursor = 0;
  let stringQuote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  while (cursor < index) {
    const char = code[cursor];
    const next = code[cursor + 1];

    if (lineComment) {
      if (char === "\n") lineComment = false;
      cursor += 1;
      continue;
    }

    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        cursor += 2;
        continue;
      }
      cursor += 1;
      continue;
    }

    if (stringQuote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === stringQuote) {
        stringQuote = null;
      }
      cursor += 1;
      continue;
    }

    if (char === "/" && next === "/") {
      lineComment = true;
      cursor += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      cursor += 2;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      stringQuote = char;
    }
    cursor += 1;
  }

  return !!(stringQuote || lineComment || blockComment);
}

function isMarkupFile(fileName, markupExtensions = DEFAULT_MARKUP_EXTENSIONS) {
  const effectiveExtensions = Array.isArray(markupExtensions) ? markupExtensions : DEFAULT_MARKUP_EXTENSIONS;
  return effectiveExtensions.includes(path.extname(fileName).toLowerCase());
}

function isMarkupFilePath(filePath, markupExtensions = DEFAULT_MARKUP_EXTENSIONS) {
  return isMarkupFile(filePath, markupExtensions);
}

function findMarkedHtmlScripts(html) {
  const blocks = [];
  HTML_SCRIPT_PATTERN.lastIndex = 0;
  let match;
  while ((match = HTML_SCRIPT_PATTERN.exec(html)) !== null) {
    const attrs = match[1] || "";
    if (!/\sdata-javascript-obfuscator(?:\s|=|$)/i.test(attrs)) continue;
    if (/\ssrc\s*=/i.test(attrs)) continue;
    if (/\stype\s*=\s*["']?module["']?/i.test(attrs)) continue;
    const full = match[0];
    const openTagEnd = match.index + full.indexOf(">") + 1;
    const contentEnd = openTagEnd + match[2].length;
    blocks.push({
      contentStart: openTagEnd,
      contentEnd,
      code: match[2]
    });
  }
  return blocks;
}

function validateMarkedHtmlScripts(fileName, html) {
  HTML_SCRIPT_PATTERN.lastIndex = 0;
  let match;
  while ((match = HTML_SCRIPT_PATTERN.exec(html)) !== null) {
    const attrs = match[1] || "";
    if (!/\sdata-javascript-obfuscator(?:\s|=|$)/i.test(attrs)) continue;
    if (/\ssrc\s*=/i.test(attrs)) {
      throw new Error(`${fileName}:${formatSourceLocation(html, match.index)} marks an external script with data-javascript-obfuscator. Only inline script contents can be protected; protect the referenced file directly or remove the marker.`);
    }
    if (/\stype\s*=\s*["']?module["']?/i.test(attrs)) {
      throw new Error(`${fileName}:${formatSourceLocation(html, match.index)} marks a module script with data-javascript-obfuscator. Module scripts are not protected in HTML mode; build them as JavaScript files or remove the marker.`);
    }
  }
}

function formatSourceLocation(source, index) {
  const safeIndex = Math.max(0, Math.min(Number(index) || 0, String(source || "").length));
  const before = String(source || "").slice(0, safeIndex).split(/\r\n|\r|\n/);
  return `${before.length}:${before[before.length - 1].length + 1}`;
}

function hasMarkedHtmlScriptAttributes(html) {
  HTML_SCRIPT_PATTERN.lastIndex = 0;
  let match;
  while ((match = HTML_SCRIPT_PATTERN.exec(html)) !== null) {
    if (/\sdata-javascript-obfuscator(?:\s|=|$)/i.test(match[1] || "")) return true;
  }
  return false;
}

function hasHtmlProtectionMarkers(filePath) {
  return hasMarkedHtmlScriptAttributes(fs.readFileSync(filePath, "utf8"));
}

function buildRequestFromItems(config, items) {
  const project = {
    APIKey: config.apiKey,
    APIPwd: config.apiPassword,
    Name: config.projectName,
    MixedServer: config.mixedServer,
    Items: items
  };

  // ReleaseLabel travels alongside the request. The JSO dashboard groups audit
  // entries by this label, so callers can drill into "show me every build
  // tagged with branch X" or "every release tagged with commit abc123".
  if (config.label) {
    project.ReleaseLabel = String(config.label);
  }

  for (const [key, value] of Object.entries(config.options)) {
    if (value !== undefined && value !== null && value !== false) {
      project[key] = value;
    }
  }

  return project;
}

// Where jso-local.exe lives when the customer unzipped the desktop download.
// Checked in order after --local-exe and JSO_LOCAL_EXE; the point is that a CI
// step which already installs the desktop archive needs no extra configuration.
const LOCAL_EXE_CANDIDATES = [
  "C:/Program Files/JavaScript Obfuscator/cli/jso-local.exe",
  "C:/Tools/JSObfuscator/cli/jso-local.exe",
  "./javascriptobfuscator/cli/jso-local.exe",
  "./cli/jso-local.exe"
];

function resolveLocalExe(config) {
  if (config.localExe) {
    const explicit = path.resolve(config.localExe);
    if (!fs.existsSync(explicit)) {
      throw new Error(`Local protector not found at ${explicit}. Point --local-exe (or JSO_LOCAL_EXE) at cli/jso-local.exe from the desktop download.`);
    }
    return explicit;
  }
  for (const candidate of LOCAL_EXE_CANDIDATES) {
    const resolved = path.resolve(candidate);
    if (fs.existsSync(resolved)) return resolved;
  }
  throw new Error(
    "--local needs the jso-local executable, which ships in the Windows desktop download " +
    "(https://javascriptobfuscator.com/downloads.aspx) under cli/jso-local.exe. " +
    "Set JSO_LOCAL_EXE or pass --local-exe <path>."
  );
}

// Run the protection locally instead of POSTing it. The payload and the
// response are the hosted API's own shapes, so this is a transport swap:
// everything downstream (manifests, evidence, budgets) is unchanged, and an
// option that works hosted works here because jso-local deserializes the same
// project object the server does.
async function runLocalProtector(config, payload) {
  const exe = resolveLocalExe(config);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jso-local-"));
  const payloadPath = path.join(dir, "request.json");
  const responsePath = path.join(dir, "response.json");
  try {
    fs.writeFileSync(payloadPath, JSON.stringify(payload), "utf8");
    const args = ["--http-project", payloadPath, "--response", responsePath, "--quiet"];

    // Node refuses to spawn .cmd/.bat directly (the 2024 batch-file argument
    // injection fix), and a wrapper script is a legitimate thing for a CI step
    // to point at. Route those through cmd.exe with the path as a separate
    // ARGUMENT rather than a concatenated command string, so a path containing
    // shell characters cannot become a command.
    const isBatch = /\.(cmd|bat)$/i.test(exe);
    const run = isBatch
      ? spawnSync(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", exe, ...args], {
          encoding: "utf8",
          maxBuffer: 256 * 1024 * 1024
        })
      : spawnSync(exe, args, {
          encoding: "utf8",
          maxBuffer: 256 * 1024 * 1024
        });
    if (run.error) {
      throw new Error(`Could not run the local protector (${exe}): ${run.error.message}`);
    }
    if (!fs.existsSync(responsePath)) {
      const detail = (run.stderr || run.stdout || "").trim().slice(0, 300);
      throw new Error(`The local protector wrote no response${detail ? `: ${detail}` : "."}`);
    }
    return JSON.parse(fs.readFileSync(responsePath, "utf8"));
  } finally {
    // The payload holds the customer's source and their credentials. It exists
    // only for the length of one exec and is removed even when that exec fails.
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

async function protectItems(config, items) {
  assertReady(config);
  if (!items.length) return { Type: "Succeed", Items: [] };

  const payload = buildRequestFromItems(config, items);
  const result = config.local
    ? await runLocalProtector(config, payload)
    : await postJson(config.endpoint, payload);
  if (result.Type !== "Succeed") {
    throw new Error(formatApiFailure({
      type: result.Type,
      fileName: result.FileName,
      message: result.Message || result.ErrorCode || "API request failed"
    }, [config.apiKey, config.apiPassword]));
  }
  return result;
}

async function protectCode(config, code, fileName = "bundle.js") {
  return (await protectCodeDetailed(config, code, fileName)).code;
}

async function protectCodeDetailed(config, code, fileName = "bundle.js") {
  const plan = buildFileProtectionPlan(config, fileName, code);
  const transforms = new Map();
  if (plan.transform) {
    transforms.set(normalizeName(fileName), plan.transform);
  }
  const protection = { items: plan.items, transforms };
  const result = await protectItems(config, plan.items);
  let output = null;
  if (plan.transform) {
    const byName = new Map((result.Items || []).map((entry) => [normalizeName(entry.FileName), entry]));
    output = finalizeProtectedCode(composeProtectionOutput(plan.transform, byName), config);
  } else {
    const item = (result.Items || []).find((entry) => normalizeName(entry.FileName) === normalizeName(fileName));
    if (item) output = finalizeProtectedCode(item.FileCode || "", config);
  }
  if (output === null) {
    throw new Error(`API response did not include output for ${fileName}`);
  }
  return {
    code: output,
    result,
    protection,
    processing: describeProtectionTransforms(protection)
  };
}

function readStdin(stream = process.stdin) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => chunks.push(chunk));
    stream.on("end", () => resolve(chunks.join("")));
    stream.on("error", reject);
  });
}

async function postJson(endpoint, payload) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch (error) {
    throw new Error(`API returned non-JSON response (${response.status}): ${text.slice(0, 300)}`);
  }

  if (!response.ok) {
    throw new Error(formatApiFailure({
      status: response.status,
      statusText: response.statusText,
      message: json.Message || json.Error || json.ErrorCode || response.statusText
    }, [payload && payload.APIKey, payload && payload.APIPwd]));
  }

  return json;
}

function formatApiFailure(details = {}, secrets = []) {
  const status = details.status ? ` (${details.status})` : "";
  const type = details.type || "API request failed";
  const location = details.fileName ? ` in ${details.fileName}` : "";
  const rawMessage = details.message || details.statusText || "API request failed";
  const message = redactApiSecrets(rawMessage, secrets);
  const hint = apiFailureHint({ ...details, message });
  return `${type}${status}${location}: ${message}${hint ? ` ${hint}` : ""}`;
}

function apiFailureHint(details = {}) {
  const text = `${details.status || ""} ${details.type || ""} ${details.message || ""}`.toLowerCase();
  if (/payment|paid|plan|subscription|credit|quota|limit|expired|billing|over[- ]?limit/.test(text)) {
    return "Paid API access is enforced by the hosted API; check account status, plan limits, credits, or subscription state.";
  }
  if (details.status === 401 || details.status === 403 || /auth|credential|api ?key|password|unauthori[sz]ed|forbidden|invalid key|invalid password/.test(text)) {
    return "Check JSO_API_KEY and JSO_API_PASSWORD from the paid dashboard.";
  }
  return "";
}

function redactApiSecrets(value, secrets = []) {
  let text = String(value || "");
  for (const secret of secrets) {
    const safeSecret = String(secret || "");
    if (safeSecret.length < 4) continue;
    text = text.split(safeSecret).join("[redacted]");
  }
  return text;
}

function writeResults(files, result, transforms = new Map(), config = null) {
  const items = result.Items || [];
  const byName = new Map(items.map((item) => [normalizeName(item.FileName), item]));

  for (const file of files) {
    const transform = transforms instanceof Map ? transforms.get(normalizeName(file.relative)) : null;
    const item = byName.get(normalizeName(file.relative));
    const output = transform ? composeProtectionOutput(transform, byName) : (item && item.FileCode);
    if (!transform && !item) {
      throw new Error(`API response did not include output for ${file.relative}`);
    }
    fs.mkdirSync(path.dirname(file.target), { recursive: true });
    fs.writeFileSync(file.target, finalizeProtectedCode(output || "", config), "utf8");
  }
}

function copyAssets(assets) {
  for (const asset of assets) {
    fs.mkdirSync(path.dirname(asset.target), { recursive: true });
    fs.copyFileSync(asset.source, asset.target);
  }
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

function assertReady(config) {
  if (!config.apiKey) throw new Error("Missing API key. Set JSO_API_KEY, JAVASCRIPT_OBFUSCATOR_API_KEY, or apiKey in config.");
  if (!config.apiPassword) throw new Error("Missing API password. Set JSO_API_PASSWORD, JAVASCRIPT_OBFUSCATOR_API_PASSWORD, or apiPassword in config.");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function fileDigest(filePath) {
  const buffer = fs.readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: sha256(buffer)
  };
}

function attachManifestLimitations(manifest, config) {
  if (!manifest || !config) return manifest;
  const sourceConfig = config.__rawConfig && typeof config.__rawConfig === "object"
    ? config.__rawConfig
    : config;
  const limitations = collectCompetitorLimitations(sourceConfig, {});
  if (limitations.length) {
    manifest.limitations = limitations;
  }
  return manifest;
}

function buildProtectionManifest(config, files, assets, result, transforms = new Map()) {
  const byName = new Map((result.Items || []).map((item) => [normalizeName(item.FileName), item]));
  const processing = describeProtectionTransforms({
    items: result.Items || [],
    transforms: transforms instanceof Map ? transforms : new Map()
  });
  return attachManifestLimitations({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: config.endpoint,
    projectName: config.projectName,
    preset: config.preset,
    options: Object.keys(config.options || {}).filter((key) => key !== "reservedNames").sort(),
    processing,
    files: files.map((file) => {
      const item = byName.get(normalizeName(file.relative));
      const transform = transforms instanceof Map ? transforms.get(normalizeName(file.relative)) : null;
      const source = fileDigest(file.source);
      const fallbackOutput = transform
        ? finalizeProtectedCode(composeProtectionOutput(transform, byName), config)
        : finalizeProtectedCode(item && item.FileCode ? item.FileCode : "", config);
      const output = fs.existsSync(file.target) ? fileDigest(file.target) : {
        bytes: Buffer.byteLength(fallbackOutput, "utf8"),
        sha256: sha256(fallbackOutput)
      };
      return {
        fileName: file.relative,
        sourcePath: file.source,
        outputPath: file.target,
        sourceBytes: source.bytes,
        outputBytes: output.bytes,
        sourceSha256: source.sha256,
        outputSha256: output.sha256
      };
    }),
    assets: (assets || []).map((asset) => {
      const digest = fs.existsSync(asset.target) ? fileDigest(asset.target) : fileDigest(asset.source);
      return {
        fileName: asset.relative,
        sourcePath: asset.source,
        outputPath: asset.target,
        bytes: digest.bytes,
        sha256: digest.sha256
      };
    })
  }, config);
}

function buildStdinManifest(config, fileName, sourceCode, outputCode, outputPath, processing = null) {
  return attachManifestLimitations({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: config.endpoint,
    projectName: config.projectName,
    preset: config.preset,
    options: Object.keys(config.options || {}).filter((key) => key !== "reservedNames").sort(),
    processing: processing || { apiItems: 1, transformedFiles: [] },
    files: [{
      fileName,
      sourcePath: "stdin",
      outputPath,
      sourceBytes: Buffer.byteLength(sourceCode, "utf8"),
      outputBytes: Buffer.byteLength(outputCode, "utf8"),
      sourceSha256: sha256(sourceCode),
      outputSha256: sha256(outputCode)
    }],
    assets: []
  }, config);
}

function buildItemsManifest(config, inputItems, result, outputPathForItem, transforms = new Map()) {
  const byName = new Map((result.Items || []).map((item) => [normalizeName(item.FileName), item]));
  const processing = describeProtectionTransforms({
    items: result.Items || [],
    transforms: transforms instanceof Map ? transforms : new Map()
  });
  return attachManifestLimitations({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: config.endpoint,
    projectName: config.projectName,
    preset: config.preset,
    options: Object.keys(config.options || {}).filter((key) => key !== "reservedNames").sort(),
    processing,
    files: inputItems.map((input) => {
      const item = byName.get(normalizeName(input.FileName));
      const transform = transforms instanceof Map ? transforms.get(normalizeName(input.FileName)) : null;
      const outputCode = transform
        ? finalizeProtectedCode(composeProtectionOutput(transform, byName), config)
        : finalizeProtectedCode(item && item.FileCode ? item.FileCode : "", config);
      return {
        fileName: input.FileName,
        sourcePath: input.SourcePath || input.FileName,
        outputPath: typeof outputPathForItem === "function" ? outputPathForItem(input.FileName) : (input.OutputPath || input.FileName),
        sourceBytes: Buffer.byteLength(input.FileCode || "", "utf8"),
        outputBytes: Buffer.byteLength(outputCode, "utf8"),
        sourceSha256: sha256(input.FileCode || ""),
        outputSha256: sha256(outputCode)
      };
    }),
    assets: []
  }, config);
}

function writeManifest(manifestPath, manifest) {
  if (!manifestPath) return;
  fs.mkdirSync(path.dirname(path.resolve(manifestPath)), { recursive: true });
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

function checkSizeBudgets(manifest, budgets = {}) {
  const failures = [];
  const maxOutputBytes = budgets.maxOutputBytes;
  const maxGrowthRatio = budgets.maxGrowthRatio;
  if (!maxOutputBytes && !maxGrowthRatio) return failures;

  for (const file of manifest.files || []) {
    if (maxOutputBytes && file.outputBytes > maxOutputBytes) {
      failures.push({
        fileName: file.fileName,
        type: "max-output-bytes",
        actual: file.outputBytes,
        limit: maxOutputBytes
      });
    }
    if (maxGrowthRatio && file.sourceBytes > 0) {
      const ratio = file.outputBytes / file.sourceBytes;
      if (ratio > maxGrowthRatio) {
        failures.push({
          fileName: file.fileName,
          type: "max-growth-ratio",
          actual: Number(ratio.toFixed(4)),
          limit: maxGrowthRatio
        });
      }
    }
  }
  return failures;
}

function assertSizeBudgets(manifest, budgets = {}) {
  const failures = checkSizeBudgets(manifest, budgets);
  if (!failures.length) return failures;
  const details = failures.map((failure) => `${failure.fileName} ${failure.type} ${failure.actual} > ${failure.limit}`).join("; ");
  throw new Error(`Size budget failed: ${details}`);
}

async function runDoctor(config, args = {}) {
  const checks = [];
  const limitations = collectCompetitorLimitations(args.rawConfig && typeof args.rawConfig === "object" ? args.rawConfig : config, args);
  addDoctorCheck(checks, "endpoint", isValidUrl(config.endpoint), `Endpoint: ${config.endpoint}`, "Endpoint must be a valid URL.");
  addDoctorCheck(checks, "apiKey", !!config.apiKey, "API key is present.", "Missing API key. Set JSO_API_KEY, JAVASCRIPT_OBFUSCATOR_API_KEY, or apiKey in config.");
  addDoctorCheck(checks, "apiPassword", !!config.apiPassword, "API password is present.", "Missing API password. Set JSO_API_PASSWORD, JAVASCRIPT_OBFUSCATOR_API_PASSWORD, or apiPassword in config.");
  addDoctorCheck(checks, "preset", true, `Preset: ${config.preset}`);
  addDoctorCheck(checks, "options", Object.keys(config.options || {}).length > 0, `${Object.keys(config.options || {}).length} option(s) enabled.`, "No protection options are enabled.");

  const inputExists = !!config.input && fs.existsSync(config.input);
  addDoctorCheck(checks, "input", inputExists, `Input exists: ${config.input}`, `Input path does not exist: ${config.input}`);

  let files = [];
  let assets = [];
  if (inputExists) {
    try {
      files = collectFiles(config.input, config.output, config.extensions, config.exclude, config.include, config.markupExtensions);
      assets = config.copyAssets ? collectAssets(config.input, config.output, files, config.assetExclude) : [];
      addDoctorCheck(checks, "files", files.length > 0, `${files.length} JavaScript file(s) match.`, "No matching JavaScript files found.");
      addDoctorCheck(checks, "assets", true, `${assets.length} asset(s) would be copied.`);
      buildProtectionItems(config, files);
      addDoctorCheck(checks, "transforms", true, "Conditional comments and marked HTML scripts are ready.");
      const compatibility = scanCompatibilityRisks(config);
      if (compatibility.summary.findings) {
        addDoctorCheck(checks, "compatibility", true, `Compatibility scan found ${compatibility.summary.findings} potential source-contract or reflection risk(s) in ${compatibility.summary.filesWithFindings} file(s). Run --compat-scan --json for details.`);
      } else {
        addDoctorCheck(checks, "compatibility", true, "Compatibility scan found no known source-contract or reflection risks.");
      }
    } catch (error) {
      addDoctorCheck(checks, "files", false, "", error.message);
    }
  }

  const outputParent = path.dirname(config.output);
  addDoctorCheck(
    checks,
    "output",
    !!outputParent && fs.existsSync(outputParent),
    `Output parent exists: ${outputParent}`,
    `Output parent does not exist: ${outputParent}`
  );

  if (args.checkApi) {
    if (!config.apiKey || !config.apiPassword) {
      addDoctorCheck(checks, "api", false, "", "API check skipped because credentials are missing.");
    } else {
      try {
        const code = await protectCode(config, "console.log('jso-doctor');", "jso-doctor.js");
        addDoctorCheck(checks, "api", !!code, `Live API check succeeded (${code.length} bytes returned).`, "Live API check returned empty output.");
      } catch (error) {
        addDoctorCheck(checks, "api", false, "", error.message);
      }
    }
  } else {
    addDoctorCheck(checks, "api", true, "Live API check skipped. Pass --check-api to test credentials and endpoint.");
  }

  return {
    ok: checks.every((check) => check.ok),
    endpoint: config.endpoint,
    projectName: config.projectName,
    preset: config.preset,
    input: config.input,
    output: config.output,
    files: files.map((file) => file.relative),
    assets: assets.map((file) => file.relative),
    limitations,
    checks
  };
}

function addDoctorCheck(checks, name, ok, message, error) {
  checks.push({
    name,
    ok: !!ok,
    message: ok ? message : (error || message || "Check failed.")
  });
}

function collectCompetitorLimitations(config = {}, args = {}) {
  const fields = new Set([
    ...getCompatibilityReviewFields(config),
    ...getCompatibilityReviewFields(args),
    ...((Array.isArray(args.compatibilityReviewFields) ? args.compatibilityReviewFields : []))
  ]);

  const optionEntries = Array.isArray(args.options) ? args.options : [];
  for (const entry of optionEntries) {
    const index = String(entry).indexOf("=");
    const name = index > 0 ? String(entry).slice(0, index).trim() : "";
    if (name) fields.add(name);
  }

  return COMPETITOR_LIMITATION_GROUPS
    .map((group) => {
      const matchedFields = group.fields.filter((field) => fields.has(field));
      if (!matchedFields.length) return null;
      return {
        id: group.id,
        title: group.title,
        fields: matchedFields,
        message: group.message,
        recommendation: group.recommendation
      };
    })
    .filter(Boolean);
}

function buildCompetitorGapReport(config = {}, args = {}) {
  const limitations = collectCompetitorLimitations(config, args);
  const limitationIds = new Set(limitations.map((limitation) => limitation.id));
  const capabilities = COMPETITOR_CAPABILITY_MATRIX.map((entry) => {
    let status = entry.status;
    if (entry.id === "locks" && limitationIds.has("runtime-self-defending")) {
      status = "partial";
    }
    if (entry.id === "runtime-defense" && !limitationIds.has("runtime-self-defending")) {
      status = "partial";
    }
    if (entry.id === "source-maps" && !limitationIds.has("source-maps") && !limitationIds.has("identifier-name-cache")) {
      status = "partial";
    }
    return {
      id: entry.id,
      capability: entry.capability,
      competitorExamples: entry.competitorExamples.slice(),
      status,
      jsoSupport: entry.jsoSupport,
      evidence: entry.evidence.slice()
    };
  });

  const summary = capabilities.reduce((acc, capability) => {
    acc[capability.status] = (acc[capability.status] || 0) + 1;
    return acc;
  }, { covered: 0, partial: 0, gap: 0 });
  const reportSummary = {
    capabilities: capabilities.length,
    covered: summary.covered || 0,
    partial: summary.partial || 0,
    gaps: summary.gap || 0,
    triggeredLimitations: limitations.length
  };
  const reviewArtifacts = buildCompetitorGapReviewArtifacts(limitations, args);
  const recommendedPlan = buildCompetitorGapPlan(capabilities, limitations);
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "public competitor names and source URLs",
      "source snapshot reviewed date and claim boundary",
      "capability labels, status, and evidence names",
      "limitation group names and field names",
      "source-free review artifact commands",
      "recommended plan items"
    ],
    doNotInclude: [
      "source code",
      "protected output",
      "API keys or passwords",
      "provider keys",
      "source-map contents",
      "identifier cache contents",
      "countermeasure values",
      "customer data",
      "secrets"
    ]
  };
  const sourceSnapshot = {
    reviewedOn: COMPETITOR_SOURCE_SNAPSHOT.reviewedOn,
    basis: COMPETITOR_SOURCE_SNAPSHOT.basis,
    sources: COMPETITOR_SOURCE_SNAPSHOT.sources.map((source) => Object.assign({}, source)),
    claimBoundary: COMPETITOR_SOURCE_SNAPSHOT.claimBoundary
  };

  return {
    format: "jso-protector-competitor-gap-report",
    version: 1,
    summary: reportSummary,
    competitors: ["Obfuscator.io", "javascript-obfuscator", "JS-Confuser", "Jscrambler", "JSDefender"],
    sourceSnapshot,
    capabilities,
    limitations,
    reviewArtifacts,
    sourceBoundary,
    reviewAssistant: buildCompetitorGapReviewAssistant(reportSummary, capabilities, limitations, reviewArtifacts, recommendedPlan, sourceSnapshot, sourceBoundary),
    recommendedPlan
  };
}

function buildCompetitorGapReviewAssistant(summary, capabilities, limitations, reviewArtifacts, recommendedPlan, sourceSnapshot, sourceBoundary) {
  const questions = [];
  const partialCapabilities = (capabilities || []).filter((item) => item && item.status === "partial");
  const gapCapabilities = (capabilities || []).filter((item) => item && item.status === "gap");
  const sourceReadingArtifacts = (reviewArtifacts || []).filter((item) => item && item.sourceFree === false);

  if (gapCapabilities.length > 0) {
    questions.push({
      topic: "Gap prioritization",
      prompt: "Review the gap capability labels and competitor examples, then decide which buyer-facing gap needs a roadmap item, partner workflow, or explicit sales boundary.",
      ownerAction: "Assign an owner and next milestone for each material gap before using the report in customer-facing comparisons."
    });
  }

  if (partialCapabilities.length > 0) {
    questions.push({
      topic: "Partial parity validation",
      prompt: "Review partial capability rows and confirm whether the evidence names are enough for the release or whether a specialized packet is required.",
      ownerAction: "Attach source-map, runtime-defense, identifier-cache, VM proof, payment-page, or AI-resistance evidence before claiming parity."
    });
  }

  if (limitations && limitations.length > 0) {
    questions.push({
      topic: "Triggered migration limitations",
      prompt: "Review limitation group names and field names, then decide which accepted competitor-only options require manual validation.",
      ownerAction: "Run the listed review artifacts and close every manual-validation item before approving the migrated config."
    });
  }

  if (sourceReadingArtifacts.length > 0) {
    questions.push({
      topic: "Source-reading scan boundary",
      prompt: "Confirm why any source-reading artifact is required and who may run it in the repository or CI environment.",
      ownerAction: "Run source-reading scans only inside the customer's controlled environment and share the summarized findings, not source snippets."
    });
  }

  questions.push({
    topic: "Vendor claim freshness",
    prompt: "Confirm the public vendor snapshot date and claim boundary are still current before using this report in a buyer, renewal, or support conversation.",
    ownerAction: "Re-check current vendor pages when the report is older than the release review window or when a named vendor changes pricing, VM, API, monitoring, or evidence claims."
  });

  questions.push({
    topic: "Plan handoff",
    prompt: "Convert the recommended plan into a release checklist with owners for migration baseline, CI preflight, release attribution, and specialized evidence.",
    ownerAction: "Attach the competitor-gap JSON beside release-check, migration-review, and any specialized source-free packets."
  });

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "covered/partial/gap counts",
      "source-free/source-reading artifact flags",
      "public vendor snapshot metadata"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw compatibility scan source snippets",
      "private vendor contract terms",
      "unredacted configuration files"
    ])));

  return {
    sourceFree: true,
    title: "Competitor Gap Review Assistant",
    intendedUse: "Use with a BYO AI key or internal reviewer to turn competitor-gap findings into release-owner actions without sending source code, protected output, API credentials, provider keys, customer data, or secrets.",
    reviewerPrompt: "Review this JSO competitor-gap report. Use only public-source snapshot metadata, competitor names, capability statuses, evidence names, limitation group names, review artifact commands, recommended plan items, and source-free/source-reading flags. Produce owner actions without requesting source code, protected output, raw compatibility scan snippets, credential values, provider keys, customer data, or secrets.",
    safeInputs,
    doNotInclude,
    questions,
    snapshotReviewedOn: sourceSnapshot && sourceSnapshot.reviewedOn ? sourceSnapshot.reviewedOn : null,
    counts: {
      covered: summary && summary.covered || 0,
      partial: summary && summary.partial || 0,
      gaps: summary && summary.gaps || 0,
      triggeredLimitations: summary && summary.triggeredLimitations || 0,
      reviewArtifacts: Array.isArray(reviewArtifacts) ? reviewArtifacts.length : 0,
      sourceReadingArtifacts: sourceReadingArtifacts.length,
      planItems: Array.isArray(recommendedPlan) ? recommendedPlan.length : 0
    }
  };
}

function buildCompetitorGapPlan(capabilities, limitations) {
  const plan = [
    "Use balanced or maximum preset as the migration baseline for string, name, dead-code, and control-flow coverage.",
    "Run --validate-config and --competitor-gap-report as separate CI preflight commands for migrated competitor configs so interval, countermeasure, and vendor-specific runtime-defense differences stay visible.",
    "Use --label, --report, --watermark, and --sign-release to cover release attribution and artifact verification."
  ];
  if (limitations.some((item) => item.id === "runtime-self-defending")) {
    plan.push("Map anti-debug, integrity, self-defending, and countermeasure requirements to JSO runtime defense helpers where possible, wire RuntimeDefenseBeaconUrl to customer monitoring or the hosted /v1/runtime/beacon.ashx intake, then manually validate behavior because migrated switches are not one-to-one hosted API options.");
  }
  if (limitations.some((item) => item.id === "source-maps" || item.id === "identifier-name-cache")) {
    plan.push("Remove protected source-map and identifier-cache assumptions from hosted API release scripts, then attach source-map evidence and source-free release metadata beside the protected artifact.");
  }
  if (limitations.some((item) => item.id === "identifier-name-cache" || item.id === "custom-identifier-dictionary")) {
    plan.push("Replace identifier-cache repeatability assumptions with explicit reserved-name reviews, saved API reports, and protected-build smoke tests for public API surfaces.");
  }
  if (capabilities.some((item) => item.id === "locks" && item.status !== "covered")) {
    plan.push("Convert domain, start-date, and end-date locks automatically; map browser/OS policies to LockBrowser/LockOS explicitly, then review custom countermeasure needs separately.");
  }
  return plan;
}

function buildCompetitorGapReviewArtifacts(limitations, args = {}) {
  const configArg = args.config || "jso.config.json";
  const limitationIds = new Set((limitations || []).map((item) => item.id));
  const artifacts = [
    {
      id: "release-check",
      command: `jso-protector --config ${configArg} --release-check --json`,
      purpose: "Validate config, file discovery, credentials, and review-only migration fields before source is sent.",
      sourceFree: true
    },
    {
      id: "competitor-gap-report",
      command: `jso-protector --config ${configArg} --competitor-gap-report --json`,
      purpose: "Keep covered, partial, and gap areas visible as a CI artifact during migration review.",
      sourceFree: true
    }
  ];

  if ((limitations || []).length) {
    artifacts.push({
      id: "migration-review",
      command: `jso-protector --config ${configArg} --migration-review --migration-review-output reports/migration-review.md`,
      purpose: "Create one source-free all-up migration-review owner packet for every accepted competitor-only option before the specialized follow-up packets.",
      sourceFree: true
    });
  }

  if (limitationIds.has("source-maps")) {
    artifacts.push({
      id: "source-map-evidence",
      command: "jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md",
      purpose: "After protection, prove the manifest verifies and no protected artifact exposes .map files or sourceMappingURL comments.",
      sourceFree: true
    });
  }

  if (limitationIds.has("identifier-name-cache") || limitationIds.has("custom-identifier-dictionary")) {
    artifacts.push({
      id: "identifier-cache-replacement-review",
      command: `jso-protector --config ${configArg} --identifier-cache-review --identifier-cache-review-output reports/identifier-cache-review.md`,
      purpose: "Document cache/dictionary fields as review-only, confirm reserved-name rules, and keep the source-free API report plus manifest instead of a deterministic cache file.",
      sourceFree: true
    });
  }

  if (limitationIds.has("runtime-self-defending")) {
    artifacts.push({
      id: "runtime-defense-review",
      command: `jso-protector --config ${configArg} --runtime-defense-review --runtime-defense-review-output reports/runtime-defense-review.md`,
      purpose: "Document anti-debug, self-defending, lock, and countermeasure migration fields as source-free runtime-defense review evidence before wiring monitoring.",
      sourceFree: true
    });
    artifacts.push({
      id: "runtime-compatibility-scan",
      command: `jso-protector --config ${configArg} --compat-scan --json`,
      purpose: "Inspect source for reflection risks before approving runtime-lock migrations that can change debugging, console, or tamper behavior.",
      sourceFree: false
    });
  }

  return artifacts;
}

function writeCompetitorGapReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }
  process.stdout.write("Competitor gap report:\n");
  process.stdout.write(`covered: ${report.summary.covered}, partial: ${report.summary.partial}, gaps: ${report.summary.gaps}, triggered limitations: ${report.summary.triggeredLimitations}\n`);
  if (report.sourceSnapshot && report.sourceSnapshot.reviewedOn) {
    process.stdout.write(`sources reviewed: ${report.sourceSnapshot.reviewedOn}; ${report.sourceSnapshot.claimBoundary}\n`);
  }
  for (const capability of report.capabilities) {
    process.stdout.write(`${capability.status.toUpperCase()} ${capability.capability}: ${capability.jsoSupport}\n`);
  }
  for (const limitation of report.limitations) {
    process.stdout.write(`LIMITATION ${limitation.id}: ${limitation.message} Fields: ${limitation.fields.join(", ")}. ${limitation.recommendation}\n`);
  }
  if (Array.isArray(report.reviewArtifacts) && report.reviewArtifacts.length) {
    process.stdout.write("Review artifacts:\n");
    for (const artifact of report.reviewArtifacts) {
      const sourceBoundary = artifact.sourceFree ? "source-free" : "source-reading";
      process.stdout.write(`- ${artifact.id} (${sourceBoundary}): ${artifact.command} - ${artifact.purpose}\n`);
    }
  }
  writeCompetitorGapReviewAssistant(report.reviewAssistant);
  process.stdout.write("Plan:\n");
  for (const item of report.recommendedPlan) {
    process.stdout.write(`- ${item}\n`);
  }
}

function writeCompetitorGapReviewAssistant(assistant) {
  if (!assistant) return;
  process.stdout.write("Review assistant:\n");
  if (assistant.title) process.stdout.write(`${assistant.title}\n`);
  process.stdout.write(`intended use: ${assistant.intendedUse}\n`);
  process.stdout.write(`reviewer prompt: ${assistant.reviewerPrompt}\n`);
  process.stdout.write("safe inputs:\n");
  for (const item of assistant.safeInputs || []) process.stdout.write(`- ${item}\n`);
  process.stdout.write("do not include:\n");
  for (const item of assistant.doNotInclude || []) process.stdout.write(`- ${item}\n`);
  process.stdout.write("questions:\n");
  for (const item of assistant.questions || []) {
    process.stdout.write(`- ${item.topic}: ${item.prompt} Owner action: ${item.ownerAction}\n`);
  }
}

function buildMigrationReviewReport(config = {}, args = {}) {
  const limitations = collectCompetitorLimitations(config, args);
  const reviewFields = collectMigrationReviewFields(config, args);
  const cliWarnings = collectMigrationReviewWarnings(args);
  const releaseEvidence = summarizeMigrationReviewReleaseEvidence(config, args);
  const followUpCommands = buildMigrationReviewFollowUps({
    config,
    args,
    limitations,
    reviewFields,
    releaseEvidence
  });
  const reviewEvidence = buildMigrationReviewEvidence({
    limitations,
    reviewFields,
    cliWarnings,
    releaseEvidence,
    followUpCommands
  });
  const reviewDecision = buildMigrationReviewDecision(limitations, reviewFields, cliWarnings, reviewEvidence);
  const summary = {
    reviewOnlyFields: reviewFields.length,
    limitationGroups: limitations.length,
    cliWarnings: cliWarnings.length,
    sourceMapFields: reviewFields.filter((field) => field.group === "source-map").length,
    identifierFields: reviewFields.filter((field) => field.group === "identifier-cache" || field.group === "custom-dictionary").length,
    runtimeFields: reviewFields.filter((field) => field.group === "runtime-defense" || field.group === "js-confuser-runtime-lock" || field.group === "runtime-lock-redirect" || field.group === "console-policy").length,
    otherReviewFields: reviewFields.filter((field) => field.group === "general-review").length,
    apiReportConfigured: releaseEvidence.apiReportConfigured,
    manifestConfigured: releaseEvidence.manifestConfigured
  };
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "review-only field names",
      "field value types and counts",
      "limitation group names",
      "CLI compatibility warning text",
      "API report and manifest configured/not-configured states",
      "source-free follow-up commands and reviewer actions"
    ],
    doNotInclude: [
      "source code",
      "protected output code",
      "source-map contents",
      "identifier cache contents",
      "identifier dictionary values",
      "identifier prefixes",
      "reserved-name or reserved-string expressions",
      "seed values",
      "domain lists",
      "runtime beacon URLs",
      "redirect URLs",
      "date lock values",
      "JS-Confuser countermeasure values",
      "compatibility-scan source snippets"
    ]
  };
  const recommendations = buildMigrationReviewRecommendations({
    limitations,
    reviewFields,
    releaseEvidence
  });

  return {
    format: "jso-protector-migration-review",
    version: 1,
    ok: true,
    generatedAt: new Date().toISOString(),
    generatedBy: "jso-protector --migration-review",
    source: {
      configFile: args.config ? path.basename(args.config) : "default-discovery",
      sourceFree: true,
      valuePolicy: "Only field names, value types/counts, configured states, warning text, and reviewer actions are included."
    },
    summary,
    reviewFields,
    limitations,
    cliWarnings,
    releaseEvidence,
    reviewEvidence,
    followUpCommands,
    reviewDecision,
    sourceBoundary,
    reviewAssistant: buildMigrationReviewAssistant(summary, reviewDecision, reviewEvidence, followUpCommands, recommendations, sourceBoundary),
    recommendations
  };
}

function collectMigrationReviewFields(config = {}, args = {}) {
  const fields = new Set([
    ...getCompatibilityReviewFields(config),
    ...((Array.isArray(args.compatibilityReviewFields) ? args.compatibilityReviewFields : []))
  ]);
  return Array.from(fields).sort().map((field) => summarizeMigrationReviewField(config, args, field));
}

function summarizeMigrationReviewField(config = {}, args = {}, field) {
  const fromConfig = config[field] !== undefined;
  const value = config[field];
  const shape = summarizeMigrationReviewFieldShape(value, fromConfig);
  return Object.assign({
    field,
    group: migrationReviewFieldGroup(field),
    source: fromConfig ? "config" : "cli-flag",
    note: migrationReviewFieldNote(field),
    valueIncluded: false,
    redaction: migrationReviewFieldRedaction(field)
  }, shape);
}

function summarizeMigrationReviewFieldShape(value, fromConfig) {
  if (!fromConfig) {
    return {
      valueType: "unknown",
      configured: true
    };
  }
  const valueType = valueKind(value);
  const summary = {
    valueType,
    configured: value !== undefined
  };
  if (Array.isArray(value)) {
    summary.entryCount = value.length;
  } else if (value && typeof value === "object") {
    summary.keyCount = Object.keys(value).length;
  } else if (typeof value === "string") {
    summary.stringConfigured = value.length > 0;
  }
  return summary;
}

function migrationReviewFieldNote(field) {
  return JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS[field]
    || JS_CONFUSER_CONFIG_REVIEW_FIELDS[field]
    || "Accepted for migration compatibility; review output and release behavior before approval.";
}

function migrationReviewFieldGroup(field) {
  if (["sourceMap", "sourceMapBaseUrl", "sourceMapFileName", "sourceMapMode", "sourceMapSourcesMode", "inputFileName"].includes(field)) {
    return "source-map";
  }
  if (field === "identifierNamesCache" || field === "identifierNamesCachePath") return "identifier-cache";
  if (field === "identifiersDictionary" || field === "identifiersPrefix") return "custom-dictionary";
  if (Object.prototype.hasOwnProperty.call(JS_CONFUSER_CONFIG_REVIEW_FIELDS, field)) return "js-confuser-runtime-lock";
  if (["debugProtection", "debugProtectionInterval", "selfDefending"].includes(field)) return "runtime-defense";
  if (field === "domainLockRedirectUrl") return "runtime-lock-redirect";
  if (field === "disableConsoleOutput") return "console-policy";
  return "general-review";
}

function migrationReviewFieldRedaction(field) {
  if (field === "identifierNamesCache") return "Cache keys and replacement names are omitted.";
  if (field === "identifierNamesCachePath") return "Cache path value is omitted.";
  if (field === "identifiersDictionary") return "Dictionary values are omitted.";
  if (field === "identifiersPrefix") return "Prefix value is omitted.";
  if (field === "reservedStrings") return "Reserved string expressions are omitted.";
  if (field === "reservedNames") return "Reserved-name expressions are omitted.";
  if (field === "seed") return "Seed value is omitted.";
  if (field === "domainLockRedirectUrl") return "Redirect URL value is omitted.";
  if (field === "jsConfuserLockStartDate") return "Start-date value is omitted.";
  if (field === "jsConfuserLockCountermeasures") return "Countermeasure value is omitted.";
  if (field === "sourceMapBaseUrl" || field === "sourceMapFileName" || field === "inputFileName") return "Source-map naming value is omitted.";
  if (field.toLowerCase().includes("stringarray")) return "String-array transform setting value is omitted.";
  return "Field value is omitted.";
}

function collectMigrationReviewWarnings(args = {}) {
  return (Array.isArray(args.compatibilityWarnings) ? args.compatibilityWarnings : []).map((message, index) => ({
    id: `compat-warning-${index + 1}`,
    message,
    valueIncluded: false
  }));
}

function summarizeMigrationReviewReleaseEvidence(config = {}, args = {}) {
  const configArg = quoteCommandArg(args.config || "jso.config.json");
  return {
    apiReportConfigured: !!(args.report || config.report),
    manifestConfigured: !!(args.manifest || config.manifest),
    configCommandArg: configArg,
    valuesIncluded: false
  };
}

function buildMigrationReviewFollowUps(context) {
  const limitations = context.limitations || [];
  const reviewFields = context.reviewFields || [];
  const releaseEvidence = context.releaseEvidence || {};
  const configArg = releaseEvidence.configCommandArg || quoteCommandArg((context.args && context.args.config) || "jso.config.json");
  const limitationIds = new Set(limitations.map((item) => item.id));
  const commands = [
    {
      label: "validate",
      command: `jso-protector --config ${configArg} --validate-config --json`,
      sourceFree: true,
      purpose: "Confirm config shape and review-only limitation groups before source is sent."
    },
    {
      label: "release-check",
      command: `jso-protector --config ${configArg} --release-check --json`,
      sourceFree: true,
      purpose: "Collect validation, dry-run planning, and doctor evidence for release approval."
    },
    {
      label: "competitor-gap",
      command: `jso-protector --config ${configArg} --competitor-gap-report --json`,
      sourceFree: true,
      purpose: "Keep covered, partial, and gap areas visible for migration triage."
    },
    {
      label: "protect-with-evidence",
      command: `jso-protector --config ${configArg} --report dist-protected/jso-report.json --manifest dist-protected/jso-manifest.json`,
      sourceFree: false,
      purpose: "Protect the build and create source-free release metadata for reviewer handoff."
    }
  ];

  if (limitationIds.has("source-maps") || reviewFields.some((field) => field.group === "source-map")) {
    commands.push({
      label: "source-map-evidence",
      command: "jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md",
      sourceFree: true,
      purpose: "After protection, prove the manifest verifies and protected artifacts do not expose source maps."
    });
  }

  if (limitationIds.has("identifier-name-cache") || limitationIds.has("custom-identifier-dictionary")) {
    commands.push({
      label: "identifier-cache-review",
      command: `jso-protector --config ${configArg} --identifier-cache-review --identifier-cache-review-output reports/identifier-cache-review.md`,
      sourceFree: true,
      purpose: "Run the focused cache/dictionary replacement packet when deterministic naming assumptions are present."
    });
  }

  if (limitationIds.has("runtime-self-defending")) {
    commands.push({
      label: "runtime-defense-review",
      command: `jso-protector --config ${configArg} --runtime-defense-review --runtime-defense-review-output reports/runtime-defense-review.md`,
      sourceFree: true,
      purpose: "Run the focused runtime-defense packet for anti-debug, self-defending, lock, console, and countermeasure behavior."
    });
    commands.push({
      label: "runtime-compatibility-scan",
      command: `jso-protector --config ${configArg} --compat-scan --json`,
      sourceFree: false,
      purpose: "Read source locally for reflection risks before approving runtime-defense migrations."
    });
  }

  return commands;
}

function buildMigrationReviewEvidence(context) {
  const limitations = context.limitations || [];
  const reviewFields = context.reviewFields || [];
  const cliWarnings = context.cliWarnings || [];
  const releaseEvidence = context.releaseEvidence || {};
  const limitationIds = new Set(limitations.map((item) => item.id));
  const reviewNeeded = reviewFields.length > 0 || limitations.length > 0 || cliWarnings.length > 0;
  const specializedCount = [
    limitationIds.has("source-maps") || reviewFields.some((field) => field.group === "source-map"),
    limitationIds.has("identifier-name-cache") || limitationIds.has("custom-identifier-dictionary"),
    limitationIds.has("runtime-self-defending")
  ].filter(Boolean).length;
  const releaseMetadataReady = releaseEvidence.apiReportConfigured && releaseEvidence.manifestConfigured;

  return [
    {
      id: "review-only-field-capture",
      status: reviewFields.length ? "evidenced" : "not-needed",
      currentEvidence: reviewFields.length
        ? `${reviewFields.length} review-only migration field(s) are captured by name, type, and count only.`
        : "No accepted competitor-only fields were detected.",
      reviewerAction: reviewFields.length
        ? "Confirm each field's release requirement or mark it out of scope before approving the migrated config."
        : "Keep standard validate, release-check, manifest, and protected-build smoke evidence with the release.",
      sourceFree: true
    },
    {
      id: "limitation-groups",
      status: limitations.length ? "evidenced" : "not-needed",
      currentEvidence: limitations.length
        ? `${limitations.length} limitation group(s) were triggered: ${limitations.map((item) => item.id).join(", ")}.`
        : "No grouped migration limitations were triggered.",
      reviewerAction: "Use the limitation groups to decide which specialized packets and smoke tests are required.",
      sourceFree: true
    },
    {
      id: "cli-warning-capture",
      status: cliWarnings.length ? "evidenced" : "not-needed",
      currentEvidence: cliWarnings.length
        ? `${cliWarnings.length} CLI compatibility warning(s) were captured without option values.`
        : "No CLI compatibility warnings were captured for this run.",
      reviewerAction: "Attach the warning list to the migration ticket when review-only flags were passed on the command line.",
      sourceFree: true
    },
    {
      id: "specialized-review-routing",
      status: specializedCount ? "needs-review" : "not-needed",
      currentEvidence: specializedCount
        ? `${specializedCount} specialized follow-up packet(s) are recommended.`
        : "No specialized source-map, identifier-cache, or runtime-defense packet is required by this review.",
      reviewerAction: "Run the listed follow-up commands before final release approval when the corresponding limitation group is present.",
      sourceFree: true
    },
    {
      id: "source-free-release-metadata",
      status: releaseMetadataReady ? "evidenced" : (reviewNeeded ? "needs-review" : "not-needed"),
      currentEvidence: releaseMetadataReady
        ? "API report and release manifest outputs are configured; path values are omitted."
        : "API report or release manifest output is missing from the reviewed config.",
      reviewerAction: "Run protection with --report dist-protected/jso-report.json and --manifest dist-protected/jso-manifest.json so migration decisions attach to the same protected build.",
      sourceFree: true
    },
    {
      id: "protected-build-smoke",
      status: reviewNeeded ? "needs-review" : "not-needed",
      currentEvidence: reviewNeeded
        ? "Protected-build smoke results are not embedded in this config-only review packet."
        : "No migration smoke-test follow-up is required by this config-only review.",
      reviewerAction: "Run browser, Node, framework, and integration smoke tests that cover public API names, strings, runtime locks, console policy, and source-map publication rules affected by migration.",
      sourceFree: true
    }
  ];
}

function buildMigrationReviewDecision(limitations, reviewFields, cliWarnings, reviewEvidence) {
  if (!limitations.length && !reviewFields.length && !cliWarnings.length) {
    return {
      decision: "ready",
      label: "Ready",
      manualReviewRequired: false,
      missingReviewTracks: [],
      reason: "No accepted competitor-only migration fields or grouped limitations were detected.",
      nextAction: "Keep standard release-check, manifest, saved API report, and protected-build smoke evidence with the release."
    };
  }

  const missingReviewTracks = (reviewEvidence || [])
    .filter((item) => item && item.status === "needs-review")
    .map((item) => ({
      id: item.id,
      action: item.reviewerAction
    }));

  return {
    decision: "ready-for-manual-review",
    label: "Ready for manual review",
    manualReviewRequired: true,
    missingReviewTracks,
    reason: "One or more accepted competitor-only migration fields require owner review because there is no one-to-one hosted API mapping.",
    nextAction: "Attach this packet, run the listed specialized follow-up commands, record protected-build smoke results, and approve or remove each review-only assumption before release."
  };
}

function buildMigrationReviewAssistant(summary, reviewDecision, reviewEvidence, followUpCommands, recommendations, sourceBoundary) {
  const questions = [];
  const commands = Array.isArray(followUpCommands) ? followUpCommands : [];
  const evidence = Array.isArray(reviewEvidence) ? reviewEvidence : [];
  const hasSourceMap = summary && summary.sourceMapFields > 0 || commands.some((item) => item.label === "source-map-evidence");
  const hasIdentifier = summary && summary.identifierFields > 0 || commands.some((item) => item.label === "identifier-cache-review");
  const hasRuntime = summary && summary.runtimeFields > 0 || commands.some((item) => item.label === "runtime-defense-review");
  const sourceReadingCommands = commands.filter((item) => item && item.sourceFree === false);

  if (reviewDecision && reviewDecision.manualReviewRequired) {
    questions.push({
      topic: "Manual review tracks",
      prompt: "Review the missing review tracks and decide which owner must close each accepted competitor-only migration assumption.",
      ownerAction: "Record approval, removal, or specialized packet evidence for every review-only field before release."
    });
  }

  if (hasSourceMap) {
    questions.push({
      topic: "Source-map policy",
      prompt: "Confirm whether the migrated project previously published source maps and whether protected artifacts must prove maps are absent.",
      ownerAction: "Run source-map-evidence after protection and attach the source-free packet beside the manifest."
    });
  }

  if (hasIdentifier) {
    questions.push({
      topic: "Identifier-cache replacement",
      prompt: "Confirm which deterministic cache or custom dictionary assumptions affect public APIs, callbacks, framework globals, or integrations.",
      ownerAction: "Run identifier-cache-review and attach reserved-name evidence plus protected-build smoke results."
    });
  }

  if (hasRuntime) {
    questions.push({
      topic: "Runtime-defense behavior",
      prompt: "Confirm which anti-debug, self-defending, console, lock, or countermeasure assumptions are still required in production.",
      ownerAction: "Run runtime-defense-review, wire customer-owned monitoring when needed, and attach compatibility-scan plus browser smoke evidence."
    });
  }

  if (sourceReadingCommands.length > 0) {
    questions.push({
      topic: "Source-reading command boundary",
      prompt: "Confirm which follow-up commands read source or protect source, and who may run them inside the customer-controlled environment.",
      ownerAction: "Share only summarized findings or source-free packets outside the repository boundary."
    });
  }

  if (summary && (!summary.apiReportConfigured || !summary.manifestConfigured)) {
    questions.push({
      topic: "Release metadata",
      prompt: "Confirm whether the protected build will include a saved API report and release manifest so decisions tie back to one artifact.",
      ownerAction: "Add --report and --manifest to the protection run before final migration approval."
    });
  }

  if (evidence.some((item) => item && item.id === "protected-build-smoke" && item.status === "needs-review")) {
    questions.push({
      topic: "Protected-build smoke",
      prompt: "Confirm the protected build was tested across the browser, Node, framework, and integration flows affected by migration settings.",
      ownerAction: "Attach smoke-test result names before marking the migrated config approved."
    });
  }

  if (reviewDecision && reviewDecision.decision === "ready") {
    questions.push({
      topic: "Clean migration handoff",
      prompt: "Confirm no competitor-only migration fields require specialized follow-up and standard release evidence is ready.",
      ownerAction: "Attach validate-config, release-check, manifest, API report, and protected-build smoke evidence with the release."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "review decision",
      "review evidence statuses",
      "follow-up command labels and source-free/source-reading flags",
      "recommendations"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw config files",
      "API credentials",
      "provider keys",
      "customer data",
      "secrets"
    ])));

  return {
    sourceFree: true,
    title: "Migration Review Assistant",
    intendedUse: "Use with a BYO AI key or internal reviewer to turn migration-review evidence into owner actions without sending source code, protected output, source maps, cache contents, config secrets, provider keys, customer data, or secrets.",
    reviewerPrompt: "Review this JSO migration-review packet. Use only review-only field names, field value types/counts, limitation groups, warning text, release metadata states, follow-up command labels, source-free/source-reading flags, review decision, and recommendations. Produce owner actions without requesting source code, protected output, source-map contents, cache contents, raw config files, credentials, provider keys, customer data, or secrets.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function buildMigrationReviewRecommendations(context) {
  const limitations = context.limitations || [];
  const reviewFields = context.reviewFields || [];
  const releaseEvidence = context.releaseEvidence || {};
  const limitationIds = new Set(limitations.map((item) => item.id));
  const recommendations = [
    "Treat this packet as the migration owner checklist for accepted competitor-only fields; it is not a protected-output quality score.",
    "Keep raw source, protected output, source maps, cache files, dictionary values, prefixes, domains, URLs, dates, and seed values out of reviewer prompts and tickets.",
    "Run validate-config, release-check, competitor-gap-report, and protected-build smoke tests before approving the migrated config."
  ];
  if (!releaseEvidence.apiReportConfigured || !releaseEvidence.manifestConfigured) {
    recommendations.push("Add --report and --manifest to the protected build so reviewer evidence can be tied to one BuildID and artifact hash set.");
  }
  if (limitationIds.has("source-maps") || reviewFields.some((field) => field.group === "source-map")) {
    recommendations.push("Run source-map-evidence after protection so reviewers can verify the release does not expose .map files or sourceMappingURL comments.");
  }
  if (limitationIds.has("identifier-name-cache") || limitationIds.has("custom-identifier-dictionary")) {
    recommendations.push("Run identifier-cache-review and confirm reserved-name rules for public APIs, framework globals, callbacks, and integrations.");
  }
  if (limitationIds.has("runtime-self-defending")) {
    recommendations.push("Run runtime-defense-review, wire RuntimeDefenseBeaconUrl when production tamper evidence is required, and run compatibility-scan plus protected-browser smoke tests.");
  }
  if (reviewFields.some((field) => field.field === "seed")) {
    recommendations.push("Set the JSO Seed option (--seed or a config seed) if you need reproducible builds; confirm the migrated seed value produces the intended output and keep seed values out of shared logs.");
  }
  return recommendations;
}

function renderMigrationReviewText(report) {
  const out = [];
  out.push("# Migration Review");
  out.push("");
  out.push(`Generated: ${report.generatedAt}`);
  out.push(`Status: ${report.reviewDecision.label}`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push(`| Review-only fields | ${report.summary.reviewOnlyFields} |`);
  out.push(`| Limitation groups | ${report.summary.limitationGroups} |`);
  out.push(`| CLI warnings | ${report.summary.cliWarnings} |`);
  out.push(`| Source-map fields | ${report.summary.sourceMapFields} |`);
  out.push(`| Identifier fields | ${report.summary.identifierFields} |`);
  out.push(`| Runtime fields | ${report.summary.runtimeFields} |`);
  out.push(`| Other review fields | ${report.summary.otherReviewFields} |`);
  out.push(`| API report configured | ${yesNo(report.summary.apiReportConfigured)} |`);
  out.push(`| Manifest configured | ${yesNo(report.summary.manifestConfigured)} |`);
  out.push("");
  if (report.reviewFields.length) {
    out.push("## Review Fields");
    out.push("");
    out.push("| Field | Group | Source | Type | Count | Note | Redaction |");
    out.push("|---|---|---|---|---|---|---|");
    for (const field of report.reviewFields) {
      const count = field.entryCount != null ? `${field.entryCount} entries` : field.keyCount != null ? `${field.keyCount} keys` : "";
      out.push("| " + [
        field.field,
        field.group,
        field.source,
        field.valueType || "",
        count,
        field.note || "",
        field.redaction || "Value omitted."
      ].map(markdownCell).join(" | ") + " |");
    }
    out.push("");
  }
  if (report.limitations.length) {
    out.push("## Limitations");
    out.push("");
    for (const limitation of report.limitations) {
      out.push(`- ${markdownCell(limitation.id)}: ${markdownCell(limitation.message)} ${markdownCell(limitation.recommendation)}`);
    }
    out.push("");
  }
  if (report.cliWarnings.length) {
    out.push("## CLI Warnings");
    out.push("");
    for (const warning of report.cliWarnings) {
      out.push(`- ${markdownCell(warning.message)}`);
    }
    out.push("");
  }
  out.push("## Review Evidence");
  out.push("");
  out.push("| Track | Status | Evidence | Reviewer action |");
  out.push("|---|---|---|---|");
  for (const item of report.reviewEvidence) {
    out.push("| " + [
      item.id,
      item.status,
      item.currentEvidence,
      item.reviewerAction
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
  renderMigrationReviewAssistant(out, report.reviewAssistant);
  out.push("## Follow-Up Commands");
  out.push("");
  out.push("| Label | Source boundary | Command | Purpose |");
  out.push("|---|---|---|---|");
  for (const command of report.followUpCommands) {
    out.push("| " + [
      command.label,
      command.sourceFree ? "source-free" : "source-reading/protection",
      command.command,
      command.purpose
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
  out.push("## Review Decision");
  out.push("");
  out.push(`Decision: ${report.reviewDecision.label}`);
  out.push(`Reason: ${report.reviewDecision.reason}`);
  out.push(`Next action: ${report.reviewDecision.nextAction}`);
  out.push("");
  out.push("## Source-Free Boundary");
  out.push("");
  out.push("Safe to include:");
  for (const item of report.sourceBoundary.includes) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of report.sourceBoundary.doNotInclude) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("## Recommendations");
  out.push("");
  for (const item of report.recommendations) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Generated by `jso-protector --migration-review`. This packet turns accepted competitor-only migration fields into one source-free owner review checklist.");
  return out.join("\n");
}

function renderMigrationReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("## Migration Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function writeMigrationReviewReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderMigrationReviewText(report)}\n`;
  if (!args.migrationReviewOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.migrationReviewOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`Migration review report written: ${resolvedPath}\n`);
}

function buildIdentifierCacheReviewReport(config = {}, args = {}) {
  const limitations = collectCompetitorLimitations(config, args).filter((item) => (
    item.id === "identifier-name-cache" || item.id === "custom-identifier-dictionary"
  ));
  const requestedFields = collectIdentifierCacheReviewFields(config, args);
  const reservedNameRules = summarizeReservedNameRules(config, args);
  const outputEvidence = {
    apiReportConfigured: !!(args.report || config.report),
    manifestConfigured: !!(args.manifest || config.manifest)
  };
  const replacementEvidence = buildIdentifierCacheReplacementEvidence({
    requestedFields,
    reservedNameRules,
    outputEvidence
  });
  const reviewDecision = buildIdentifierCacheReviewDecision(limitations, requestedFields, replacementEvidence);
  const summary = {
    reviewOnlyLimitations: limitations.length,
    identifierCacheFields: requestedFields.filter((field) => field.group === "identifier-cache").length,
    customDictionaryFields: requestedFields.filter((field) => field.group === "custom-dictionary").length,
    reservedNameRules: reservedNameRules.total,
    apiReportConfigured: outputEvidence.apiReportConfigured,
    manifestConfigured: outputEvidence.manifestConfigured
  };
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "review-only field names",
      "field value types and counts",
      "reserved-name rule counts",
      "API report and manifest configured/not-configured states",
      "reviewer actions for replacing deterministic cache assumptions"
    ],
    doNotInclude: [
      "source code",
      "protected output code",
      "identifierNamesCache contents",
      "identifierNamesCachePath values",
      "identifiersDictionary values",
      "identifiersPrefix values",
      "reservedNames expressions",
      "VariableExclusion expressions"
    ]
  };
  const recommendations = buildIdentifierCacheReviewRecommendations({
    limitations,
    requestedFields,
    reservedNameRules,
    outputEvidence
  });

  return {
    format: "jso-protector-identifier-cache-review",
    version: 1,
    ok: true,
    generatedAt: new Date().toISOString(),
    generatedBy: "jso-protector --identifier-cache-review",
    source: {
      configFile: args.config ? path.basename(args.config) : "default-discovery",
      sourceFree: true,
      valuePolicy: "Only field names, counts, configured/not-configured states, and reviewer actions are included."
    },
    summary,
    requestedFields,
    limitations,
    reservedNameRules,
    replacementEvidence,
    reviewDecision,
    sourceBoundary,
    reviewAssistant: buildIdentifierCacheReviewAssistant(summary, reviewDecision, replacementEvidence, sourceBoundary),
    recommendations
  };
}

function collectIdentifierCacheReviewFields(config = {}, args = {}) {
  const fields = new Set();
  for (const field of ["identifierNamesCache", "identifierNamesCachePath", "identifiersDictionary", "identifiersPrefix"]) {
    if (config[field] !== undefined) fields.add(field);
  }
  for (const field of Array.isArray(args.compatibilityReviewFields) ? args.compatibilityReviewFields : []) {
    if (["identifierNamesCache", "identifierNamesCachePath", "identifiersDictionary", "identifiersPrefix"].includes(field)) {
      fields.add(field);
    }
  }
  return Array.from(fields).sort().map((field) => summarizeIdentifierCacheReviewField(config, args, field));
}

function summarizeIdentifierCacheReviewField(config = {}, args = {}, field) {
  const fromConfig = config[field] !== undefined;
  const value = config[field];
  const summary = {
    field,
    group: field === "identifiersDictionary" || field === "identifiersPrefix" ? "custom-dictionary" : "identifier-cache",
    source: fromConfig ? "config" : "cli-flag",
    valueIncluded: false
  };

  if (field === "identifierNamesCache") {
    summary.valueType = fromConfig ? valueKind(value) : "unknown";
    summary.entryCount = value && typeof value === "object" && !Array.isArray(value) ? Object.keys(value).length : null;
    summary.redaction = "Cache keys and replacement names are omitted.";
  } else if (field === "identifierNamesCachePath") {
    summary.valueType = fromConfig ? valueKind(value) : "unknown";
    summary.pathConfigured = true;
    summary.redaction = "Cache path value is omitted.";
  } else if (field === "identifiersDictionary") {
    summary.valueType = fromConfig ? valueKind(value) : "unknown";
    summary.entryCount = Array.isArray(value) ? value.length : null;
    summary.redaction = "Dictionary values are omitted.";
  } else if (field === "identifiersPrefix") {
    summary.valueType = fromConfig ? valueKind(value) : "unknown";
    summary.prefixConfigured = true;
    summary.redaction = "Prefix value is omitted.";
  }

  if (!fromConfig && Array.isArray(args.compatibilityReviewFields) && args.compatibilityReviewFields.includes(field)) {
    summary.redaction = summary.redaction || "CLI value was consumed for migration compatibility and is omitted.";
  }
  return summary;
}

function valueKind(value) {
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  return typeof value;
}

function summarizeReservedNameRules(config = {}, args = {}) {
  const configReserved = Array.isArray(config.reservedNames) ? config.reservedNames.length : 0;
  const cliReserved = Array.isArray(args.reservedNames) ? args.reservedNames.length : 0;
  const optionReserved = config.options && Array.isArray(config.options.reservedNames) ? config.options.reservedNames.length : 0;
  const variableExclusion = firstReportValue(config, "variableExclusion", "VariableExclusion")
    || firstReportValue(config.options || {}, "VariableExclusion", "variableExclusion");
  const variableExclusionRules = countRuleLines(variableExclusion);
  return {
    total: configReserved + cliReserved + optionReserved + variableExclusionRules,
    configReservedNames: configReserved,
    cliReservedNameFlags: cliReserved,
    optionReservedNames: optionReserved,
    variableExclusionRules,
    valuesIncluded: false
  };
}

function countRuleLines(value) {
  if (Array.isArray(value)) return value.length;
  if (typeof value !== "string") return 0;
  return value.split(/\r?\n|,/).map((entry) => entry.trim()).filter(Boolean).length;
}

function buildIdentifierCacheReplacementEvidence(context) {
  const requestedFields = context.requestedFields || [];
  const reservedNameRules = context.reservedNameRules || { total: 0 };
  const outputEvidence = context.outputEvidence || {};
  return [
    {
      id: "review-only-field-capture",
      status: requestedFields.length ? "evidenced" : "not-needed",
      currentEvidence: requestedFields.length
        ? `${requestedFields.length} identifier cache or custom dictionary field(s) are captured by name only.`
        : "No identifier cache or custom dictionary migration fields were detected.",
      reviewerAction: requestedFields.length
        ? "Confirm the release does not depend on deterministic cache-file reuse before switching to the hosted API workflow."
        : "No identifier-cache replacement review is needed for this config.",
      sourceFree: true
    },
    {
      id: "reserved-name-review",
      status: reservedNameRules.total > 0 ? "evidenced" : "needs-review",
      currentEvidence: reservedNameRules.total > 0
        ? `${reservedNameRules.total} reserved-name rule(s) are configured; expression values are omitted.`
        : "No reserved-name rules are visible in this source-free review.",
      reviewerAction: "Confirm public API names, framework globals, and integration callbacks are covered by reserved-name rules or documented as safe to rename.",
      sourceFree: true
    },
    {
      id: "saved-api-report",
      status: outputEvidence.apiReportConfigured ? "evidenced" : "needs-review",
      currentEvidence: outputEvidence.apiReportConfigured
        ? "API report output is configured; path value is omitted."
        : "No API report output is configured in the reviewed config.",
      reviewerAction: "Run protection with --report dist-protected/jso-report.json and keep the saved source-free API report with the release.",
      sourceFree: true
    },
    {
      id: "release-manifest",
      status: outputEvidence.manifestConfigured ? "evidenced" : "needs-review",
      currentEvidence: outputEvidence.manifestConfigured
        ? "Release manifest output is configured; path value is omitted."
        : "No release manifest output is configured in the reviewed config.",
      reviewerAction: "Run protection with --manifest dist-protected/jso-manifest.json and attach the manifest to the review packet.",
      sourceFree: true
    },
    {
      id: "protected-build-smoke",
      status: "needs-review",
      currentEvidence: "Smoke-test results are not embedded in this config-only review packet.",
      reviewerAction: "Run the protected build through the same browser, Node, and integration smoke tests that gate unprotected output.",
      sourceFree: true
    }
  ];
}

function buildIdentifierCacheReviewDecision(limitations, requestedFields, replacementEvidence) {
  if (!limitations.length && !requestedFields.length) {
    return {
      decision: "ready",
      label: "Ready",
      manualReviewRequired: false,
      missingReviewTracks: [],
      reason: "No identifier cache or custom dictionary migration fields were detected.",
      nextAction: "Keep standard release-check, manifest, and protected-build smoke evidence with the release."
    };
  }

  const missingReviewTracks = (replacementEvidence || [])
    .filter((item) => item && item.status === "needs-review")
    .map((item) => ({
      id: item.id,
      action: item.reviewerAction
    }));

  return {
    decision: "ready-for-manual-review",
    label: "Ready for manual review",
    manualReviewRequired: true,
    missingReviewTracks,
    reason: "Identifier cache or custom dictionary behavior is review-only in the hosted API workflow.",
    nextAction: "Attach this packet, confirm reserved-name rules, keep the saved API report and manifest, and record protected-build smoke results before approving migration."
  };
}

function buildIdentifierCacheReviewAssistant(summary, reviewDecision, replacementEvidence, sourceBoundary) {
  const questions = [];
  const evidence = Array.isArray(replacementEvidence) ? replacementEvidence : [];
  const missingEvidence = evidence.filter((item) => item && item.status === "needs-review");

  if (reviewDecision && reviewDecision.manualReviewRequired) {
    questions.push({
      topic: "Deterministic cache assumption",
      prompt: "Confirm whether the release previously depended on deterministic identifier-name cache reuse, custom dictionary naming, or a fixed prefix.",
      ownerAction: "Approve the hosted API replacement path or remove the migrated cache/dictionary fields before release."
    });
  }

  if (summary && summary.customDictionaryFields > 0) {
    questions.push({
      topic: "Custom dictionary replacement",
      prompt: "Confirm whether custom dictionary or prefix assumptions affect public APIs, framework globals, callbacks, or integrations.",
      ownerAction: "Replace naming assumptions with reserved-name rules and protected-build smoke coverage."
    });
  }

  if (summary && summary.reservedNameRules > 0) {
    questions.push({
      topic: "Reserved-name coverage",
      prompt: "Confirm the reserved-name rule count is enough to cover public contracts without needing cache contents or dictionary values.",
      ownerAction: "Attach the owner-approved public-contract checklist without pasting reserved-name expressions."
    });
  } else {
    questions.push({
      topic: "Missing reserved-name coverage",
      prompt: "Confirm whether the release has public API names, callbacks, framework globals, or integration names that must survive renaming.",
      ownerAction: "Add reserved-name rules or document why no public naming contract exists."
    });
  }

  if (summary && (!summary.apiReportConfigured || !summary.manifestConfigured)) {
    questions.push({
      topic: "Release metadata",
      prompt: "Confirm whether the protected build will include a saved API report and release manifest for the same artifact under review.",
      ownerAction: "Add --report and --manifest to the protection run before final identifier-cache migration approval."
    });
  }

  if (missingEvidence.some((item) => item.id === "protected-build-smoke")) {
    questions.push({
      topic: "Protected-build smoke",
      prompt: "Confirm the protected build still passes the browser, Node, framework, and integration flows affected by renamed identifiers.",
      ownerAction: "Attach smoke-test result names before approving the migration."
    });
  }

  if (reviewDecision && reviewDecision.decision === "ready") {
    questions.push({
      topic: "Clean identifier handoff",
      prompt: "Confirm no deterministic cache or custom dictionary migration fields require focused follow-up.",
      ownerAction: "Attach standard release-check, manifest, saved API report, and protected-build smoke evidence."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "review decision",
      "replacement evidence statuses",
      "recommendations"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw config files",
      "API credentials",
      "provider keys",
      "customer data",
      "secrets"
    ])));

  return {
    sourceFree: true,
    title: "Identifier Cache Review Assistant",
    intendedUse: "Use with a BYO AI key or internal reviewer to turn identifier-cache replacement evidence into owner actions without sending source code, protected output, cache contents, dictionary values, prefixes, reserved-name expressions, raw config files, provider keys, customer data, or secrets.",
    reviewerPrompt: "Review this JSO identifier-cache replacement packet. Use only field names, field value types/counts, reserved-name rule counts, API report and manifest states, replacement evidence statuses, review decision, and recommendations. Produce owner actions without requesting source code, protected output, identifierNamesCache contents, identifierNamesCachePath values, identifiersDictionary values, identifiersPrefix values, reservedNames expressions, raw config files, credentials, provider keys, customer data, or secrets.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function buildIdentifierCacheReviewRecommendations(context) {
  const recommendations = [
    "Treat deterministic identifier-name cache reuse as a migration assumption, not as a hosted API output guarantee.",
    "Use reserved-name rules for public contracts and integration callbacks that must survive renaming.",
    "Keep the saved API report and release manifest with each protected build so reviewers can inspect source-free build metadata."
  ];
  if ((context.reservedNameRules && context.reservedNameRules.total) === 0) {
    recommendations.push("Add reserved-name rules or document why this release has no public names that require preservation.");
  }
  if (!(context.outputEvidence && context.outputEvidence.apiReportConfigured)) {
    recommendations.push("Add --report dist-protected/jso-report.json to capture source-free API metadata for the same build.");
  }
  if (!(context.outputEvidence && context.outputEvidence.manifestConfigured)) {
    recommendations.push("Add --manifest dist-protected/jso-manifest.json so artifact hashes and migration limitations stay attached to the release.");
  }
  if ((context.limitations || []).some((item) => item.id === "custom-identifier-dictionary")) {
    recommendations.push("Spot-check naming-sensitive integrations because custom dictionary and prefix values are not reproduced by the hosted API workflow.");
  }
  return recommendations;
}

function renderIdentifierCacheReviewText(report) {
  const out = [];
  out.push("# Identifier Cache Replacement Review");
  out.push("");
  out.push(`Generated: ${report.generatedAt}`);
  out.push(`Status: ${report.reviewDecision.label}`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push(`| Review-only limitations | ${report.summary.reviewOnlyLimitations} |`);
  out.push(`| Identifier cache fields | ${report.summary.identifierCacheFields} |`);
  out.push(`| Custom dictionary fields | ${report.summary.customDictionaryFields} |`);
  out.push(`| Reserved-name rules | ${report.summary.reservedNameRules} |`);
  out.push(`| API report configured | ${yesNo(report.summary.apiReportConfigured)} |`);
  out.push(`| Manifest configured | ${yesNo(report.summary.manifestConfigured)} |`);
  out.push("");
  if (report.requestedFields.length) {
    out.push("## Requested Fields");
    out.push("");
    out.push("| Field | Source | Type | Count | Redaction |");
    out.push("|---|---|---|---|---|");
    for (const field of report.requestedFields) {
      const count = field.entryCount == null ? "" : String(field.entryCount);
      out.push("| " + [
        field.field,
        field.source,
        field.valueType || "",
        count,
        field.redaction || "Value omitted."
      ].map(markdownCell).join(" | ") + " |");
    }
    out.push("");
  }
  if (report.limitations.length) {
    out.push("## Limitations");
    out.push("");
    for (const limitation of report.limitations) {
      out.push(`- ${markdownCell(limitation.id)}: ${markdownCell(limitation.message)} ${markdownCell(limitation.recommendation)}`);
    }
    out.push("");
  }
  out.push("## Replacement Evidence");
  out.push("");
  out.push("| Track | Status | Evidence | Reviewer action |");
  out.push("|---|---|---|---|");
  for (const item of report.replacementEvidence) {
    out.push("| " + [
      item.id,
      item.status,
      item.currentEvidence,
      item.reviewerAction
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
  renderIdentifierCacheReviewAssistant(out, report.reviewAssistant);
  out.push("## Review Decision");
  out.push("");
  out.push(`Decision: ${report.reviewDecision.label}`);
  out.push(`Reason: ${report.reviewDecision.reason}`);
  out.push(`Next action: ${report.reviewDecision.nextAction}`);
  out.push("");
  out.push("## Source-Free Boundary");
  out.push("");
  out.push("Safe to include:");
  for (const item of report.sourceBoundary.includes) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of report.sourceBoundary.doNotInclude) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("## Recommendations");
  out.push("");
  for (const item of report.recommendations) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Generated by `jso-protector --identifier-cache-review`. This packet replaces deterministic cache-file assumptions with source-free release review evidence.");
  return out.join("\n");
}

function renderIdentifierCacheReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("## Identifier Cache Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function writeIdentifierCacheReviewReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderIdentifierCacheReviewText(report)}\n`;
  if (!args.identifierCacheReviewOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.identifierCacheReviewOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`Identifier cache review report written: ${resolvedPath}\n`);
}

function buildRuntimeDefenseReviewReport(config = {}, args = {}) {
  const limitations = collectCompetitorLimitations(config, args).filter((item) => item.id === "runtime-self-defending");
  const requestedFields = collectRuntimeDefenseReviewFields(config, args);
  const runtimeEvidence = summarizeRuntimeDefenseConfiguredEvidence(config, args);
  const reviewEvidence = buildRuntimeDefenseReviewEvidence({
    requestedFields,
    runtimeEvidence,
    reviewNeeded: limitations.length > 0 || requestedFields.length > 0
  });
  const reviewDecision = buildRuntimeDefenseReviewDecision(limitations, requestedFields, reviewEvidence);
  const summary = {
    reviewOnlyLimitations: limitations.length,
    runtimeReviewFields: requestedFields.length,
    runtimeBeaconConfigured: runtimeEvidence.runtimeBeaconConfigured,
    countermeasurePolicyConfigured: runtimeEvidence.countermeasurePolicyConfigured,
    domainLockConfigured: runtimeEvidence.domainLockConfigured,
    dateLockConfigured: runtimeEvidence.dateLockConfigured,
    apiReportConfigured: runtimeEvidence.apiReportConfigured,
    manifestConfigured: runtimeEvidence.manifestConfigured
  };
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "review-only runtime field names",
      "field value types",
      "runtime-defense configured/not-configured states",
      "API report and manifest configured/not-configured states",
      "reviewer actions for monitoring, countermeasure, compatibility, and smoke-test follow-up"
    ],
    doNotInclude: [
      "source code",
      "protected output code",
      "domainLock or LockDomainList values",
      "LockDateValue or start-date values",
      "domainLockRedirectUrl values",
      "RuntimeDefenseBeaconUrl values",
      "jsConfuserLockCountermeasures values",
      "countermeasure redirect URLs",
      "compatibility-scan source snippets"
    ]
  };
  const recommendations = buildRuntimeDefenseReviewRecommendations({
    limitations,
    requestedFields,
    runtimeEvidence
  });

  return {
    format: "jso-protector-runtime-defense-review",
    version: 1,
    ok: true,
    generatedAt: new Date().toISOString(),
    generatedBy: "jso-protector --runtime-defense-review",
    source: {
      configFile: args.config ? path.basename(args.config) : "default-discovery",
      sourceFree: true,
      valuePolicy: "Only field names, value types, configured/not-configured states, and reviewer actions are included."
    },
    summary,
    requestedFields,
    limitations,
    runtimeEvidence,
    reviewEvidence,
    reviewDecision,
    sourceBoundary,
    reviewAssistant: buildRuntimeDefenseReviewAssistant(summary, reviewDecision, reviewEvidence, runtimeEvidence, sourceBoundary),
    recommendations
  };
}

function collectRuntimeDefenseReviewFields(config = {}, args = {}) {
  const fields = new Set();
  for (const field of RUNTIME_DEFENSE_REVIEW_FIELDS) {
    if (config[field] !== undefined) fields.add(field);
  }
  for (const field of Array.isArray(args.compatibilityReviewFields) ? args.compatibilityReviewFields : []) {
    if (RUNTIME_DEFENSE_REVIEW_FIELDS.includes(field)) fields.add(field);
  }
  return Array.from(fields).sort().map((field) => summarizeRuntimeDefenseReviewField(config, args, field));
}

function summarizeRuntimeDefenseReviewField(config = {}, args = {}, field) {
  const fromConfig = config[field] !== undefined;
  const value = config[field];
  const summary = {
    field,
    group: runtimeDefenseReviewFieldGroup(field),
    source: fromConfig ? "config" : "cli-flag",
    valueType: fromConfig ? valueKind(value) : "unknown",
    valueIncluded: false,
    redaction: runtimeDefenseReviewFieldRedaction(field)
  };
  if (!fromConfig && Array.isArray(args.compatibilityReviewFields) && args.compatibilityReviewFields.includes(field)) {
    summary.redaction = summary.redaction || "CLI value was consumed for migration compatibility and is omitted.";
  }
  return summary;
}

function runtimeDefenseReviewFieldGroup(field) {
  if (Object.prototype.hasOwnProperty.call(JS_CONFUSER_CONFIG_REVIEW_FIELDS, field)) return "js-confuser-runtime-lock";
  return "runtime-defense";
}

function runtimeDefenseReviewFieldRedaction(field) {
  if (field === "jsConfuserLockStartDate") return "Start-date value is omitted.";
  if (field === "jsConfuserLockCountermeasures") return "Countermeasure value is omitted.";
  return "Runtime setting value is omitted.";
}

function summarizeRuntimeDefenseConfiguredEvidence(config = {}, args = {}) {
  const configArg = quoteCommandArg(args.config || "jso.config.json");
  return {
    runtimeBeaconConfigured: hasConfiguredRuntimeOption(config, args, [
      "RuntimeDefenseBeaconUrl",
      "runtimeDefenseBeaconUrl",
      "BeaconUrl",
      "beaconUrl"
    ]),
    countermeasurePolicyConfigured: hasConfiguredRuntimeOption(config, args, [
      "RuntimeDefenseCountermeasure",
      "RuntimeDefenseCountermeasures",
      "CountermeasureMode"
    ]) || config.countermeasures !== undefined || config.runtimeCountermeasures !== undefined,
    domainLockConfigured: hasConfiguredRuntimeOption(config, args, [
      "LockDomain",
      "LockDomainList",
	  "LockDomainRedirectUrl",
      "domainLock"
    ]) || config.domainLock !== undefined || config.domainLockRedirectUrl !== undefined,
    dateLockConfigured: hasConfiguredRuntimeOption(config, args, [
      "LockDate",
      "LockDateValue",
      "lockDate",
      "lockDateValue"
    ]) || config.lockDate !== undefined,
    apiReportConfigured: !!(args.report || config.report),
    manifestConfigured: !!(args.manifest || config.manifest),
    compatibilityScanCommand: `jso-protector --config ${configArg} --compat-scan --json`,
    valuesIncluded: false
  };
}

function hasConfiguredRuntimeOption(config = {}, args = {}, names = []) {
  if (hasAnyOwnCaseInsensitive(config, names)) return true;
  if (config.options && typeof config.options === "object" && hasAnyOwnCaseInsensitive(config.options, names)) return true;
  for (const entry of Array.isArray(args.options) ? args.options : []) {
    const index = String(entry).indexOf("=");
    const name = index > 0 ? String(entry).slice(0, index).trim() : String(entry).trim();
    if (names.some((candidate) => candidate.toLowerCase() === name.toLowerCase())) return true;
  }
  return false;
}

function hasAnyOwnCaseInsensitive(obj, names = []) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const targets = new Set(names.map((name) => String(name).toLowerCase()));
  return Object.keys(obj).some((key) => targets.has(key.toLowerCase()));
}

function buildRuntimeDefenseReviewEvidence(context) {
  const requestedFields = context.requestedFields || [];
  const runtimeEvidence = context.runtimeEvidence || {};
  const reviewNeeded = context.reviewNeeded === true;
  const releaseMetadataReady = runtimeEvidence.apiReportConfigured && runtimeEvidence.manifestConfigured;
  return [
    {
      id: "review-only-runtime-fields",
      status: requestedFields.length ? "evidenced" : "not-needed",
      currentEvidence: requestedFields.length
        ? `${requestedFields.length} runtime defense or lock field(s) are captured by name only.`
        : "No runtime-defense migration fields were detected.",
      reviewerAction: requestedFields.length
        ? "Confirm each anti-debug, self-defending, console, lock, or countermeasure requirement before release approval."
        : "No runtime-defense migration review is needed for this config.",
      sourceFree: true
    },
    {
      id: "runtime-monitoring-target",
      status: runtimeEvidence.runtimeBeaconConfigured ? "evidenced" : (reviewNeeded ? "needs-review" : "not-needed"),
      currentEvidence: runtimeEvidence.runtimeBeaconConfigured
        ? "RuntimeDefenseBeaconUrl is configured; URL value is omitted."
        : "No runtime-defense beacon target is configured in this source-free review.",
      reviewerAction: "Set RuntimeDefenseBeaconUrl to hosted dashboard intake or a customer-owned forwarding endpoint when runtime tamper evidence is required.",
      sourceFree: true
    },
    {
      id: "customer-owned-forwarding",
      status: runtimeEvidence.runtimeBeaconConfigured ? "evidenced" : (reviewNeeded ? "needs-review" : "not-needed"),
      currentEvidence: runtimeEvidence.runtimeBeaconConfigured
        ? "A beacon target exists; endpoint details are omitted."
        : "No forwarding target is visible in the reviewed config.",
      reviewerAction: "Document whether runtime events go to Dashboard Monitoring, Slack, Splunk, Elasticsearch, a signed webhook, or another customer-owned system.",
      sourceFree: true
    },
    {
      id: "countermeasure-policy",
      status: runtimeEvidence.countermeasurePolicyConfigured ? "evidenced" : (reviewNeeded ? "needs-review" : "not-needed"),
      currentEvidence: runtimeEvidence.countermeasurePolicyConfigured
        ? "Countermeasure policy is configured; action names and redirect values are omitted."
        : "No countermeasure policy is visible in this source-free review.",
      reviewerAction: "Confirm allowed runtime reactions, escalation path, and rollback owner before enabling tamper countermeasures in production.",
      sourceFree: true
    },
    {
      id: "mapped-domain-date-locks",
      status: (runtimeEvidence.domainLockConfigured || runtimeEvidence.dateLockConfigured)
        ? "evidenced"
        : "not-needed",
      currentEvidence: (runtimeEvidence.domainLockConfigured || runtimeEvidence.dateLockConfigured)
        ? "Domain or date lock options are configured; domain and date values are omitted."
        : "No mapped domain/date lock options are visible in this source-free review.",
      reviewerAction: "Smoke-test allowed domains, blocked domains, and expiry behavior in staging when lock behavior changed during migration.",
      sourceFree: true
    },
    {
      id: "source-free-release-metadata",
      status: releaseMetadataReady ? "evidenced" : (reviewNeeded ? "needs-review" : "not-needed"),
      currentEvidence: releaseMetadataReady
        ? "API report and release manifest outputs are configured; path values are omitted."
        : "API report or release manifest output is missing from the reviewed config.",
      reviewerAction: "Run protection with --report dist-protected/jso-report.json and --manifest dist-protected/jso-manifest.json so runtime-review decisions attach to the same protected build.",
      sourceFree: true
    },
    {
      id: "compatibility-scan",
      status: reviewNeeded ? "needs-review" : "not-needed",
      currentEvidence: reviewNeeded
        ? "Source-reading compatibility-scan results are not embedded in this source-free packet."
        : "No compatibility scan is required by this config-only runtime review.",
      reviewerAction: `Run ${runtimeEvidence.compatibilityScanCommand || "jso-protector --config jso.config.json --compat-scan --json"} before approving runtime-lock migrations that may affect reflection, debugging, console output, or tamper behavior.`,
      sourceFree: true,
      followUpReadsSource: reviewNeeded
    },
    {
      id: "protected-build-smoke",
      status: reviewNeeded ? "needs-review" : "not-needed",
      currentEvidence: reviewNeeded
        ? "Smoke-test results are not embedded in this config-only review packet."
        : "No runtime-defense smoke test is required by this config-only review.",
      reviewerAction: "Run protected-browser and integration smoke tests with debugger-open, console, domain-lock, date-lock, and tamper-event cases that match the release risk.",
      sourceFree: true
    }
  ];
}

function buildRuntimeDefenseReviewDecision(limitations, requestedFields, reviewEvidence) {
  if (!limitations.length && !requestedFields.length) {
    return {
      decision: "ready",
      label: "Ready",
      manualReviewRequired: false,
      missingReviewTracks: [],
      reason: "No anti-debug, self-defending, runtime lock, console, or countermeasure migration fields were detected.",
      nextAction: "Keep standard release-check, manifest, protected-build smoke, and runtime incident evidence with the release."
    };
  }

  const missingReviewTracks = (reviewEvidence || [])
    .filter((item) => item && item.status === "needs-review")
    .map((item) => ({
      id: item.id,
      action: item.reviewerAction
    }));

  return {
    decision: "ready-for-manual-review",
    label: "Ready for manual review",
    manualReviewRequired: true,
    missingReviewTracks,
    reason: "Runtime defense, lock, console, or countermeasure behavior is review-only in the hosted API workflow.",
    nextAction: "Attach this packet, wire runtime monitoring, document countermeasure policy, run the compatibility scan, and record protected-build smoke results before approving migration."
  };
}

function buildRuntimeDefenseReviewAssistant(summary, reviewDecision, reviewEvidence, runtimeEvidence, sourceBoundary) {
  const questions = [];
  const evidence = Array.isArray(reviewEvidence) ? reviewEvidence : [];
  const needs = (id) => evidence.some((item) => item && item.id === id && item.status === "needs-review");

  if (reviewDecision && reviewDecision.manualReviewRequired) {
    questions.push({
      topic: "Runtime behavior scope",
      prompt: "Confirm which anti-debug, self-defending, console, lock, or countermeasure behaviors are still required after migration.",
      ownerAction: "Approve, replace, or remove each runtime-defense assumption before release."
    });
  }

  if (needs("runtime-monitoring-target")) {
    questions.push({
      topic: "Monitoring target",
      prompt: "Decide whether runtime tamper events should route to hosted Dashboard Monitoring or a customer-owned forwarding endpoint.",
      ownerAction: "Configure RuntimeDefenseBeaconUrl or document why this release does not need runtime event forwarding."
    });
  } else if (summary && summary.runtimeBeaconConfigured) {
    questions.push({
      topic: "Monitoring handoff",
      prompt: "Confirm the configured runtime beacon destination has an owner, response path, and retention expectation.",
      ownerAction: "Attach the source-free routing decision without pasting beacon URLs or tokens."
    });
  }

  if (needs("countermeasure-policy") || (summary && summary.countermeasurePolicyConfigured)) {
    questions.push({
      topic: "Countermeasure policy",
      prompt: "Confirm allowed runtime reactions, escalation path, rollback owner, and production-safe default behavior.",
      ownerAction: "Record whether the release observes, redirects, disables features, or forwards events without sharing countermeasure values or URLs."
    });
  }

  if (summary && (summary.domainLockConfigured || summary.dateLockConfigured)) {
    questions.push({
      topic: "Domain/date lock smoke",
      prompt: "Confirm allowed domains, blocked domains, and expiry behavior were tested in staging without exposing domain or date values in the packet.",
      ownerAction: "Attach protected-build smoke result names for lock behavior."
    });
  }

  if (needs("source-free-release-metadata")) {
    questions.push({
      topic: "Release metadata",
      prompt: "Confirm whether the protected build will include a saved API report and release manifest for the same artifact under review.",
      ownerAction: "Add --report and --manifest to the protection run before final runtime-defense migration approval."
    });
  }

  if (needs("compatibility-scan")) {
    questions.push({
      topic: "Source-reading compatibility scan",
      prompt: "Confirm who may run the compatibility scan inside the customer-controlled repository or CI environment.",
      ownerAction: `Run ${runtimeEvidence && runtimeEvidence.compatibilityScanCommand ? runtimeEvidence.compatibilityScanCommand : "jso-protector --config jso.config.json --compat-scan --json"} and share summarized findings, not source snippets.`
    });
  }

  if (needs("protected-build-smoke")) {
    questions.push({
      topic: "Protected-build smoke",
      prompt: "Confirm debugger-open, console-policy, domain/date-lock, countermeasure, and tamper-event flows pass on the protected build.",
      ownerAction: "Attach smoke-test result names before approving the migration."
    });
  }

  if (reviewDecision && reviewDecision.decision === "ready") {
    questions.push({
      topic: "Clean runtime handoff",
      prompt: "Confirm no runtime-defense migration fields require focused follow-up and standard release evidence is ready.",
      ownerAction: "Attach release-check, manifest, saved API report, runtime incident evidence when applicable, and protected-build smoke evidence."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "review decision",
      "review evidence statuses",
      "compatibility scan command label",
      "recommendations"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw config files",
      "API credentials",
      "provider keys",
      "collector tokens",
      "customer data",
      "secrets"
    ])));

  return {
    sourceFree: true,
    title: "Runtime Defense Review Assistant",
    intendedUse: "Use with a BYO AI key or internal reviewer to turn runtime-defense migration evidence into owner actions without sending source code, protected output, domains, dates, redirect URLs, beacon URLs, countermeasure values, raw config files, provider keys, customer data, or secrets.",
    reviewerPrompt: "Review this JSO runtime-defense migration packet. Use only field names, value types, configured/not-configured states, review evidence statuses, compatibility scan command labels, review decision, and recommendations. Produce owner actions without requesting source code, protected output, domain values, date values, redirect URLs, beacon URLs, countermeasure values, compatibility-scan snippets, raw config files, credentials, provider keys, customer data, or secrets.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function buildRuntimeDefenseReviewRecommendations(context) {
  const recommendations = [
    "Treat competitor anti-debug, self-defending, integrity, console, and countermeasure switches as migration requirements, not as one-to-one hosted API options.",
    "Route RuntimeDefenseBeaconUrl to hosted dashboard intake or a customer-owned monitoring endpoint when production tamper evidence is required.",
    "Keep the saved API report and release manifest with the same protected build so runtime-defense decisions can be reviewed without sharing source code.",
    "Run source-reading compatibility scan and protected-build smoke tests before approving runtime-lock migrations."
  ];
  const runtimeEvidence = context.runtimeEvidence || {};
  if (!runtimeEvidence.runtimeBeaconConfigured) {
    recommendations.push("Add RuntimeDefenseBeaconUrl or document why this release does not need runtime event forwarding.");
  }
  if (!runtimeEvidence.countermeasurePolicyConfigured) {
    recommendations.push("Document the allowed runtime countermeasure policy even when the initial production action is observe-only.");
  }
  if (runtimeEvidence.domainLockConfigured || runtimeEvidence.dateLockConfigured) {
    recommendations.push("Test mapped domain/date locks in staging because allowed domains, blocked domains, and expiry windows are operational behavior, not static proof.");
  }
  if ((context.requestedFields || []).some((field) => field.field === "disableConsoleOutput")) {
    recommendations.push("Confirm console-output policy with support and observability owners before suppressing logs in protected production bundles.");
  }
  return recommendations;
}

function renderRuntimeDefenseReviewText(report) {
  const out = [];
  out.push("# Runtime Defense Migration Review");
  out.push("");
  out.push(`Generated: ${report.generatedAt}`);
  out.push(`Status: ${report.reviewDecision.label}`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push(`| Review-only limitations | ${report.summary.reviewOnlyLimitations} |`);
  out.push(`| Runtime review fields | ${report.summary.runtimeReviewFields} |`);
  out.push(`| Runtime beacon configured | ${yesNo(report.summary.runtimeBeaconConfigured)} |`);
  out.push(`| Countermeasure policy configured | ${yesNo(report.summary.countermeasurePolicyConfigured)} |`);
  out.push(`| Domain lock configured | ${yesNo(report.summary.domainLockConfigured)} |`);
  out.push(`| Date lock configured | ${yesNo(report.summary.dateLockConfigured)} |`);
  out.push(`| API report configured | ${yesNo(report.summary.apiReportConfigured)} |`);
  out.push(`| Manifest configured | ${yesNo(report.summary.manifestConfigured)} |`);
  out.push("");
  if (report.requestedFields.length) {
    out.push("## Requested Fields");
    out.push("");
    out.push("| Field | Group | Source | Type | Redaction |");
    out.push("|---|---|---|---|---|");
    for (const field of report.requestedFields) {
      out.push("| " + [
        field.field,
        field.group,
        field.source,
        field.valueType || "",
        field.redaction || "Value omitted."
      ].map(markdownCell).join(" | ") + " |");
    }
    out.push("");
  }
  if (report.limitations.length) {
    out.push("## Limitations");
    out.push("");
    for (const limitation of report.limitations) {
      out.push(`- ${markdownCell(limitation.id)}: ${markdownCell(limitation.message)} ${markdownCell(limitation.recommendation)}`);
    }
    out.push("");
  }
  out.push("## Review Evidence");
  out.push("");
  out.push("| Track | Status | Evidence | Reviewer action |");
  out.push("|---|---|---|---|");
  for (const item of report.reviewEvidence) {
    out.push("| " + [
      item.id,
      item.status,
      item.currentEvidence,
      item.reviewerAction
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
  renderRuntimeDefenseReviewAssistant(out, report.reviewAssistant);
  out.push("## Review Decision");
  out.push("");
  out.push(`Decision: ${report.reviewDecision.label}`);
  out.push(`Reason: ${report.reviewDecision.reason}`);
  out.push(`Next action: ${report.reviewDecision.nextAction}`);
  out.push("");
  out.push("## Source-Free Boundary");
  out.push("");
  out.push("Safe to include:");
  for (const item of report.sourceBoundary.includes) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of report.sourceBoundary.doNotInclude) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("## Recommendations");
  out.push("");
  for (const item of report.recommendations) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Generated by `jso-protector --runtime-defense-review`. This packet turns anti-debug, self-defending, runtime lock, console, and countermeasure migration settings into source-free release review evidence.");
  return out.join("\n");
}

function renderRuntimeDefenseReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("## Runtime Defense Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function writeRuntimeDefenseReviewReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderRuntimeDefenseReviewText(report)}\n`;
  if (!args.runtimeDefenseReviewOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.runtimeDefenseReviewOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`Runtime defense review report written: ${resolvedPath}\n`);
}

function isValidUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (_error) {
    return false;
  }
}

const COMPATIBILITY_SCAN_RULES = [
  {
    id: "function-source-reflection",
    pattern: /\bFunction\s*\.\s*prototype\s*\.\s*toString\s*\.\s*call\s*\(/g,
    message: "Function source reflection can break because obfuscation changes function source text."
  },
  {
    id: "constructor-name-reflection",
    pattern: /\.constructor\.name\b/g,
    message: "Constructor name reflection can break because obfuscation renames function and class identifiers."
  },
  {
    id: "name-reflection",
    pattern: /\.\s*name\b/g,
    message: "Name-based reflection can break because obfuscation renames function and class identifiers."
  },
  {
    id: "classic-script-public-global",
    pattern: /^(?:(?:\s+)|(?:\/\*[\s\S]*?\*\/)|(?:\/\/[^\r\n]*(?:\r?\n|$)))*var\s+(?<name>[A-Za-z_$][\w$]*)\s*=\s*\(?\s*function\b/g,
    message: "A browser distribution publishes a top-level global. Preserve this script-tag API when RenameGlobals is enabled."
  },
  {
    id: "assigned-public-global",
    pattern: /\b(?:window|globalThis|self)\s*\.\s*(?<name>[A-Za-z_$][\w$]*)\s*=/g,
    message: "Code assigns a public browser global. Preserve this external API when RenameGlobals is enabled."
  }
];

function findLineNumber(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function buildSnippet(text, index, length) {
  const lineStart = text.lastIndexOf("\n", index - 1) + 1;
  const lineEndIndex = text.indexOf("\n", index + length);
  const lineEnd = lineEndIndex === -1 ? text.length : lineEndIndex;
  return text.slice(lineStart, lineEnd).trim();
}

function scanTextCompatibilityRisks(fileName, code) {
  const findings = [];
  for (const rule of COMPATIBILITY_SCAN_RULES) {
    rule.pattern.lastIndex = 0;
    let match = rule.pattern.exec(code);
    while (match) {
      if (rule.id === "name-reflection") {
        const prefix = code.slice(Math.max(0, match.index - 12), match.index);
        if (prefix.endsWith(".constructor")) {
          match = rule.pattern.exec(code);
          continue;
        }
      }
      const publicGlobalName = match.groups && match.groups.name ? match.groups.name : null;
      const locationIndex = publicGlobalName ? match.index + match[0].lastIndexOf(publicGlobalName) : match.index;
      findings.push({
        ruleId: rule.id,
        fileName,
        line: findLineNumber(code, locationIndex),
        snippet: buildSnippet(code, locationIndex, publicGlobalName ? publicGlobalName.length : match[0].length),
        message: rule.message,
        ...(publicGlobalName ? { publicGlobalName, suggestedVariableExclusion: `^${publicGlobalName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$` } : {})
      });
      match = rule.pattern.exec(code);
    }
  }
  return findings;
}

function scanCompatibilityRisks(config) {
  const files = collectFiles(config.input, config.output, config.extensions, config.exclude, config.include, config.markupExtensions);
  const findings = [];

  for (const file of files) {
    const code = fs.readFileSync(file.source, "utf8");
    findings.push(...scanTextCompatibilityRisks(file.relative, code));
  }

  return {
    format: "jso-protector-compatibility-scan",
    version: 1,
    ok: true,
    input: config.input,
    output: config.output,
    scannedFiles: files.map((file) => file.relative),
    summary: {
      files: files.length,
      findings: findings.length,
      filesWithFindings: new Set(findings.map((finding) => finding.fileName)).size
    },
    findings
  };
}

function writeCompatibilityScanReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`jso-protector compat-scan: ${report.summary.findings ? "warning" : "ok"}\n`);
  process.stdout.write(`files: ${report.summary.files}, findings: ${report.summary.findings}\n`);
  for (const finding of report.findings) {
    process.stdout.write(`WARN ${finding.fileName}:${finding.line} ${finding.ruleId}: ${finding.message}\n`);
    if (finding.suggestedVariableExclusion) {
      process.stdout.write(`  Suggested VariableExclusion: ${finding.suggestedVariableExclusion}\n`);
    }
  }
}

function writeDoctorReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`jso-protector doctor: ${report.ok ? "ok" : "failed"}\n`);
  for (const limitation of report.limitations || []) {
    process.stdout.write(`LIMITATION ${limitation.id}: ${limitation.message} Fields: ${limitation.fields.join(", ")}. ${limitation.recommendation}\n`);
  }
  for (const check of report.checks) {
    process.stdout.write(`${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.message}\n`);
  }
}

async function runReleaseCheck(config, args = {}) {
  const validation = validateProtectionConfig(config, args);
  let resolved = null;
  let plan = null;
  let doctor = null;

  try {
    resolved = mergeConfig(config, args);
  } catch (error) {
    plan = { ok: false, error: error.message };
  }

  if (resolved) {
    plan = buildReleasePlan(resolved);
    doctor = await runDoctor(resolved, {
      ...args,
      rawConfig: config
    });
  }

  return {
    format: "jso-protector-release-check",
    version: 1,
    ok: validation.ok && (!plan || plan.ok) && (!doctor || doctor.ok),
    endpoint: resolved ? resolved.endpoint : null,
    projectName: resolved ? resolved.projectName : null,
    preset: resolved ? resolved.preset : null,
    validation,
    plan,
    doctor,
    checkApi: !!args.checkApi
  };
}

function buildReleasePlan(config) {
  try {
    const files = collectFiles(config.input, config.output, config.extensions, config.exclude, config.include);
    const assets = config.copyAssets ? collectAssets(config.input, config.output, files, config.assetExclude) : [];
    const protection = buildProtectionItems(config, files);
    return addProtectionSummary({
      ok: files.length > 0,
      input: config.input,
      output: config.output,
      files: files.map((file) => file.relative),
      assets: assets.map((file) => file.relative),
      options: Object.keys(config.options || {}).filter((key) => key !== "reservedNames"),
      manifest: config.manifest || null,
      maxOutputBytes: config.maxOutputBytes || null,
      maxGrowthRatio: config.maxGrowthRatio || null,
      error: files.length > 0 ? null : "No matching input files found."
    }, protection);
  } catch (error) {
    return {
      ok: false,
      input: config.input,
      output: config.output,
      files: [],
      assets: [],
      options: Object.keys(config.options || {}).filter((key) => key !== "reservedNames"),
      manifest: config.manifest || null,
      maxOutputBytes: config.maxOutputBytes || null,
      maxGrowthRatio: config.maxGrowthRatio || null,
      processing: { apiItems: 0, transformedFiles: [] },
      error: error.message
    };
  }
}

function writeReleaseCheckReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`jso-protector release-check: ${report.ok ? "ok" : "failed"}\n`);
  process.stdout.write(`validation: ${report.validation && report.validation.ok ? "ok" : "failed"}${report.validation && report.validation.warnings ? ` (${report.validation.warnings} warning(s))` : ""}\n`);
  for (const limitation of report.validation && report.validation.limitations || []) {
    process.stdout.write(`LIMITATION ${limitation.id}: ${limitation.message} Fields: ${limitation.fields.join(", ")}. ${limitation.recommendation}\n`);
  }
  if (report.plan) {
    const processing = report.plan.processing || { apiItems: 0, transformedFiles: [] };
    process.stdout.write(`plan: ${report.plan.ok ? "ok" : "failed"} (${(report.plan.files || []).length} file(s), ${(report.plan.assets || []).length} asset(s), ${processing.apiItems || 0} API item(s))\n`);
    if (processing.transformedFiles && processing.transformedFiles.length) {
      for (const entry of processing.transformedFiles) {
        process.stdout.write(`transform ${entry.fileName}: ${entry.type}, ${entry.apiItems} API item(s), ${entry.preservedParts} preserved part(s)\n`);
      }
    }
    if (report.plan.error) process.stdout.write(`plan error: ${report.plan.error}\n`);
  }
  if (report.doctor) {
    process.stdout.write(`doctor: ${report.doctor.ok ? "ok" : "failed"}\n`);
    for (const check of report.doctor.checks) {
      process.stdout.write(`${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.message}\n`);
    }
  }
}

function validateProtectionConfig(config, args = {}) {
  const checks = [];
  let resolved = null;
  const limitations = collectCompetitorLimitations(config, args);

  try {
    validateRawConfigShape(config);
    resolved = mergeConfig(config, args);
    addValidationCheck(checks, "config", "ok", "Config shape is valid.");
  } catch (error) {
    addValidationCheck(checks, "config", "error", error.message);
    return buildValidationReport(checks, null, args.strict, limitations);
  }

  addValidationCheck(checks, "endpoint", isValidUrl(resolved.endpoint) ? "ok" : "error", isValidUrl(resolved.endpoint) ? `Endpoint: ${resolved.endpoint}` : "Endpoint must be a valid HTTP or HTTPS URL.");
  addValidationCheck(checks, "apiKey", resolved.apiKey ? "ok" : "error", resolved.apiKey ? "API key is present." : "Missing API key. Set JSO_API_KEY, JAVASCRIPT_OBFUSCATOR_API_KEY, or apiKey in config.");
  addValidationCheck(checks, "apiPassword", resolved.apiPassword ? "ok" : "error", resolved.apiPassword ? "API password is present." : "Missing API password. Set JSO_API_PASSWORD, JAVASCRIPT_OBFUSCATOR_API_PASSWORD, or apiPassword in config.");
  addCredentialStorageValidation(checks, config, args);
  addValidationCheck(checks, "preset", "ok", `Preset: ${resolved.preset}`);
  addValidationCheck(checks, "paths", resolved.input && resolved.output ? "ok" : "error", resolved.input && resolved.output ? "Input and output paths are configured." : "Input and output paths must be configured.");

  if (resolved.input && !fs.existsSync(resolved.input)) {
    addValidationCheck(checks, "input", "warning", `Input path does not exist yet: ${resolved.input}`);
  } else if (resolved.input) {
    addValidationCheck(checks, "input", "ok", `Input exists: ${resolved.input}`);
  }

  const outputParent = resolved.output ? path.dirname(resolved.output) : "";
  if (outputParent && !fs.existsSync(outputParent)) {
    addValidationCheck(checks, "output", "warning", `Output parent does not exist yet: ${outputParent}`);
  } else if (outputParent) {
    addValidationCheck(checks, "output", "ok", `Output parent exists: ${outputParent}`);
  }

  const unknownOptions = findUnknownOptionNames(config, args);
  if (unknownOptions.length) {
    addValidationCheck(checks, "options", "warning", `Unknown option name(s): ${unknownOptions.join(", ")}. Verify spelling or confirm they are supported by the HTTP API.`);
  } else {
    addValidationCheck(checks, "options", "ok", "Option names match the local reference.");
  }

  const runtimeAction = String((resolved.options && resolved.options.RuntimeDefenseAction) || "").trim().toLowerCase();
  const runtimeRedirect = String((resolved.options && resolved.options.RuntimeDefenseRedirectUrl) || "").trim();
  if (runtimeAction === "redirect") {
    const safeRelative = runtimeRedirect.startsWith("/") && !runtimeRedirect.startsWith("//") && !runtimeRedirect.includes("\\");
    let safeAbsolute = false;
    try {
      const parsed = new URL(runtimeRedirect);
      safeAbsolute = parsed.protocol === "https:" || parsed.protocol === "http:";
    } catch { }
    addValidationCheck(checks, "runtimeDefenseRedirect", safeRelative || safeAbsolute ? "ok" : "error",
      safeRelative || safeAbsolute
        ? "Runtime defense redirect uses an HTTP(S) URL or same-origin root-relative path."
        : "RuntimeDefenseRedirectUrl must be an HTTP(S) URL or same-origin root-relative path when RuntimeDefenseAction is redirect.");
  }

  const compatibilityReviewFields = getCompatibilityReviewFields(config);
  if (compatibilityReviewFields.length) {
    addValidationCheck(checks, "compatibility", "warning", `Config includes javascript-obfuscator review-only field(s): ${compatibilityReviewFields.join(", ")}. They are accepted for migration compatibility, but require manual review because the hosted API has no one-to-one mapping.`);
  }

  if (resolved.manifest) {
    const manifestParent = path.dirname(resolved.manifest);
    addValidationCheck(checks, "manifest", fs.existsSync(manifestParent) ? "ok" : "warning", fs.existsSync(manifestParent) ? `Manifest parent exists: ${manifestParent}` : `Manifest parent does not exist yet: ${manifestParent}`);
  }

  if (resolved.maxOutputBytes || resolved.maxGrowthRatio) {
    addValidationCheck(checks, "budgets", "ok", "Size budgets are configured.");
  }

  return buildValidationReport(checks, resolved, args.strict, limitations);
}

function validateRawConfigShape(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("Config must be a JSON object.");
  }

  const allowedKeys = new Set([
    "$schema",
    "__configDir",
    "format",
    "version",
    "standardOptions",
    "advancedFeatures",
    "variableExclusionList",
    "endpoint",
    "apiKey",
    "apiPassword",
    "projectName",
    "input",
    "output",
    "preset",
    "compact",
    "selfDefending",
    "debugProtection",
    "debugProtectionInterval",
    "debugProtectionIntervalMilliseconds",
    "disableConsoleOutput",
    "domainLockRedirectUrl",
    "controlFlowFlattening",
    "deadCodeInjection",
    "deadCodeInjectionThreshold",
    "domainLock",
    "identifierNamesGenerator",
    "optionsPreset",
    "renameGlobals",
    "renameProperties",
    "stringArray",
    "splitStrings",
    "splitStringsChunkLength",
    "stringArrayIndexShift",
    "stringArrayShuffle",
    "stringArrayRotate",
    "stringArrayIndexesType",
    "stringArrayCallsTransform",
    "stringArrayCallsTransformThreshold",
    "stringArrayWrappersCount",
    "stringArrayWrappersChainedCalls",
    "stringArrayWrappersParametersMaxCount",
    "stringArrayWrappersType",
    "transformObjectKeys",
    "stringArrayEncoding",
    "stringArrayThreshold",
    "target",
    "unicodeEscapeSequence",
    "webPreset",
    "include",
    "extensions",
    "markupExtensions",
    "exclude",
    "assetExclude",
    "copyAssets",
    "mixedServer",
    "parseHtml",
    "honorConditionalComments",
    "protectMarkedComments",
    "ignoreImports",
    "keepHeaderComment",
    "protectObjectDeclaration",
    "moveNestedFunction",
    "formattedOutput",
    "keepIndent",
    "lineNumbers",
    "lockDomainSubdomains",
    "lockDomainMessage",
    "lockDate",
    "lockDateValue",
    "lockDateMessage",
    ...CONVENIENCE_OPTION_ALIASES.map((alias) => alias.configKey),
    ...Object.keys(JS_CONFUSER_CONFIG_REVIEW_FIELDS),
	...JS_CONFUSER_CONFIG_MAPPED_FIELDS,
    "reservedNames",
	"reservedStrings",
	"forceTransformStrings",
    "variableExclusion",
    "removeSourceMaps",
    "manifest",
    "maxOutputBytes",
    "maxGrowthRatio",
    "options",
    ...Object.keys(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS)
  ]);

  const unknownKeys = Object.keys(config).filter((key) => !allowedKeys.has(key));
  if (unknownKeys.length) {
    throw new Error(`Unknown config field(s): ${unknownKeys.join(", ")}`);
  }

  validateOptionalString("endpoint", config.endpoint);
  validateOptionalString("apiKey", config.apiKey);
  validateOptionalString("apiPassword", config.apiPassword);
  validateOptionalString("projectName", config.projectName);
  validateOptionalString("input", config.input);
  validateOptionalString("output", config.output);
  validateOptionalString("preset", config.preset);
  validateOptionalBoolean("compact", config.compact);
  validateOptionalBoolean("selfDefending", config.selfDefending);
  if (config.selfDefendingIntervalSeconds !== undefined && (!Number.isInteger(config.selfDefendingIntervalSeconds) || config.selfDefendingIntervalSeconds < 1 || config.selfDefendingIntervalSeconds > 86400)) {
    throw new Error("selfDefendingIntervalSeconds must be an integer from 1 through 86400.");
  }
  validateOptionalBoolean("selfHealing", config.selfHealing);
  if (config.selfHealingMaxAttempts !== undefined && (!Number.isInteger(config.selfHealingMaxAttempts) || config.selfHealingMaxAttempts < 1 || config.selfHealingMaxAttempts > 10)) {
    throw new Error("selfHealingMaxAttempts must be an integer from 1 through 10.");
  }
  validateOptionalBoolean("antiMonkeyPatching", config.antiMonkeyPatching);
  validateOptionalBoolean("antiMonkeyPatchingCleanRealm", config.antiMonkeyPatchingCleanRealm);
  validateOptionalString("antiMonkeyPatchingIncludeGlobals", config.antiMonkeyPatchingIncludeGlobals);
  validateOptionalString("antiMonkeyPatchingExcludeGlobals", config.antiMonkeyPatchingExcludeGlobals);
  validateOptionalString("runtimeDefenseAction", config.runtimeDefenseAction);
  if (config.runtimeDefenseAction !== undefined && !["throw", "blank", "redirect", "reload", "callback", "degrade"].includes(String(config.runtimeDefenseAction).toLowerCase())) {
    throw new Error("runtimeDefenseAction must be throw, blank, redirect, reload, callback, or degrade.");
  }
  validateOptionalString("runtimeDefenseCallback", config.runtimeDefenseCallback);
  validateOptionalString("runtimeDefenseRedirectUrl", config.runtimeDefenseRedirectUrl);
  validateOptionalBoolean("debugProtection", config.debugProtection);
  if (config.debugProtectionInterval !== undefined) normalizeDebugProtectionInterval(config.debugProtectionInterval);
  if (config.debugProtectionIntervalMilliseconds !== undefined) normalizeDebugProtectionInterval(config.debugProtectionIntervalMilliseconds, "debugProtectionIntervalMilliseconds");
  validateOptionalBoolean("disableConsoleOutput", config.disableConsoleOutput);
  validateOptionalBoolean("splitStrings", config.splitStrings);
  validateOptionalBoolean("stringArrayIndexShift", config.stringArrayIndexShift);
  validateOptionalBoolean("stringArrayShuffle", config.stringArrayShuffle);
  validateOptionalBoolean("stringArrayRotate", config.stringArrayRotate);
  if (config.stringArrayIndexesType !== undefined) normalizeStringArrayIndexesType(config.stringArrayIndexesType);
  validateOptionalBoolean("stringArrayCallsTransform", config.stringArrayCallsTransform);
  if (config.stringArrayCallsTransformThreshold !== undefined) normalizeProbability(config.stringArrayCallsTransformThreshold, "stringArrayCallsTransformThreshold");
  if (config.stringArrayWrappersCount !== undefined) normalizeIntegerRange(config.stringArrayWrappersCount, "stringArrayWrappersCount", 0, 10);
  validateOptionalBoolean("stringArrayWrappersChainedCalls", config.stringArrayWrappersChainedCalls);
  if (config.stringArrayWrappersParametersMaxCount !== undefined) normalizeIntegerRange(config.stringArrayWrappersParametersMaxCount, "stringArrayWrappersParametersMaxCount", 2, 5);
  if (config.stringArrayWrappersType !== undefined) normalizeStringArrayWrappersType(config.stringArrayWrappersType);
  validateOptionalBoolean("transformObjectKeys", config.transformObjectKeys);
  if (config.splitStringsChunkLength !== undefined) normalizeSplitStringsChunkLength(config.splitStringsChunkLength);
  if (config.stringSplitting !== undefined && !((typeof config.stringSplitting === "boolean") || (typeof config.stringSplitting === "number" && Number.isFinite(config.stringSplitting) && config.stringSplitting >= 0 && config.stringSplitting <= 1))) {
    throw new Error("stringSplitting must be a boolean or probability from 0 through 1; selector functions require manual migration review.");
  }
  if (config.domainLockRedirectUrl !== undefined) normalizeRuntimeRedirectUrl(config.domainLockRedirectUrl);
  if (config.seed !== undefined) normalizeSeedValue(config.seed);
  if (config.reservedStrings !== undefined) normalizeReservedStringPatterns(config.reservedStrings);
  if (config.forceTransformStrings !== undefined) normalizeReservedStringPatterns(config.forceTransformStrings, "forceTransformStrings");
  validateOptionalBoolean("controlFlowFlattening", config.controlFlowFlattening);
  validateOptionalBoolean("deadCodeInjection", config.deadCodeInjection);
  validateOptionalNonNegativeNumber("deadCodeInjectionThreshold", config.deadCodeInjectionThreshold);
  validateOptionalString("identifierNamesGenerator", config.identifierNamesGenerator);
  validateOptionalString("optionsPreset", config.optionsPreset);
  validateOptionalBoolean("renameGlobals", config.renameGlobals);
  validateOptionalBoolean("renameProperties", config.renameProperties);
  validateOptionalBoolean("stringArray", config.stringArray);
  if (config.stringArrayThreshold !== undefined) normalizeProbability(config.stringArrayThreshold, "stringArrayThreshold");
  validateOptionalString("target", config.target);
  validateOptionalBoolean("unicodeEscapeSequence", config.unicodeEscapeSequence);
  validateOptionalString("webPreset", config.webPreset);
  validateOptionalString("variableExclusion", config.variableExclusion);
  validateOptionalString("manifest", config.manifest);
  validateOptionalBoolean("copyAssets", config.copyAssets);
  validateOptionalBoolean("mixedServer", config.mixedServer);
  validateOptionalBoolean("parseHtml", config.parseHtml);
  validateOptionalBoolean("honorConditionalComments", config.honorConditionalComments);
  validateOptionalBoolean("protectMarkedComments", config.protectMarkedComments);
  validateOptionalBoolean("ignoreImports", config.ignoreImports);
  validateOptionalBoolean("keepHeaderComment", config.keepHeaderComment);
  validateOptionalBoolean("protectObjectDeclaration", config.protectObjectDeclaration);
  validateOptionalBoolean("moveNestedFunction", config.moveNestedFunction);
  validateOptionalBoolean("formattedOutput", config.formattedOutput);
  validateOptionalBoolean("keepIndent", config.keepIndent);
  validateOptionalBoolean("lineNumbers", config.lineNumbers);
  validateOptionalBoolean("lockDomainSubdomains", config.lockDomainSubdomains);
  validateOptionalString("lockDomainMessage", config.lockDomainMessage);
  validateOptionalBoolean("lockDate", config.lockDate);
  validateOptionalString("lockDateValue", config.lockDateValue);
  validateOptionalString("lockDateMessage", config.lockDateMessage);
  validateOptionalBoolean("removeSourceMaps", config.removeSourceMaps);
  validateOptionalPositiveNumber("maxOutputBytes", config.maxOutputBytes);
  validateOptionalPositiveNumber("maxGrowthRatio", config.maxGrowthRatio);
  validateCompatibilityReviewConfigFields(config);

  if (config.include !== undefined) validateStringArray("include", config.include);
  if (config.domainLock !== undefined && typeof config.domainLock !== "string" && !Array.isArray(config.domainLock)) {
    throw new Error("domainLock must be a string or array");
  }
  if (Array.isArray(config.domainLock)) validateStringArray("domainLock", config.domainLock);
  if (config.stringArrayEncoding !== undefined && typeof config.stringArrayEncoding !== "string" && !Array.isArray(config.stringArrayEncoding)) {
    throw new Error("stringArrayEncoding must be a string or array");
  }
  if (Array.isArray(config.stringArrayEncoding)) validateStringArray("stringArrayEncoding", config.stringArrayEncoding);
  if (config.extensions !== undefined) validateStringArray("extensions", config.extensions);
  if (config.markupExtensions !== undefined) validateStringArray("markupExtensions", config.markupExtensions);
  if (config.exclude !== undefined) validateStringArray("exclude", config.exclude);
  if (config.assetExclude !== undefined) validateStringArray("assetExclude", config.assetExclude);
  if (config.reservedNames !== undefined) validateStringArray("reservedNames", config.reservedNames);
  if (config.options !== undefined && (!config.options || typeof config.options !== "object" || Array.isArray(config.options))) {
    throw new Error("options must be an object");
  }
}

function getCompatibilityReviewFields(config = {}) {
  return [
    ...Object.keys(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTIONS).filter((key) => config[key] !== undefined),
    ...Object.keys(JS_CONFUSER_CONFIG_REVIEW_FIELDS).filter((key) => config[key] !== undefined)
  ];
}

function validateCompatibilityReviewConfigFields(config = {}) {
  for (const [key, type] of Object.entries(JAVASCRIPT_OBFUSCATOR_REVIEW_OPTION_TYPES)) {
    const value = config[key];
    if (value === undefined) continue;

    switch (type) {
      case "boolean":
        validateOptionalBoolean(key, value);
        break;
      case "nonNegativeNumber":
        validateOptionalNonNegativeNumber(key, value);
        break;
      case "string":
        validateOptionalString(key, value);
        break;
      case "stringArray":
        validateStringArray(key, value);
        break;
      case "stringOrNumber":
        if (typeof value !== "string" && typeof value !== "number") {
          throw new Error(`${key} must be a string or number`);
        }
        break;
      case "booleanOrNull":
        if (value !== null && typeof value !== "boolean") {
          throw new Error(`${key} must be a boolean or null`);
        }
        break;
      case "stringOrStringArray":
        if (typeof value !== "string" && !Array.isArray(value)) {
          throw new Error(`${key} must be a string or array`);
        }
        if (Array.isArray(value)) validateStringArray(key, value);
        break;
      case "objectOrNull":
        if (value !== null && (typeof value !== "object" || Array.isArray(value))) {
          throw new Error(`${key} must be an object or null`);
        }
        break;
      default:
        break;
    }
  }

  for (const [key, type] of Object.entries(JS_CONFUSER_CONFIG_REVIEW_FIELD_TYPES)) {
    const value = config[key];
    if (value === undefined) continue;

    switch (type) {
      case "booleanOrNonNegativeNumber":
        if (typeof value !== "boolean" && (!Number.isFinite(Number(value)) || Number(value) < 0)) {
          throw new Error(`${key} must be a boolean or non-negative number`);
        }
        break;
      case "string":
        validateOptionalString(key, value);
        break;
      default:
        break;
    }
  }
}

function findUnknownOptionNames(config, args = {}) {
  const known = new Set(OPTION_REFERENCE.map((option) => option.name));
  const names = new Set(Object.keys(config.options || {}));
  for (const entry of args.options || []) {
    const index = String(entry).indexOf("=");
    if (index > 0) names.add(String(entry).slice(0, index).trim());
  }
  return Array.from(names).filter((name) => name && !known.has(name) && name !== "reservedNames").sort();
}

function addCredentialStorageValidation(checks, config = {}, args = {}) {
  const inlineConfigFields = [];
  if (isInlineCredentialValue(config.apiKey)) inlineConfigFields.push("apiKey");
  if (isInlineCredentialValue(config.apiPassword)) inlineConfigFields.push("apiPassword");
  if (inlineConfigFields.length) {
    addValidationCheck(checks, "credentialStorage", "warning", `Config contains inline ${inlineConfigFields.join(" and ")} value(s). Prefer $JSO_API_KEY and $JSO_API_PASSWORD environment references so dashboard credentials are not committed.`);
    return;
  }

  const inlineCliFields = [];
  if (isInlineCredentialValue(args.apiKey)) inlineCliFields.push("--api-key");
  if (isInlineCredentialValue(args.apiPassword)) inlineCliFields.push("--api-password");
  if (inlineCliFields.length) {
    addValidationCheck(checks, "credentialStorage", "warning", `Command line contains ${inlineCliFields.join(" and ")} value(s). Prefer environment variables so dashboard credentials do not land in shell history or process logs.`);
    return;
  }

  addValidationCheck(checks, "credentialStorage", "ok", "Credentials are configured through environment references or runtime environment variables.");
}

function isInlineCredentialValue(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  return !!trimmed && !trimmed.startsWith("$");
}

function addValidationCheck(checks, name, level, message) {
  checks.push({
    name,
    level,
    ok: level !== "error",
    message
  });
}

function buildValidationReport(checks, config, strict = false, limitations = []) {
  const warnings = checks.filter((check) => check.level === "warning").length;
  return {
    ok: checks.every((check) => check.level !== "error") && !(strict && warnings > 0),
    strict: !!strict,
    warnings,
    endpoint: config ? config.endpoint : null,
    projectName: config ? config.projectName : null,
    preset: config ? config.preset : null,
    input: config ? config.input : null,
    output: config ? config.output : null,
    limitations,
    checks
  };
}

function writeValidationReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`jso-protector validate-config: ${report.ok ? "ok" : "failed"}${report.warnings ? ` (${report.warnings} warning(s))` : ""}\n`);
  for (const limitation of report.limitations || []) {
    process.stdout.write(`LIMITATION ${limitation.id}: ${limitation.message} Fields: ${limitation.fields.join(", ")}. ${limitation.recommendation}\n`);
  }
  for (const check of report.checks) {
    process.stdout.write(`${check.level.toUpperCase()} ${check.name}: ${check.message}\n`);
  }
}

function getRedactedConfig(config) {
  return {
    endpoint: config.endpoint,
    mode: config.mode || null,
    apiKey: config.apiKey ? "[set]" : "[missing]",
    apiPassword: config.apiPassword ? "[set]" : "[missing]",
    projectName: config.projectName,
    preset: config.preset,
    input: config.input,
    output: config.output,
    include: config.include.slice(),
    extensions: config.extensions.slice(),
    markupExtensions: config.markupExtensions.slice(),
    exclude: config.exclude.slice(),
    assetExclude: config.assetExclude.slice(),
    copyAssets: config.copyAssets,
    mixedServer: config.mixedServer,
    parseHtml: config.parseHtml,
    honorConditionalComments: config.honorConditionalComments,
    protectMarkedComments: config.protectMarkedComments,
    ignoreImports: config.ignoreImports,
    removeSourceMaps: config.removeSourceMaps,
    manifest: config.manifest,
    maxOutputBytes: config.maxOutputBytes,
    maxGrowthRatio: config.maxGrowthRatio,
    options: { ...config.options }
  };
}

function writeResolvedConfig(config, json) {
  const redacted = getRedactedConfig(config);
  if (json) {
    process.stdout.write(`${JSON.stringify(redacted, null, 2)}\n`);
    return;
  }

  process.stdout.write("Resolved jso-protector config:\n");
  process.stdout.write(`endpoint: ${redacted.endpoint}\n`);
  process.stdout.write(`mode: ${redacted.mode || "(default)"}\n`);
  process.stdout.write(`apiKey: ${redacted.apiKey}\n`);
  process.stdout.write(`apiPassword: ${redacted.apiPassword}\n`);
  process.stdout.write(`projectName: ${redacted.projectName}\n`);
  process.stdout.write(`preset: ${redacted.preset}\n`);
  process.stdout.write(`input: ${redacted.input}\n`);
  process.stdout.write(`output: ${redacted.output}\n`);
  process.stdout.write(`include: ${redacted.include.join(", ")}\n`);
  process.stdout.write(`extensions: ${redacted.extensions.join(", ")}\n`);
  process.stdout.write(`markupExtensions: ${redacted.markupExtensions.join(", ")}\n`);
  process.stdout.write(`exclude: ${redacted.exclude.join(", ")}\n`);
  process.stdout.write(`assetExclude: ${redacted.assetExclude.join(", ")}\n`);
  process.stdout.write(`copyAssets: ${redacted.copyAssets}\n`);
  process.stdout.write(`mixedServer: ${redacted.mixedServer}\n`);
  process.stdout.write(`parseHtml: ${redacted.parseHtml}\n`);
  process.stdout.write(`honorConditionalComments: ${redacted.honorConditionalComments}\n`);
  process.stdout.write(`protectMarkedComments: ${redacted.protectMarkedComments}\n`);
  process.stdout.write(`ignoreImports: ${redacted.ignoreImports}\n`);
  process.stdout.write(`removeSourceMaps: ${redacted.removeSourceMaps}\n`);
  process.stdout.write(`manifest: ${redacted.manifest || ""}\n`);
  process.stdout.write(`maxOutputBytes: ${redacted.maxOutputBytes || ""}\n`);
  process.stdout.write(`maxGrowthRatio: ${redacted.maxGrowthRatio || ""}\n`);
  process.stdout.write(`options: ${Object.keys(redacted.options).join(", ")}\n`);
}

function listPresets() {
  return Object.entries(PRESET_OPTIONS).map(([name, options]) => ({
    name,
    options: { ...options }
  }));
}

function listOptions() {
  return OPTION_REFERENCE.map((option) => ({ ...option }));
}

function writePresetList(json) {
  const presets = listPresets();
  if (json) {
    process.stdout.write(`${JSON.stringify({ presets }, null, 2)}\n`);
    return;
  }

  process.stdout.write("Available presets:\n");
  for (const preset of presets) {
    process.stdout.write(`- ${preset.name}: ${Object.keys(preset.options).join(", ")}\n`);
  }
}

function writeOptionList(json) {
  const options = listOptions();
  if (json) {
    process.stdout.write(`${JSON.stringify({ options }, null, 2)}\n`);
    return;
  }

  process.stdout.write("Common API options:\n");
  for (const option of options) {
    const values = option.values ? ` (${option.values.join("|")})` : "";
    process.stdout.write(`- ${option.name}: ${option.type}${values} - ${option.description}\n`);
  }
}

function getPackageMetadata() {
  return {
    name: packageJson.name,
    version: packageJson.version,
    description: packageJson.description,
    homepage: packageJson.homepage,
    endpoint: DEFAULT_ENDPOINT
  };
}

function writeVersion(json) {
  const metadata = getPackageMetadata();
  if (json) {
    process.stdout.write(`${JSON.stringify(metadata, null, 2)}\n`);
    return;
  }

  process.stdout.write(`${metadata.name} ${metadata.version}\n`);
}

function writeLocalOnlyGuidance(json) {
  const guidance = {
    ok: false,
    sourceLeavesMachine: false,
    npmPublished: false,
    packageDistribution: "local-only",
    message: "This package is intentionally local-only as a distribution artifact and is not published to npm. Install it from a workspace path, a file: dependency, or an internal npm pack tarball. The npm CLI and desktop app protect JavaScript through the hosted service. Use --dry-run, --validate-config, --release-check, --competitor-gap-report, and --doctor for local preflight only. If project policy requires source code to remain local during protection, current JavaScript Obfuscator protection workflows do not meet that requirement.",
    localInstallCommands: [
      "npm install --save-dev ./packages/jso-protector",
      "npm install --save-dev ../packages/jso-protector",
      "npm install --save-dev path/to/jso-protector-0.2.0.tgz"
    ],
    localPackageJsonDependency: {
      devDependencies: {
        "jso-protector": "file:../packages/jso-protector"
      }
    },
    internalTarballCommands: [
      "npm pack --json",
      "npm install --save-dev path/to/jso-protector-0.2.0.tgz"
    ],
    localPreflightCommands: [
      "jso-protector --config jso.config.json --release-check --json",
      "jso-protector --config jso.config.json --competitor-gap-report --json",
      "jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md",
      "jso-protector --runtime-incident-evidence reports/runtime-incidents.json --runtime-incident-evidence-output reports/runtime-incident-evidence.md",
      "jso-protector --config jso.config.json --dry-run --json",
      "jso-protector --config jso.config.json --print-config --json"
    ]
  };
  if (json) {
    process.stdout.write(`${JSON.stringify(guidance, null, 2)}\n`);
    return;
  }
  process.stdout.write(`${guidance.message}\n`);
  process.stdout.write("Local install commands:\n");
  for (const command of guidance.localInstallCommands) {
    process.stdout.write(`- ${command}\n`);
  }
  process.stdout.write("Local preflight commands:\n");
  for (const command of guidance.localPreflightCommands) {
    process.stdout.write(`- ${command}\n`);
  }
}

function readManifest(manifestPath) {
  const resolvedPath = path.resolve(manifestPath);
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
  } catch (error) {
    throw new Error(`Failed to read manifest ${resolvedPath}: ${error.message}`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Manifest ${resolvedPath} must be a JSON object.`);
  }
  if (parsed.format !== "jso-protector-manifest") {
    throw new Error(`Manifest ${resolvedPath} is not a jso-protector manifest.`);
  }
  if (!Array.isArray(parsed.files) || !Array.isArray(parsed.assets)) {
    throw new Error(`Manifest ${resolvedPath} must include files and assets arrays.`);
  }

  return {
    manifestPath: resolvedPath,
    manifest: parsed
  };
}

function verifyManifestOutputs(manifestInput, options = {}) {
  const manifestPath = typeof manifestInput === "string" ? path.resolve(manifestInput) : path.resolve(manifestInput.manifestPath);
  const manifest = typeof manifestInput === "string" ? readManifest(manifestPath).manifest : manifestInput.manifest;
  const verifyRoot = options.verifyRoot ? path.resolve(options.verifyRoot) : null;
  const auditSourceMaps = options.auditSourceMaps === true;
  const files = Array.isArray(manifest.files) ? manifest.files : [];
  const assets = Array.isArray(manifest.assets) ? manifest.assets : [];

  const verifyEntry = (kind, entry) => {
    const entryPath = verifyRoot ? path.resolve(verifyRoot, normalizeName(entry.fileName)) : path.resolve(entry.outputPath);
    const expectedBytes = kind === "file" ? entry.outputBytes : entry.bytes;
    const expectedSha256 = kind === "file" ? entry.outputSha256 : entry.sha256;

    if (!fs.existsSync(entryPath)) {
      return {
        kind,
        fileName: entry.fileName,
        path: entryPath,
        ok: false,
        reason: "missing",
        expectedBytes,
        expectedSha256,
        actualBytes: null,
        actualSha256: null
      };
    }

    const actual = fileDigest(entryPath);
    const matchesBytes = actual.bytes === expectedBytes;
    const matchesSha256 = actual.sha256 === expectedSha256;
    return {
      kind,
      fileName: entry.fileName,
      path: entryPath,
      ok: matchesBytes && matchesSha256,
      reason: matchesBytes && matchesSha256 ? "ok" : (!matchesBytes ? "size-mismatch" : "sha256-mismatch"),
      expectedBytes,
      expectedSha256,
      actualBytes: actual.bytes,
      actualSha256: actual.sha256
    };
  };

  const fileResults = files.map((entry) => verifyEntry("file", entry));
  const assetResults = assets.map((entry) => verifyEntry("asset", entry));
  const entries = [...fileResults, ...assetResults];
  const sourceMapLeaks = auditSourceMaps ? auditManifestSourceMaps(entries) : [];
  const summary = {
    total: entries.length,
    ok: entries.filter((entry) => entry.ok).length,
    missing: entries.filter((entry) => entry.reason === "missing").length,
    mismatched: entries.filter((entry) => !entry.ok && entry.reason !== "missing").length,
    sourceMapLeaks: sourceMapLeaks.length
  };

  return {
    format: "jso-protector-manifest-check",
    version: 1,
    ok: summary.missing === 0 && summary.mismatched === 0 && summary.sourceMapLeaks === 0,
    manifestPath,
    verifyRoot,
    auditSourceMaps,
    generatedAt: new Date().toISOString(),
    projectName: manifest.projectName || null,
    preset: manifest.preset || null,
    summary,
    files: fileResults,
    assets: assetResults,
    sourceMapLeaks
  };
}

function auditManifestSourceMaps(entries) {
  const leaks = [];
  for (const entry of entries) {
    if (!entry.ok || !entry.path) continue;
    const normalizedName = normalizeName(entry.fileName).toLowerCase();
    if (normalizedName.endsWith(".map")) {
      leaks.push({
        kind: entry.kind,
        fileName: entry.fileName,
        path: entry.path,
        reason: "map-file"
      });
      continue;
    }
    if (entry.kind !== "file" || !/\.(?:c|m)?jsx?$/i.test(normalizedName)) continue;
    const code = fs.readFileSync(entry.path, "utf8");
    SOURCE_MAP_COMMENT_LINE_PATTERN.lastIndex = 0;
    SOURCE_MAP_COMMENT_BLOCK_PATTERN.lastIndex = 0;
    if (SOURCE_MAP_COMMENT_LINE_PATTERN.test(code) || SOURCE_MAP_COMMENT_BLOCK_PATTERN.test(code)) {
      leaks.push({
        kind: entry.kind,
        fileName: entry.fileName,
        path: entry.path,
        reason: "sourceMappingURL"
      });
    }
  }
  return leaks;
}

function writeManifestVerificationReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`jso-protector verify-manifest: ${report.ok ? "ok" : "failed"}\n`);
  process.stdout.write(`manifest: ${report.manifestPath}\n`);
  if (report.verifyRoot) process.stdout.write(`verify root: ${report.verifyRoot}\n`);
  if (report.auditSourceMaps) process.stdout.write("source map audit: enabled\n");
  process.stdout.write(`entries: ${report.summary.ok}/${report.summary.total} ok`);
  if (report.summary.missing || report.summary.mismatched) {
    process.stdout.write(` (${report.summary.missing} missing, ${report.summary.mismatched} mismatched)\n`);
  } else {
    process.stdout.write("\n");
  }
  if (report.auditSourceMaps) {
    process.stdout.write(`source map leaks: ${report.summary.sourceMapLeaks}\n`);
  }

  for (const entry of [...report.files, ...report.assets]) {
    const label = entry.kind === "file" ? "file" : "asset";
    if (entry.ok) {
      process.stdout.write(`OK ${label} ${entry.fileName}: ${entry.path}\n`);
      continue;
    }
    process.stdout.write(`FAIL ${label} ${entry.fileName}: ${entry.reason} at ${entry.path}\n`);
  }
  for (const leak of report.sourceMapLeaks || []) {
    process.stdout.write(`FAIL source-map ${leak.fileName}: ${leak.reason} at ${leak.path}\n`);
  }
}

function buildSourceMapEvidenceReport(manifestPath, options = {}) {
  const verification = verifyManifestOutputs(manifestPath, {
    verifyRoot: options.verifyRoot,
    auditSourceMaps: true
  });
  const entries = [...verification.files, ...verification.assets];
  const sourceMapLeaks = (verification.sourceMapLeaks || []).map((leak) => ({
    kind: leak.kind,
    fileName: leak.fileName,
    reason: leak.reason
  }));
  const entryFailures = entries
    .filter((entry) => !entry.ok)
    .map((entry) => ({
      kind: entry.kind,
      fileName: entry.fileName,
      reason: entry.reason,
      expectedBytes: entry.expectedBytes,
      actualBytes: entry.actualBytes
    }));
  const mapFileLeaks = sourceMapLeaks.filter((leak) => leak.reason === "map-file").length;
  const sourceMappingUrlComments = sourceMapLeaks.filter((leak) => leak.reason === "sourceMappingURL").length;
  const hashOk = verification.summary.missing === 0 && verification.summary.mismatched === 0;
  const noMapFiles = mapFileLeaks === 0;
  const noSourceMappingUrlComments = sourceMappingUrlComments === 0;
  const checks = [
    {
      name: "manifest-hash-verification",
      required: true,
      ok: hashOk,
      message: hashOk
        ? "Every manifest entry matched its recorded bytes and SHA-256."
        : `${verification.summary.missing} missing and ${verification.summary.mismatched} mismatched manifest entr${verification.summary.missing + verification.summary.mismatched === 1 ? "y" : "ies"} need review.`
    },
    {
      name: "source-map-files",
      required: true,
      ok: noMapFiles,
      message: noMapFiles
        ? "No .map files are present in the protected artifact manifest."
        : `${mapFileLeaks} .map file${mapFileLeaks === 1 ? "" : "s"} found in protected artifacts.`
    },
    {
      name: "source-mapping-url-comments",
      required: true,
      ok: noSourceMappingUrlComments,
      message: noSourceMappingUrlComments
        ? "No sourceMappingURL comments remain in protected JavaScript files."
        : `${sourceMappingUrlComments} protected JavaScript file${sourceMappingUrlComments === 1 ? "" : "s"} still reference source maps.`
    }
  ];
  const ok = checks.every((check) => !check.required || check.ok);
  const reviewDecision = ok ? {
    decision: "ready",
    label: "Ready",
    ok: true,
    manualReviewRequired: false,
    reason: "The manifest verified and no source-map artifacts or sourceMappingURL comments were found.",
    nextAction: "Attach this source-map evidence report beside the signed manifest and protected artifact."
  } : {
    decision: "blocked",
    label: "Blocked",
    ok: false,
    manualReviewRequired: true,
    reason: "Protected artifact source-map policy evidence is incomplete or leaking.",
    nextAction: "Remove source maps from the protected artifact, strip sourceMappingURL comments, regenerate the manifest, and rerun this report."
  };
  const summary = {
    manifestEntries: verification.summary.total,
    verifiedEntries: verification.summary.ok,
    missingEntries: verification.summary.missing,
    mismatchedEntries: verification.summary.mismatched,
    sourceMapLeaks: sourceMapLeaks.length,
    mapFiles: mapFileLeaks,
    sourceMappingUrlComments
  };
  const sourceMapPolicy = {
    protectedReleaseDefault: "Source maps are excluded or removed from protected release artifacts by default.",
    reviewerBoundary: "This report is source-free: it lists artifact names, counts, and reasons, but not source code or source-map contents.",
    secureExceptionPath: "If a team intentionally keeps maps, store them outside the public protected artifact and restrict access through the release owner's secure debugging process."
  };
  const sourceBoundary = {
    includes: [
      "manifest/project/preset names",
      "source-map leak counts",
      "artifact names and source-map leak reasons",
      "manifest verification counts and failure reasons",
      "source-map policy text",
      "review decision and recommendations"
    ],
    doNotInclude: [
      "source code",
      "protected output",
      "source-map contents",
      "raw .map files",
      "original source paths from source maps",
      "credentials",
      "customer data",
      "secrets"
    ]
  };

  return {
    format: "jso-protector-source-map-evidence",
    version: 1,
    ok,
    generatedAt: new Date().toISOString(),
    generatedBy: "jso-protector --source-map-evidence",
    manifestPath: verification.manifestPath,
    verifyRoot: verification.verifyRoot,
    projectName: verification.projectName,
    preset: verification.preset,
    summary,
    sourceMapPolicy,
    sourceBoundary,
    reviewDecision,
    checks,
    sourceMapLeaks,
    entryFailures,
    reviewAssistant: buildSourceMapReviewAssistant(summary, reviewDecision, checks, sourceMapLeaks, entryFailures, sourceBoundary),
    recommendations: ok ? [
      "Keep --verify-manifest --audit-source-maps or --source-map-evidence in release CI before artifact publication.",
      "Publish protected JavaScript and the signed manifest; store source maps separately only when a secure debugging workflow requires them."
    ] : [
      "Run protection with removeSourceMaps enabled or remove copied .map files before publishing.",
      "Strip sourceMappingURL comments from protected JavaScript after any downstream bundler step.",
      "Regenerate the manifest after removing leaks so the reviewer packet matches the final artifact."
    ]
  };
}

function buildSourceMapReviewAssistant(summary, reviewDecision, checks, sourceMapLeaks, entryFailures, sourceBoundary) {
  const questions = [];
  const failedChecks = (checks || []).filter((check) => check && check.required && !check.ok);
  const hasMapFiles = (sourceMapLeaks || []).some((leak) => leak && leak.reason === "map-file");
  const hasMappingComments = (sourceMapLeaks || []).some((leak) => leak && leak.reason === "sourceMappingURL");

  if (sourceMapLeaks && sourceMapLeaks.length > 0) {
    questions.push({
      topic: "Source-map leak cleanup",
      prompt: "Review the artifact names and leak reasons, then confirm whether .map files, sourceMappingURL comments, or both are still present in the protected release.",
      ownerAction: "Remove leaked maps, strip stale sourceMappingURL comments after downstream bundling, regenerate the manifest, and rerun source-map evidence."
    });
  }

  if (entryFailures && entryFailures.length > 0) {
    questions.push({
      topic: "Manifest verification",
      prompt: "Review the manifest failure artifact names and reasons, then decide whether the protected artifact was moved, rebuilt, or changed after the manifest was generated.",
      ownerAction: "Rebuild or re-verify the final protected artifact before sharing this evidence with a customer or auditor."
    });
  }

  if (failedChecks.length > 0) {
    questions.push({
      topic: "Release block",
      prompt: "Decide whether the failed required checks block publication, and identify the exact release step that must rerun.",
      ownerAction: "Keep the protected artifact out of public release until manifest verification and source-map leak checks pass together."
    });
  }

  questions.push({
    topic: "Secure debugging exception",
    prompt: "If the team intentionally keeps source maps for debugging, confirm they are stored outside public protected artifacts and restricted through the release owner's debugging process.",
    ownerAction: "Document the secure map-storage location, access owner, retention period, and removal plan without pasting map contents into the review."
  });

  if (hasMapFiles && hasMappingComments) {
    questions.push({
      topic: "Bundler cleanup order",
      prompt: "Confirm whether a downstream bundler or copy step reintroduced both .map files and sourceMappingURL comments after protection.",
      ownerAction: "Move source-map removal after the last bundler/copy step or enforce --audit-source-maps at the artifact publication gate."
    });
  } else if (hasMapFiles) {
    questions.push({
      topic: "Copied map files",
      prompt: "Confirm which asset-copy rule allowed .map files into the protected artifact.",
      ownerAction: "Update assetExclude or the bundler plugin source-map removal setting before regenerating the manifest."
    });
  } else if (hasMappingComments) {
    questions.push({
      topic: "Stale mapping comments",
      prompt: "Confirm which JavaScript transform or minifier added sourceMappingURL comments after protection.",
      ownerAction: "Strip sourceMappingURL comments at the final artifact step and rerun source-map evidence."
    });
  }

  if (reviewDecision && reviewDecision.decision === "ready") {
    questions.push({
      topic: "Clean source-map handoff",
      prompt: "Confirm the manifest verification count, leak count, source-map policy, and secure-debugging boundary are enough for reviewer handoff.",
      ownerAction: "Attach this source-map evidence packet beside the signed manifest and protected artifact."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "required check names, status, and messages",
      "source-map summary counts",
      "secure debugging exception policy"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "sourceMappingURL target contents",
      "raw source-map sources arrays",
      "local absolute source paths",
      "source snippets copied from maps"
    ])));

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to review source-map release evidence without sending source code, protected output, source-map contents, original source paths, provider keys, customer data, or secrets.",
    reviewerPrompt: "Review this JSO source-map evidence packet. Use only manifest/project/preset names, source-map summary counts, artifact names, leak reasons, manifest failure reasons, source-map policy, required check results, review decision, and recommendations. Produce owner actions without requesting raw source maps, original source paths, source code, or protected output.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function renderSourceMapEvidenceText(report) {
  const out = [];
  out.push(`# JSO Source Map Evidence`);
  out.push("");
  out.push(`Status: ${report.ok ? "PASS" : "NEEDS REVIEW"}`);
  out.push(`Review decision: ${report.reviewDecision.label}`);
  out.push(`Manifest: ${report.manifestPath}`);
  if (report.verifyRoot) out.push(`Verify root: ${report.verifyRoot}`);
  if (report.projectName) out.push(`Project: ${report.projectName}`);
  if (report.preset) out.push(`Preset: ${report.preset}`);
  out.push("");
  out.push("## Summary");
  out.push(`- Manifest entries: ${report.summary.verifiedEntries}/${report.summary.manifestEntries} verified`);
  out.push(`- Missing entries: ${report.summary.missingEntries}`);
  out.push(`- Mismatched entries: ${report.summary.mismatchedEntries}`);
  out.push(`- Source map leaks: ${report.summary.sourceMapLeaks}`);
  out.push(`- .map files: ${report.summary.mapFiles}`);
  out.push(`- sourceMappingURL comments: ${report.summary.sourceMappingUrlComments}`);
  out.push("");
  out.push("## Checks");
  for (const check of report.checks) {
    out.push(`- ${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.message}`);
  }
  out.push("");
  out.push("## Source-Free Policy");
  out.push(`- ${report.sourceMapPolicy.protectedReleaseDefault}`);
  out.push(`- ${report.sourceMapPolicy.reviewerBoundary}`);
  out.push(`- ${report.sourceMapPolicy.secureExceptionPath}`);
  renderSourceMapReviewAssistant(out, report.reviewAssistant);
  if (report.sourceMapLeaks.length) {
    out.push("");
    out.push("## Source Map Findings");
    for (const leak of report.sourceMapLeaks) {
      out.push(`- ${leak.fileName}: ${leak.reason}`);
    }
  }
  if (report.entryFailures.length) {
    out.push("");
    out.push("## Manifest Findings");
    for (const failure of report.entryFailures) {
      out.push(`- ${failure.fileName}: ${failure.reason}`);
    }
  }
  out.push("");
  out.push("## Recommendations");
  for (const item of report.recommendations) {
    out.push(`- ${item}`);
  }
  return out.join("\n");
}

function renderSourceMapReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("");
  out.push("## Source Map Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function writeSourceMapEvidenceReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderSourceMapEvidenceText(report)}\n`;
  if (!args.sourceMapEvidenceOutput) {
    process.stdout.write(text);
    return;
  }

  const resolvedPath = path.resolve(args.sourceMapEvidenceOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`Source map evidence report written: ${resolvedPath}\n`);
}

function buildDeploymentHygieneEvidenceReport(reportPath, options = {}) {
  const resolvedPath = path.resolve(reportPath);
  let sourceBuffer;
  let manifest;
  try {
    sourceBuffer = fs.readFileSync(resolvedPath);
    manifest = JSON.parse(sourceBuffer.toString("utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    throw new Error(`Failed to read deployment hygiene evidence ${resolvedPath}: ${error.message}`);
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error(`Deployment hygiene evidence ${resolvedPath} must be a JSON object.`);
  }

  const archives = normalizeDeploymentHygieneArchives(manifest.archives);
  const operatorChecklist = normalizeDeploymentHygieneChecklist(manifest.operatorChecklist);
  const exclusionPolicy = normalizeDeploymentHygienePolicy(manifest.policy);
  const summary = summarizeDeploymentHygieneArchives(archives, manifest.ok);
  const checks = buildDeploymentHygieneChecks(manifest, archives, summary, operatorChecklist);
  const ok = checks.every((check) => !check.required || check.ok);
  const reviewDecision = ok ? {
    decision: "ready",
    label: "Ready",
    ok: true,
    manualReviewRequired: false,
    reason: "The archive hygiene report is clean: no blocked deployment files were found and required updated entries are present.",
    nextAction: "Attach this source-free deployment hygiene packet beside the updated-files archive and keep Web.config or host-specific transforms out of reviewer handoff."
  } : {
    decision: "blocked",
    label: "Blocked",
    ok: false,
    manualReviewRequired: true,
    reason: "Archive hygiene evidence is incomplete or blocked deployment files were detected.",
    nextAction: "Remove blocked entries, restore required files, rebuild the updated-files archives with -ReportPath, and rotate credentials if any secret-bearing config was shared."
  };
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "archive names",
      "entry counts",
      "archive byte sizes",
      "missing required entry names",
      "blocked entry names",
      "blocked category booleans",
      "exclusion policy categories",
      "operator checklist text",
      "rotation-trigger guidance",
      "hygiene report SHA-256"
    ],
    doNotInclude: [
      "Web.config contents",
      "raw secrets",
      "provider keys",
      "webhook signing secrets",
      "database connection strings",
      "host-specific deployment transforms",
      "customer data"
    ]
  };

  return {
    format: "jso-protector-deployment-hygiene-evidence",
    version: 1,
    ok,
    generatedAt: options.generatedAt || new Date().toISOString(),
    generatedBy: "jso-protector --deployment-hygiene-evidence",
    source: {
      file: path.basename(resolvedPath),
      format: stringOrNull(manifest.schema) || "unknown",
      sha256: sha256(sourceBuffer),
      generatedUtc: stringOrNull(manifest.generatedUtc),
      cutoffUtc: stringOrNull(manifest.cutoffUtc),
      websiteRelativePath: stringOrNull(manifest.websiteRelativePath)
    },
    summary,
    archives,
    exclusionPolicy,
    operatorChecklist,
    reviewDecision,
    checks,
    sourceBoundary,
    reviewAssistant: buildDeploymentHygieneReviewAssistant(summary, reviewDecision, sourceBoundary),
    recommendations: buildDeploymentHygieneRecommendations(summary, ok)
  };
}

function normalizeDeploymentHygieneArchives(value) {
  if (!Array.isArray(value)) return [];
  return value.map((archive) => {
    const contains = archive && archive.contains && typeof archive.contains === "object" ? archive.contains : {};
    const missingRequiredEntries = normalizeStringArray(archive && archive.missingRequiredEntries);
    const blockedEntries = normalizeStringArray(archive && archive.blockedEntries);
    return {
      zip: basenameFromAnyPath(archive && archive.zip),
      entries: integerOrZero(archive && archive.entries),
      size: integerOrZero(archive && archive.size),
      missingRequiredEntries,
      blockedEntries,
      contains: {
        webConfig: contains.webConfig === true,
        generatedTemp: contains.generatedTemp === true,
        nodeModules: contains.nodeModules === true,
        buildOutput: contains.buildOutput === true,
        downloadBinaries: contains.downloadBinaries === true
      }
    };
  });
}

function normalizeDeploymentHygieneChecklist(value) {
  const checklist = value && typeof value === "object" ? value : {};
  return {
    sourceFree: checklist.sourceFree === true,
    beforeSharing: normalizeStringArray(checklist.beforeSharing),
    rotationTriggers: normalizeStringArray(checklist.rotationTriggers),
    supportBoundary: stringOrNull(checklist.supportBoundary) || "This packet is source-free and must not include secrets, customer data, or host-specific deployment config."
  };
}

function normalizeDeploymentHygienePolicy(value) {
  const policy = value && typeof value === "object" ? value : {};
  return {
    excludedFileNames: normalizeStringArray(policy.excludedFileNames),
    excludedExtensions: normalizeStringArray(policy.excludedExtensions),
    excludedDirectories: normalizeStringArray(policy.excludedDirectories),
    excludedBuildOutputs: normalizeStringArray(policy.excludedBuildOutputs),
    excludedDownloadBinaries: normalizeStringArray(policy.excludedDownloadBinaries),
    excludedEvidenceFiles: normalizeStringArray(policy.excludedEvidenceFiles),
    failingSignals: normalizeStringArray(policy.failingSignals)
  };
}

function summarizeDeploymentHygieneArchives(archives, reportOk) {
  const risky = {
    webConfig: archives.some((archive) => archive.contains.webConfig),
    generatedTemp: archives.some((archive) => archive.contains.generatedTemp),
    nodeModules: archives.some((archive) => archive.contains.nodeModules),
    buildOutput: archives.some((archive) => archive.contains.buildOutput),
    downloadBinaries: archives.some((archive) => archive.contains.downloadBinaries)
  };
  const missingRequiredEntries = archives.reduce((sum, archive) => sum + archive.missingRequiredEntries.length, 0);
  const blockedEntries = archives.reduce((sum, archive) => sum + archive.blockedEntries.length, 0);
  return {
    reportOk: reportOk === true,
    archives: archives.length,
    totalEntries: archives.reduce((sum, archive) => sum + archive.entries, 0),
    totalSizeBytes: archives.reduce((sum, archive) => sum + archive.size, 0),
    missingRequiredEntries,
    blockedEntries,
    containsWebConfig: risky.webConfig,
    containsGeneratedTemp: risky.generatedTemp,
    containsNodeModules: risky.nodeModules,
    containsBuildOutput: risky.buildOutput,
    containsDownloadBinaries: risky.downloadBinaries
  };
}

function buildDeploymentHygieneChecks(manifest, archives, summary, operatorChecklist) {
  const schemaOk = manifest.schema === "jso.archive-hygiene.v1";
  const cleanCategories = !summary.containsWebConfig &&
    !summary.containsGeneratedTemp &&
    !summary.containsNodeModules &&
    !summary.containsBuildOutput &&
    !summary.containsDownloadBinaries;
  return [
    {
      name: "archive-hygiene-schema",
      required: true,
      ok: schemaOk,
      message: schemaOk
        ? "Archive hygiene JSON uses the expected jso.archive-hygiene.v1 schema."
        : "Archive hygiene JSON does not use the expected jso.archive-hygiene.v1 schema."
    },
    {
      name: "archive-count",
      required: true,
      ok: archives.length > 0,
      message: archives.length > 0
        ? `${archives.length} archive hygiene entr${archives.length === 1 ? "y" : "ies"} were summarized.`
        : "No archive entries were found in the hygiene report."
    },
    {
      name: "builder-ok-flag",
      required: true,
      ok: summary.reportOk,
      message: summary.reportOk
        ? "The archive builder marked the hygiene report clean."
        : "The archive builder did not mark the hygiene report clean."
    },
    {
      name: "missing-required-entries",
      required: true,
      ok: summary.missingRequiredEntries === 0,
      message: summary.missingRequiredEntries === 0
        ? "No required updated archive entries are missing."
        : `${summary.missingRequiredEntries} required archive entr${summary.missingRequiredEntries === 1 ? "y is" : "ies are"} missing.`
    },
    {
      name: "blocked-entries",
      required: true,
      ok: summary.blockedEntries === 0,
      message: summary.blockedEntries === 0
        ? "No blocked deployment entries were found in the archives."
        : `${summary.blockedEntries} blocked deployment entr${summary.blockedEntries === 1 ? "y was" : "ies were"} found.`
    },
    {
      name: "blocked-category-booleans",
      required: true,
      ok: cleanCategories,
      message: cleanCategories
        ? "Web.config, generated temp, dependencies, build outputs, and timestamp-only download binaries are absent."
        : "One or more blocked deployment categories is present in the archive evidence."
    },
    {
      name: "operator-checklist",
      required: true,
      ok: operatorChecklist.sourceFree === true &&
        operatorChecklist.beforeSharing.length > 0 &&
        operatorChecklist.rotationTriggers.length > 0,
      message: operatorChecklist.sourceFree === true
        ? "Source-free operator checklist and rotation triggers are present."
        : "Operator checklist must be marked source-free and include before-sharing plus rotation-trigger guidance."
    }
  ];
}

function buildDeploymentHygieneReviewAssistant(summary, reviewDecision, sourceBoundary) {
  const questions = [];
  if (summary.blockedEntries > 0 || summary.containsWebConfig || summary.containsGeneratedTemp || summary.containsNodeModules || summary.containsBuildOutput || summary.containsDownloadBinaries) {
    questions.push({
      topic: "Blocked deployment file",
      prompt: "Review the blocked archive entries and category booleans, then decide which files must be removed before sharing the updated-files archive.",
      ownerAction: "Rebuild the archive after removing blocked files and keep the failed hygiene packet with the internal remediation ticket."
    });
  }
  if (summary.missingRequiredEntries > 0) {
    questions.push({
      topic: "Missing required update",
      prompt: "Confirm why required updated files are absent from the archive and whether the release handoff would be incomplete without them.",
      ownerAction: "Restore the required entries or update the archive-builder required-entry list before reviewer handoff."
    });
  }
  if (summary.containsWebConfig) {
    questions.push({
      topic: "Credential rotation",
      prompt: "Assume Web.config or another secret-bearing deployment file may have been exposed and identify which credentials need rotation.",
      ownerAction: "Rotate affected admin, provider, webhook, database, and host-specific credentials before external sharing."
    });
  } else {
    questions.push({
      topic: "Config exclusion",
      prompt: "Confirm Web.config and host-specific deployment transforms stayed outside the archive and no one added secrets to logs, tickets, or support transcripts.",
      ownerAction: "Record the clean config-exclusion decision beside the archive hygiene evidence."
    });
  }
  if (reviewDecision && reviewDecision.ok === true) {
    questions.push({
      topic: "Clean archive handoff",
      prompt: "Confirm the archive names, sizes, required-entry status, blocked-entry status, and source-free checklist are enough for the reviewer.",
      ownerAction: "Attach the generated deployment hygiene packet beside the updated-files zip."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "review decision",
      "recommendations",
      "operator checklist",
      "rotation-trigger guidance"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw configuration files",
      "secret values pasted from deployment settings"
    ])));

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to validate archive/deployment hygiene without sending Web.config, raw secrets, provider keys, database strings, deployment transforms, customer data, or source code.",
    reviewerPrompt: "Review this JSO deployment hygiene evidence packet. Use only archive names, counts, sizes, blocked-category booleans, missing/blocked entry names, checklist text, rotation-trigger guidance, and the hygiene report SHA-256. Produce owner actions for archive sharing and credential-rotation decisions without requesting raw deployment config.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function buildDeploymentHygieneRecommendations(summary, ok) {
  if (ok) {
    return [
      "Attach this deployment hygiene packet beside the updated-files archive before reviewer handoff.",
      "Keep Web.config, host-specific transforms, provider keys, webhook secrets, database strings, and customer data out of archives and support transcripts.",
      "Regenerate the hygiene JSON with tools/Build-UpdatedArchives.ps1 -ReportPath whenever the archive is rebuilt."
    ];
  }
  const recommendations = [
    "Rebuild the updated-files archive after removing blocked entries and restoring required updated files.",
    "Rerun tools/Build-UpdatedArchives.ps1 with -ReportPath, then regenerate this deployment hygiene evidence packet."
  ];
  if (summary.containsWebConfig) {
    recommendations.push("Rotate credentials if Web.config was included in a zip, support ticket, email, chat, source snapshot, or reviewer handoff.");
  }
  recommendations.push("Do not share failed archive contents externally; share only this source-free failure packet with the internal remediation owner.");
  return recommendations;
}

function renderDeploymentHygieneEvidenceText(report) {
  const out = [];
  out.push("# Deployment Hygiene Evidence");
  out.push("");
  out.push(`Generated: ${report.generatedAt}`);
  out.push(`Status: ${report.ok ? "PASS" : "NEEDS REVIEW"}`);
  out.push(`Review decision: ${report.reviewDecision.label}`);
  out.push("");
  out.push("## Source");
  out.push("");
  out.push("| Field | Value |");
  out.push("|---|---|");
  out.push(`| Evidence file | \`${markdownInline(report.source.file)}\` |`);
  out.push(`| Evidence sha256 | \`${report.source.sha256}\` |`);
  out.push(`| Evidence format | ${markdownCell(report.source.format)} |`);
  out.push(`| Generated UTC | ${markdownCell(report.source.generatedUtc || "not supplied")} |`);
  out.push(`| Cutoff UTC | ${markdownCell(report.source.cutoffUtc || "not supplied")} |`);
  out.push(`| Website scope | ${markdownCell(report.source.websiteRelativePath || "not supplied")} |`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push(`| Archives | ${report.summary.archives} |`);
  out.push(`| Total entries | ${report.summary.totalEntries} |`);
  out.push(`| Total size bytes | ${report.summary.totalSizeBytes} |`);
  out.push(`| Missing required entries | ${report.summary.missingRequiredEntries} |`);
  out.push(`| Blocked entries | ${report.summary.blockedEntries} |`);
  out.push(`| Contains Web.config | ${yesNo(report.summary.containsWebConfig)} |`);
  out.push(`| Contains generated temp | ${yesNo(report.summary.containsGeneratedTemp)} |`);
  out.push(`| Contains node_modules | ${yesNo(report.summary.containsNodeModules)} |`);
  out.push(`| Contains build output | ${yesNo(report.summary.containsBuildOutput)} |`);
  out.push(`| Contains download binaries | ${yesNo(report.summary.containsDownloadBinaries)} |`);
  out.push("");
  out.push("## Archives");
  out.push("");
  out.push("| Archive | Entries | Size | Missing required | Blocked entries | Blocked categories |");
  out.push("|---|---:|---:|---|---|---|");
  for (const archive of report.archives) {
    out.push("| " + [
      archive.zip,
      archive.entries,
      archive.size,
      archive.missingRequiredEntries.length ? archive.missingRequiredEntries.join(", ") : "none",
      archive.blockedEntries.length ? archive.blockedEntries.join(", ") : "none",
      formatDeploymentBlockedCategories(archive.contains)
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
  out.push("## Checks");
  out.push("");
  out.push("| Check | Required | Status | Message |");
  out.push("|---|---|---|---|");
  for (const check of report.checks) {
    out.push("| " + [
      check.name,
      yesNo(check.required),
      check.ok ? "PASS" : "REVIEW",
      check.message
    ].map(markdownCell).join(" | ") + " |");
  }
  renderDeploymentHygieneReviewAssistant(out, report.reviewAssistant);
  out.push("## Operator Checklist");
  out.push("");
  out.push("Before sharing:");
  for (const item of report.operatorChecklist.beforeSharing) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Rotation triggers:");
  for (const item of report.operatorChecklist.rotationTriggers) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push(`Support boundary: ${markdownCell(report.operatorChecklist.supportBoundary)}`);
  out.push("");
  out.push("## Source-Free Boundary");
  out.push("");
  out.push("Safe to include:");
  for (const item of report.sourceBoundary.includes) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of report.sourceBoundary.doNotInclude) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("## Recommendations");
  out.push("");
  for (const item of report.recommendations) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Generated by `jso-protector --deployment-hygiene-evidence`. This packet summarizes archive hygiene evidence and is not a secret scan of live deployment config.");
  return out.join("\n");
}

function renderDeploymentHygieneReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("");
  out.push("## Deployment Hygiene Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function writeDeploymentHygieneEvidenceReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderDeploymentHygieneEvidenceText(report)}\n`;
  if (!args.deploymentHygieneOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.deploymentHygieneOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`Deployment hygiene evidence report written: ${resolvedPath}\n`);
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => stringOrNull(item)).filter(Boolean);
}

function basenameFromAnyPath(value) {
  const text = stringOrNull(value);
  if (!text) return "";
  const normalized = text.replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : normalized;
}

function formatDeploymentBlockedCategories(contains) {
  const items = [];
  if (contains.webConfig) items.push("Web.config");
  if (contains.generatedTemp) items.push("generated temp");
  if (contains.nodeModules) items.push("node_modules");
  if (contains.buildOutput) items.push("build output");
  if (contains.downloadBinaries) items.push("download binaries");
  return items.length ? items.join(", ") : "none";
}

function buildRuntimeIncidentEvidenceReport(exportPath, options = {}) {
  const evidence = pciCompliance._collectRuntimeIncidentEvidence(exportPath);
  const activeHighCritical = evidence.unresolvedHighCriticalCount || 0;
  const active = evidence.unresolvedCount || 0;
  const status = activeHighCritical > 0
    ? "needs-urgent-response"
    : (active > 0 ? "needs-triage" : "ready");
  const ok = activeHighCritical === 0;
  const generatedAt = options.generatedAt || new Date().toISOString();
  const routing = evidence.routing || {};
  const responseWindow = evidence.responseWindow || {};
  const responseChecklist = evidence.responseChecklist || {};
  const dashboardActions = Array.isArray(evidence.dashboardActions) ? evidence.dashboardActions : [];
  const correlation = evidence.correlation && typeof evidence.correlation === "object" ? evidence.correlation : {};
  const incidentActionPlan = evidence.actionPlanSummary && typeof evidence.actionPlanSummary === "object" ? evidence.actionPlanSummary : {};
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "incident counts",
      "status and severity totals",
      "BuildID list",
      "event and received date ranges",
      "repeated-signal correlation",
      "routing recommendation",
      "dashboard action metadata",
      "response window",
      "response checklist",
      "per-incident action-plan owners, due states, and status moves",
      "export SHA-256"
    ],
    doNotInclude: [
      "source code",
      "payment-card data",
      "customer personal data",
      "provider API keys",
      "collector tokens",
      "session tokens or secrets"
    ]
  };
  const reviewDecision = {
    status,
    label: status === "needs-urgent-response"
      ? "Needs urgent response"
      : (status === "needs-triage" ? "Needs triage" : "Ready"),
    reason: activeHighCritical > 0
      ? `${activeHighCritical} unresolved high/critical runtime incident(s) are present in the export.`
      : (active > 0
        ? `${active} unresolved runtime incident(s) are present, but none are high/critical.`
        : "No unresolved runtime incidents require response in this export."),
    nextAction: activeHighCritical > 0
      ? `Acknowledge the active high/critical packet, ${routing.statusAction || "move Open incidents to Reviewing"}, and route confirmed production incidents to the customer-owned alerting path.`
      : (active > 0
        ? "Triage Open and Reviewing incidents, confirm BuildID scope, and attach this packet beside the Dashboard export."
        : "Attach this source-free runtime incident packet beside the release evidence and keep monitoring routed to customer-owned systems.")
  };
  const recommendations = buildRuntimeIncidentEvidenceRecommendations(evidence);

  return {
    format: "jso-protector-runtime-incident-evidence",
    version: 1,
    ok,
    generatedAt,
    generatedBy: "jso-protector --runtime-incident-evidence",
    source: {
      file: path.basename(exportPath),
      format: evidence.sourceFormat,
      sha256: evidence.sourceSha256,
      filters: evidence.filters || {},
      generatedUtc: evidence.generatedUtc || null
    },
    summary: {
      incidents: evidence.count,
      unresolved: active,
      unresolvedHighCritical: activeHighCritical,
      uniqueBuildIds: evidence.uniqueBuildIdCount,
      buildIds: evidence.buildIds || [],
      statusCounts: evidence.statusCounts || {},
      severityCounts: evidence.severityCounts || {},
      oldestReceivedUtc: evidence.oldestReceivedUtc || null,
      newestReceivedUtc: evidence.newestReceivedUtc || null,
      oldestEventUtc: evidence.oldestEventUtc || null,
      newestEventUtc: evidence.newestEventUtc || null
    },
    routing: {
      escalationLevel: routing.escalationLevel || "",
      recommendedQueue: routing.recommendedQueue || "",
      preferredEvidence: routing.preferredEvidence || "",
      recommendedAction: routing.recommendedAction || "",
      responseTargetMinutes: routing.responseTargetMinutes || null,
      responseTargetLabel: routing.responseTargetLabel || "",
      statusAction: routing.statusAction || "",
      routeConfirmedIncidentsTo: Array.isArray(routing.routeConfirmedIncidentsTo) ? routing.routeConfirmedIncidentsTo : [],
      alertRoutingPlaybook: Array.isArray(routing.alertRoutingPlaybook) ? routing.alertRoutingPlaybook : []
    },
    responseWindow,
    responseChecklist,
    dashboardActions,
    correlation,
    incidentActionPlan,
    reviewDecision,
    sourceBoundary,
    reviewAssistant: buildRuntimeIncidentReviewAssistant(evidence, reviewDecision, sourceBoundary),
    recommendations
  };
}

function buildRuntimeIncidentEvidenceRecommendations(evidence) {
  const recommendations = [];
  const dashboardActions = Array.isArray(evidence && evidence.dashboardActions) ? evidence.dashboardActions : [];
  const actionPlan = evidence && evidence.actionPlanSummary && typeof evidence.actionPlanSummary === "object"
    ? evidence.actionPlanSummary
    : {};
  const bulkReviewAction = dashboardActions.find((action) => (
    action && action.dashboardAction === "mark_filtered_reviewing" && action.enabled === true
  ));
  const bulkResolveAction = dashboardActions.find((action) => (
    action && action.dashboardAction === "mark_filtered_resolved" && action.enabled === true
  ));
  if (bulkReviewAction) {
    recommendations.push(`Use Dashboard Monitoring action "${bulkReviewAction.label || "Move open in view to Reviewing"}" before external review, then re-export the filtered JSON packet.`);
  }
  if (bulkResolveAction) {
    recommendations.push(`Use Dashboard Monitoring action "${bulkResolveAction.label || "Resolve reviewing in view"}" after the filtered review is complete, then re-export the filtered JSON packet.`);
  }
  const repeatedGroups = runtimeEvidenceCorrelationGroups(evidence && evidence.correlation);
  const repeatedHighCritical = repeatedGroups.find((group) => (group.highOrCriticalActiveCount || 0) > 0);
  if (repeatedHighCritical) {
    recommendations.push(`Review repeated ${repeatedHighCritical.groupBy || "runtime"} signal "${repeatedHighCritical.key}" before external handoff; it appears ${repeatedHighCritical.count || 0} time(s) in the filtered packet.`);
  } else if (repeatedGroups.length > 0) {
    recommendations.push("Use the repeated-signal correlation table to close duplicate fingerprints or reasons as one triage thread before reviewer handoff.");
  }
  if ((actionPlan.overdueCount || 0) > 0) {
    recommendations.push(`Escalate ${actionPlan.overdueCount} overdue incident action plan(s) to the named next owner before sharing the packet.`);
  } else if ((actionPlan.incidentsWithActionPlan || 0) > 0) {
    recommendations.push("Use the incident action plan table to assign next owners and status moves before reviewer handoff.");
  }
  if ((evidence.unresolvedHighCriticalCount || 0) > 0) {
    recommendations.push("Treat this as an active response packet: acknowledge high/critical incidents within the response window before external review.");
  } else if ((evidence.unresolvedCount || 0) > 0) {
    recommendations.push("Review Open and Reviewing incidents before describing the protected release as clean.");
  } else if ((evidence.count || 0) === 0) {
    recommendations.push("Keep the empty Dashboard Monitoring export with release evidence to show no incidents matched the selected scope.");
  } else {
    recommendations.push("Keep this packet with the Dashboard Monitoring export so reviewers can see incident status without raw payload history.");
  }
  recommendations.push("Route confirmed production incidents to customer-owned SIEM, Slack, Splunk HEC, Elasticsearch, or signed webhook destinations.");
  recommendations.push("Share the export SHA-256 and source-free summary; do not add source code, payment-card data, customer personal data, provider keys, collector tokens, or secrets.");
  return recommendations;
}

function buildRuntimeIncidentReviewAssistant(evidence, reviewDecision, sourceBoundary) {
  evidence = evidence || {};
  const questions = [];
  const unresolvedHighCritical = evidence.unresolvedHighCriticalCount || 0;
  const unresolved = evidence.unresolvedCount || 0;
  const dashboardActions = Array.isArray(evidence.dashboardActions) ? evidence.dashboardActions : [];
  const enabledActions = dashboardActions.filter((action) => action && action.enabled === true);
  const repeatedGroups = runtimeEvidenceCorrelationGroups(evidence.correlation);
  const repeatedHighCritical = repeatedGroups.find((group) => (group.highOrCriticalActiveCount || 0) > 0);
  const routing = evidence.routing || {};
  const responseWindow = evidence.responseWindow || {};
  const actionPlan = evidence.actionPlanSummary && typeof evidence.actionPlanSummary === "object" ? evidence.actionPlanSummary : {};

  if (unresolvedHighCritical > 0) {
    questions.push({
      topic: "Urgent response",
      prompt: "Identify the active high/critical runtime incidents, confirm whether they are production-affecting, and decide who owns the immediate response.",
      ownerAction: "Acknowledge the packet, move matching Open incidents to Reviewing when appropriate, and route confirmed incidents to the customer-owned alerting path."
    });
  } else if (unresolved > 0) {
    questions.push({
      topic: "Open triage",
      prompt: "Review Open and Reviewing runtime incidents, confirm BuildID and filter scope, and decide which rows can be resolved, ignored, or escalated.",
      ownerAction: "Update Dashboard Monitoring status before external reviewer handoff."
    });
  }

  if (repeatedHighCritical) {
    questions.push({
      topic: "Repeated high-risk signal",
      prompt: `Review repeated ${repeatedHighCritical.groupBy || "runtime"} signal "${repeatedHighCritical.key}" as one incident thread and confirm whether it indicates persistent tamper activity.`,
      ownerAction: "Close duplicate rows together only after the shared cause is understood."
    });
  } else if (repeatedGroups.length > 0) {
    questions.push({
      topic: "Repeated signal correlation",
      prompt: "Group repeated fingerprints or reasons into triage threads so the reviewer sees one owner action per repeated signal instead of one action per row.",
      ownerAction: "Attach the repeated-signal owner, suspected cause, and closeout note before review."
    });
  }

  if (enabledActions.length > 0) {
    questions.push({
      topic: "Dashboard status actions",
      prompt: "Decide which enabled Dashboard Monitoring action should run before the next export, and confirm its filtered account/status/severity/BuildID scope.",
      ownerAction: "Run the scoped dashboard action, then export a fresh JSON packet."
    });
  }

  if (responseWindow && responseWindow.responseDueUtc) {
    questions.push({
      topic: "Response window",
      prompt: "Check whether the response window is within target or overdue, then decide whether this packet needs immediate on-call escalation.",
      ownerAction: "Record the response owner and due-time decision in the incident system."
    });
  }

  if ((actionPlan.overdueCount || 0) > 0) {
    questions.push({
      topic: "Overdue incident owners",
      prompt: "Review incident action plans with overdue response windows and confirm the named next owner has accepted the handoff.",
      ownerAction: "Escalate overdue rows in the customer-owned incident system, then re-export after status changes are recorded."
    });
  } else if ((actionPlan.incidentsWithActionPlan || 0) > 0) {
    questions.push({
      topic: "Incident owner assignment",
      prompt: "Use the per-incident action plan to confirm each row has a next owner, status move, evidence packet, and due-state decision.",
      ownerAction: "Assign unresolved rows before external review and keep archived rows with release evidence."
    });
  }

  if (routing && (routing.recommendedQueue || routing.statusAction || (Array.isArray(routing.routeConfirmedIncidentsTo) && routing.routeConfirmedIncidentsTo.length))) {
    questions.push({
      topic: "Alert routing handoff",
      prompt: "Confirm the recommended queue, status action, and downstream destinations for confirmed runtime incidents.",
      ownerAction: "Route confirmed incidents to customer-owned SIEM, Slack, Splunk HEC, Elasticsearch, or signed webhook destinations."
    });
  }

  if (questions.length === 0) {
    questions.push({
      topic: "Clean review",
      prompt: "Confirm no runtime incidents in this export require response and attach the source-free packet beside the release evidence.",
      ownerAction: "Keep monitoring routed to customer-owned systems and re-export if the dashboard filter changes."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "review decision",
      "recommendations",
      "alert routing playbook lanes",
      "dashboard status-action labels and scope",
      "repeated-signal correlation summaries",
      "incident action-plan owner and due-state summaries"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw incident payloads",
      "raw user-agent strings when treated as personal data",
      "collector-token values"
    ])));

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to triage runtime incident evidence without sending source code, raw payloads, collector tokens, customer data, or secrets.",
    reviewerPrompt: "Review this JSO runtime incident evidence packet. Use only the source-free counts, BuildIDs, statuses, severities, response window, routing recommendation, dashboard actions, response checklist, per-incident action-plan owner/due labels, repeated-signal correlation, and export SHA-256. Produce owner actions without treating JSO as a managed SOC console.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function renderRuntimeIncidentEvidenceText(report) {
  const out = [];
  out.push("# Runtime Incident Evidence");
  out.push("");
  out.push(`Generated: ${report.generatedAt}`);
  out.push(`Status: ${report.ok ? "PASS" : "NEEDS RESPONSE"}`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push(`| Export artifact | \`${markdownInline(report.source.file)}\` |`);
  out.push(`| Export format | ${String(report.source.format || "").toUpperCase()} |`);
  out.push(`| Export sha256 | \`${report.source.sha256}\` |`);
  out.push(`| Filters | ${markdownCell(formatRuntimeEvidenceFilters(report.source.filters))} |`);
  out.push(`| Incidents | ${report.summary.incidents} |`);
  out.push(`| Open/reviewing | ${report.summary.unresolved} |`);
  out.push(`| Open/reviewing high-or-critical | ${report.summary.unresolvedHighCritical} |`);
  out.push(`| Status counts | ${markdownCell(formatRuntimeEvidenceCounts(report.summary.statusCounts))} |`);
  out.push(`| Severity counts | ${markdownCell(formatRuntimeEvidenceCounts(report.summary.severityCounts))} |`);
  out.push(`| Build IDs | ${markdownCell(formatRuntimeEvidenceBuildIds(report.summary))} |`);
  out.push(`| Received range | ${markdownCell(formatRuntimeEvidenceRange(report.summary.oldestReceivedUtc, report.summary.newestReceivedUtc))} |`);
  out.push(`| Event range | ${markdownCell(formatRuntimeEvidenceRange(report.summary.oldestEventUtc, report.summary.newestEventUtc))} |`);
  out.push(`| Repeated-signal correlation | ${markdownCell(formatRuntimeEvidenceCorrelation(report.correlation))} |`);
  out.push(`| Incident action plan | ${markdownCell(formatRuntimeEvidenceActionPlan(report.incidentActionPlan))} |`);
  out.push(`| Routing | ${markdownCell(formatRuntimeEvidenceRouting(report.routing))} |`);
  out.push(`| Response window | ${markdownCell(formatRuntimeEvidenceResponseWindow(report.responseWindow))} |`);
  out.push("");
  out.push("## Review Decision");
  out.push("");
  out.push("| Field | Value |");
  out.push("|---|---|");
  out.push(`| Decision | ${markdownCell(report.reviewDecision.label)} |`);
  out.push(`| Reason | ${markdownCell(report.reviewDecision.reason)} |`);
  out.push(`| Next action | ${markdownCell(report.reviewDecision.nextAction)} |`);
  renderRuntimeIncidentEvidenceCorrelation(out, report.correlation);
  renderRuntimeIncidentEvidenceActionPlan(out, report.incidentActionPlan);
  renderRuntimeIncidentEvidenceDashboardActions(out, report.dashboardActions);
  renderRuntimeIncidentEvidencePlaybook(out, report.routing.alertRoutingPlaybook);
  renderRuntimeIncidentEvidenceChecklist(out, report.responseChecklist);
  renderRuntimeIncidentReviewAssistant(out, report.reviewAssistant);
  out.push("## Source-Free Boundary");
  out.push("");
  out.push("Safe to include:");
  for (const item of report.sourceBoundary.includes) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of report.sourceBoundary.doNotInclude) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("## Recommendations");
  out.push("");
  for (const item of report.recommendations) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Generated by `jso-protector --runtime-incident-evidence`. This packet summarizes a Dashboard Monitoring export and is not a managed SOC report.");
  return out.join("\n");
}

function renderRuntimeIncidentReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("## Runtime Incident Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push(`- ${markdownCell(item)}`);
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function renderRuntimeIncidentEvidenceDashboardActions(out, actions) {
  if (!Array.isArray(actions) || actions.length === 0) return;
  out.push("");
  out.push("## Dashboard Actions");
  out.push("");
  out.push("| Action | Enabled | Scope | Status change | Safety |");
  out.push("|---|---|---|---|---|");
  for (const action of actions) {
    const enabled = action.enabled === true ? "yes" : (action.enabled === false ? "no" : "n/a");
    const statusChange = action.statusFrom && action.statusTo ? `${action.statusFrom} -> ${action.statusTo}` : "";
    out.push("| " + [
      action.label || action.id || "",
      enabled,
      action.scope || action.filterContext || "",
      statusChange,
      action.safety || ""
    ].map(markdownCell).join(" | ") + " |");
  }
}

function renderRuntimeIncidentEvidenceActionPlan(out, actionPlan) {
  if (!actionPlan || !Array.isArray(actionPlan.topActions) || actionPlan.topActions.length === 0) return;
  out.push("");
  out.push("## Incident Action Plan");
  out.push("");
  out.push("These source-free row actions come from Dashboard Monitoring and identify the next owner, due state, evidence packet, and dashboard status move.");
  out.push("");
  out.push("| Incident | Level | Next owner | Due | State | Status move | Evidence | Next action |");
  out.push("|---|---|---|---|---|---|---|---|");
  for (const row of actionPlan.topActions) {
    out.push("| " + [
      row.incidentId || "",
      row.escalationLevel || "",
      row.nextOwner || "",
      row.responseDueUtc || row.responseTargetLabel || "",
      row.windowState || "",
      row.statusTransition || "",
      row.evidence || "",
      row.nextAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function renderRuntimeIncidentEvidencePlaybook(out, playbook) {
  if (!Array.isArray(playbook) || playbook.length === 0) return;
  out.push("");
  out.push("## Alert Routing Playbook");
  out.push("");
  out.push("| Lane | Owner | Trigger | Target | Evidence | Action | Boundary |");
  out.push("|---|---|---|---|---|---|---|");
  for (const row of playbook) {
    out.push("| " + [
      row.lane || row.id || "",
      row.owner || "",
      row.trigger || "",
      row.target || "",
      row.evidence || "",
      row.action || "",
      row.boundary || ""
    ].map(markdownCell).join(" | ") + " |");
  }
}

function renderRuntimeIncidentEvidenceChecklist(out, checklist) {
  if (!checklist || !Array.isArray(checklist.steps) || checklist.steps.length === 0) return;
  out.push("");
  out.push("## Response Checklist");
  out.push("");
  if (checklist.filterScope) out.push(`Filter scope: ${markdownCell(checklist.filterScope)}`);
  if (checklist.routingScope) out.push(`Routing scope: ${markdownCell(checklist.routingScope)}`);
  out.push("");
  out.push("| Step | Owner | Target | Action |");
  out.push("|---|---|---|---|");
  for (const step of checklist.steps) {
    out.push("| " + [
      step.id || "",
      step.owner || "",
      step.target || "",
      step.action || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function renderRuntimeIncidentEvidenceCorrelation(out, correlation) {
  const groups = runtimeEvidenceCorrelationGroups(correlation);
  if (groups.length === 0) return;
  out.push("");
  out.push("## Repeated Signal Correlation");
  out.push("");
  out.push("These source-free clusters show repeated fingerprints or repeated reasons in the filtered Dashboard Monitoring packet.");
  out.push("");
  out.push("| Group | Key | Hits | Active | Active high/critical | Build IDs | Last seen | Recommended action |");
  out.push("|---|---|---|---|---|---|---|---|");
  for (const group of groups) {
    out.push("| " + [
      group.groupBy || "",
      group.key || "",
      group.count || 0,
      group.activeCount || 0,
      group.highOrCriticalActiveCount || 0,
      Array.isArray(group.buildIds) && group.buildIds.length ? group.buildIds.join(", ") : "none",
      group.lastReceivedUtc || "",
      group.recommendedAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
}

function runtimeEvidenceCorrelationGroups(correlation) {
  if (!correlation || typeof correlation !== "object") return [];
  return []
    .concat(Array.isArray(correlation.topFingerprintGroups) ? correlation.topFingerprintGroups : [])
    .concat(Array.isArray(correlation.topReasonGroups) ? correlation.topReasonGroups : [])
    .filter((group) => group && group.key && (group.count || 0) > 1)
    .slice(0, 10);
}

function writeRuntimeIncidentEvidenceReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderRuntimeIncidentEvidenceText(report)}\n`;
  if (!args.runtimeIncidentEvidenceOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.runtimeIncidentEvidenceOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`Runtime incident evidence report written: ${resolvedPath}\n`);
}

function formatRuntimeEvidenceCounts(counts) {
  const keys = Object.keys(counts || {}).filter((key) => counts[key] > 0).sort();
  if (!keys.length) return "none";
  return keys.map((key) => `${key}: ${counts[key]}`).join(", ");
}

function formatRuntimeEvidenceActionPlan(actionPlan) {
  if (!actionPlan || !actionPlan.incidentsWithActionPlan) return "none";
  const parts = [`plans=${actionPlan.incidentsWithActionPlan}`];
  if (actionPlan.overdueCount) parts.push(`overdue=${actionPlan.overdueCount}`);
  if (actionPlan.acknowledgementRequiredCount) parts.push(`acknowledgement-required=${actionPlan.acknowledgementRequiredCount}`);
  const ownerCounts = formatRuntimeEvidenceCounts(actionPlan.nextOwnerCounts || {});
  if (ownerCounts !== "none") parts.push(`owners ${ownerCounts}`);
  const escalationCounts = formatRuntimeEvidenceCounts(actionPlan.escalationCounts || {});
  if (escalationCounts !== "none") parts.push(`levels ${escalationCounts}`);
  return parts.join("; ");
}

function formatRuntimeEvidenceFilters(filters) {
  const keys = Object.keys(filters || {}).filter((key) => filters[key] !== "" && filters[key] != null).sort();
  if (!keys.length) return "none";
  return keys.map((key) => `${key}=${filters[key]}`).join(", ");
}

function formatRuntimeEvidenceBuildIds(summary) {
  const ids = Array.isArray(summary.buildIds) ? summary.buildIds : [];
  if (!ids.length) return "none";
  const suffix = summary.uniqueBuildIds > ids.length ? ` +${summary.uniqueBuildIds - ids.length} more` : "";
  return ids.join(", ") + suffix;
}

function formatRuntimeEvidenceRange(oldest, newest) {
  if (!oldest && !newest) return "none";
  if (oldest && newest && oldest !== newest) return `${oldest} .. ${newest}`;
  return oldest || newest || "none";
}

function formatRuntimeEvidenceRouting(routing) {
  const parts = [];
  if (routing.escalationLevel) parts.push(`level=${routing.escalationLevel}`);
  if (routing.recommendedQueue) parts.push(`queue=${routing.recommendedQueue}`);
  if (routing.preferredEvidence) parts.push(`evidence=${routing.preferredEvidence}`);
  if (routing.responseTargetLabel) parts.push(`target=${routing.responseTargetLabel}`);
  return parts.join(", ") || "none";
}

function formatRuntimeEvidenceResponseWindow(window) {
  if (!window || typeof window !== "object") return "none";
  const parts = [];
  if (window.windowState) parts.push(`state=${window.windowState}`);
  if (window.targetLabel) parts.push(`target=${window.targetLabel}`);
  if (window.responseDueUtc) parts.push(`due=${window.responseDueUtc}`);
  if (window.overdue === true) parts.push("overdue=yes");
  else if (window.overdue === false) parts.push("overdue=no");
  if (window.basis) parts.push(`basis=${window.basis}`);
  return parts.join(", ") || "none";
}

function formatRuntimeEvidenceCorrelation(correlation) {
  if (!correlation || typeof correlation !== "object") return "none";
  const fingerprintCount = correlation.repeatedFingerprintGroupCount || 0;
  const reasonCount = correlation.repeatedReasonGroupCount || 0;
  const top = runtimeEvidenceCorrelationGroups(correlation).slice(0, 3).map((group) => {
    const groupBy = group.groupBy || "signal";
    return `${groupBy}=${group.key} (${group.count || 0}x)`;
  });
  const prefix = `fingerprints=${fingerprintCount}, reasons=${reasonCount}`;
  return top.length ? `${prefix}; top ${top.join(", ")}` : prefix;
}

function verifyVmProofReport(reportPath, options = {}) {
  const resolvedPath = path.resolve(reportPath);
  const raw = readJsonObjectFile(resolvedPath, "VM proof report");
  const report = raw.Report && typeof raw.Report === "object" && !Array.isArray(raw.Report) ? raw.Report : raw;
  const minVirtualizedFunctions = Math.max(1, Math.floor(Number(options.minVirtualizedFunctions || options.minVmFunctions || 1) || 1));
  const enabledOptions = firstReportValue(report, "EnabledOptions", "enabledOptions", "Options", "options");
  const requestOptions = firstReportValue(report, "RequestOptions", "requestOptions", "HttpOptions", "httpOptions");
  const requested =
    boolishTrue(firstReportValue(report, "UseVMProtection", "useVMProtection")) ||
    optionListIncludes(enabledOptions, "UseVMProtection") ||
    optionListIncludes(requestOptions, "UseVMProtection") ||
    boolishTrue(optionObjectValue(enabledOptions, "UseVMProtection")) ||
    boolishTrue(optionObjectValue(requestOptions, "UseVMProtection"));
  const applied = boolishTrue(firstReportValue(report, "VMProtectionApplied", "vmProtectionApplied"));
  const virtualizedCount = integerOrZero(firstReportValue(
    report,
    "VMProtectionVirtualizedCount",
    "vmProtectionVirtualizedCount",
    "VirtualizedFunctionCount",
    "virtualizedFunctionCount"
  ));
  const warnings = normalizeVmWarnings(firstReportValue(report, "VMProtectionWarnings", "vmProtectionWarnings"));
  const buildId = stringOrNull(firstReportValue(report, "BuildID", "BuildId", "buildID", "buildId"));

  const checks = [
    {
      name: "requested",
      ok: requested,
      message: requested ? "UseVMProtection was requested." : "UseVMProtection is not present in the report."
    },
    {
      name: "applied",
      ok: applied,
      message: applied ? "VMProtectionApplied is true." : "VMProtectionApplied is not true."
    },
    {
      name: "virtualized-count",
      ok: virtualizedCount >= minVirtualizedFunctions,
      message: `Virtualized function count is ${virtualizedCount}; required minimum is ${minVirtualizedFunctions}.`
    },
    {
      name: "warnings",
      ok: warnings.length === 0,
      message: warnings.length === 0 ? "No VMProtectionWarnings are present." : `${warnings.length} VMProtectionWarnings still need review.`
    }
  ];

  const ok = checks.every((check) => check.ok);
  return {
    format: "jso-protector-vm-proof-check",
    version: 1,
    ok,
    reportPath: resolvedPath,
    generatedAt: new Date().toISOString(),
    buildId,
    minVirtualizedFunctions,
    summary: {
      requested,
      applied,
      virtualizedCount,
      warnings: warnings.length
    },
    warnings,
    checks
  };
}

function buildVmProofPack(reportPath, options = {}) {
  const resolvedPath = path.resolve(reportPath);
  const raw = readJsonObjectFile(resolvedPath, "VM proof pack report");
  const report = raw.Report && typeof raw.Report === "object" && !Array.isArray(raw.Report) ? raw.Report : raw;
  const minVirtualizedFunctions = Math.max(1, Math.floor(Number(options.minVirtualizedFunctions || options.minVmFunctions || 1) || 1));
  const proof = verifyVmProofReport(resolvedPath, { minVirtualizedFunctions });
  const buildId = proof.buildId || stringOrNull(firstReportValue(report, "BuildID", "BuildId", "buildID", "buildId") || firstReportValue(raw, "BuildID", "BuildId", "buildID", "buildId"));
  const releaseLabel = stringOrNull(firstReportValue(report, "ReleaseLabel", "releaseLabel", "Label", "label") || firstReportValue(raw, "ReleaseLabel", "releaseLabel", "Label", "label"));
  const polymorphismFingerprint = stringOrNull(firstReportValue(report, "PolymorphismFingerprint", "polymorphismFingerprint", "Fingerprint", "fingerprint") || firstReportValue(raw, "PolymorphismFingerprint", "polymorphismFingerprint", "Fingerprint", "fingerprint"));
  const enabledOptions = normalizedOptionNames(
    firstReportValue(report, "EnabledOptions", "enabledOptions", "Options", "options", "RequestOptions", "requestOptions")
  );
  const checklist = buildVmProofPackChecklist(proof, {
    buildId,
    releaseLabel,
    polymorphismFingerprint
  });
  const ok = checklist.every((item) => !item.required || item.ok);
  const reviewDecision = buildVmProofReviewDecision(checklist, proof);
  const sourceBoundary = {
    sourceFree: true,
    includes: [
      "build identity",
      "release label",
      "polymorphism fingerprint",
      "enabled option names",
      "VM proof check status",
      "virtualized function count",
      "VM warning count and warning text",
      "compatibility guidance",
      "hot-path/cold-path performance guidance",
      "review decision"
    ],
    doNotInclude: [
      "source code",
      "protected output",
      "VM bytecode",
      "raw source function bodies",
      "source maps",
      "provider keys",
      "customer data",
      "secrets"
    ]
  };
  return {
    format: "jso-protector-vm-proof-pack",
    version: 1,
    ok,
    sourceFree: true,
    generatedAt: new Date().toISOString(),
    generatedBy: "jso-protector --vm-proof-pack",
    reportPath: resolvedPath,
    buildId,
    releaseLabel,
    polymorphismFingerprint,
    minVirtualizedFunctions,
    proof,
    evidence: {
      enabledOptions,
      requested: proof.summary.requested,
      applied: proof.summary.applied,
      virtualizedCount: proof.summary.virtualizedCount,
      warningCount: proof.summary.warnings,
      warnings: proof.warnings.slice()
    },
    compatibilityGuidance: buildVmProofCompatibilityGuidance(),
    performanceGuidance: buildVmProofPerformanceGuidance(),
    checklist,
    reviewDecision,
    sourceBoundary,
    reviewAssistant: buildVmProofReviewAssistant(checklist, proof, reviewDecision, sourceBoundary),
    recommendations: buildVmProofPackRecommendations(checklist, proof)
  };
}

function buildVmProofPackChecklist(proof, context) {
  const proofChecks = proof.checks || [];
  const byName = {};
  for (const check of proofChecks) byName[check.name] = check;
  return [
    {
      name: "source-free-report",
      required: true,
      ok: true,
      message: "The proof pack reads the saved API report only and does not include protected or original source code."
    },
    {
      name: "build-id",
      required: true,
      ok: !!context.buildId,
      message: context.buildId ? "Build identity is present: " + context.buildId + "." : "The API report does not include a BuildID."
    },
    {
      name: "release-label",
      required: false,
      ok: !!context.releaseLabel,
      message: context.releaseLabel ? "Release label is present: " + context.releaseLabel + "." : "No release label was found. Use --label during protection when reviewers need a CI commit or release tag."
    },
    {
      name: "polymorphism-fingerprint",
      required: false,
      ok: !!context.polymorphismFingerprint,
      message: context.polymorphismFingerprint ? "Polymorphism fingerprint is present." : "No polymorphism fingerprint was found in the report."
    },
    vmProofChecklistItem(byName.requested, "requested"),
    vmProofChecklistItem(byName.applied, "applied"),
    vmProofChecklistItem(byName["virtualized-count"], "virtualized-count"),
    vmProofChecklistItem(byName.warnings, "warnings"),
    {
      name: "performance-scope",
      required: false,
      ok: false,
      message: "Manual review: confirm every virtualized function is a cold sensitive path, not a render loop, animation tick, scroll handler, or high-frequency parser."
    }
  ];
}

function vmProofChecklistItem(check, fallbackName) {
  check = check || { name: fallbackName, ok: false, message: "VM proof check was not present." };
  return {
    name: check.name,
    required: true,
    ok: !!check.ok,
    message: check.message || ""
  };
}

function buildVmProofReviewDecision(checklist, proof) {
  const requiredFailures = (checklist || []).filter((item) => item.required && !item.ok);
  const manualItems = (checklist || []).filter((item) => !item.required && !item.ok);
  if (requiredFailures.length > 0) {
    return {
      decision: "blocked",
      label: "Blocked",
      ok: false,
      manualReviewRequired: true,
      reason: requiredFailures.length + " required VM proof check" + (requiredFailures.length === 1 ? "" : "s") + " failed: " + requiredFailures.map((item) => item.name).join(", ") + ".",
      nextAction: "Resolve the failed proof checks, rerun protection if needed, and regenerate the VM proof pack before reviewer handoff."
    };
  }
  if (manualItems.length > 0) {
    return {
      decision: "ready-for-manual-review",
      label: "Ready for manual review",
      ok: true,
      manualReviewRequired: true,
      reason: "Required VM proof checks passed; reviewer still needs to confirm function scope and protected-build behavior.",
      nextAction: "Confirm every virtualized function is a cold sensitive path and attach smoke-test results for the affected flow."
    };
  }
  return {
    decision: "ready",
    label: "Ready",
    ok: true,
    manualReviewRequired: false,
    reason: "Required and optional VM proof checks passed.",
    nextAction: "Attach this proof pack beside the signed manifest and protected artifact for release review."
  };
}

function buildVmProofPackRecommendations(checklist, proof) {
  const recommendations = [];
  if (checklist.some((item) => item.name === "build-id" && !item.ok)) {
    recommendations.push("Keep the saved API report from the same protected build and include --label so reviewers can tie the proof pack to a release.");
  }
  if (!proof.summary.requested) {
    recommendations.push("Set UseVMProtection=true and mark selected cold sensitive functions with // @virtualize before expecting VM proof to pass.");
  }
  if (!proof.summary.applied) {
    recommendations.push("Confirm the account tier is eligible for VM protection and that the API response accepted UseVMProtection.");
  }
  if (proof.summary.virtualizedCount < proof.minVirtualizedFunctions) {
    recommendations.push("Review marker placement and unsupported syntax when the virtualized function count is lower than expected.");
  }
  if (proof.warnings.length) {
    recommendations.push("Resolve every VMProtectionWarnings entry before handing the proof pack to a security reviewer.");
  }
  if (recommendations.length === 0) {
    recommendations.push("Attach this proof pack beside the signed manifest and protected artifact for release review.");
  }
  return recommendations;
}

function buildVmProofReviewAssistant(checklist, proof, reviewDecision, sourceBoundary) {
  const questions = [];
  const requiredFailures = (checklist || []).filter((item) => item && item.required && !item.ok);
  const performanceScope = (checklist || []).find((item) => item && item.name === "performance-scope");
  const buildId = (checklist || []).find((item) => item && item.name === "build-id");
  const releaseLabel = (checklist || []).find((item) => item && item.name === "release-label");

  if (requiredFailures.length > 0) {
    questions.push({
      topic: "Failed VM proof",
      prompt: "Identify which required VM proof checks failed and decide whether the release must be rebuilt before reviewer handoff.",
      ownerAction: "Resolve failed UseVMProtection, VMProtectionApplied, virtualized-count, BuildID, or warning checks before describing the build as VM-protected."
    });
  }

  if (proof && proof.summary && proof.summary.warnings > 0) {
    questions.push({
      topic: "VM warning resolution",
      prompt: "Review VMProtectionWarnings and decide which marked functions were skipped, narrowed, or left on Maximum mode.",
      ownerAction: "Record the skipped-function decision without pasting source bodies or protected output."
    });
  }

  if (proof && proof.summary && proof.summary.virtualizedCount > 0) {
    questions.push({
      topic: "VM scope confirmation",
      prompt: "Confirm each virtualized function is intentionally selected, sensitive, and narrow enough to justify VM bytecode protection.",
      ownerAction: "Attach the function-scope rationale and release owner approval beside the proof pack."
    });
  }

  if (performanceScope && performanceScope.ok === false) {
    questions.push({
      topic: "Hot-path risk",
      prompt: "Confirm none of the virtualized functions run in render loops, animation ticks, scroll handlers, high-volume parsers, or tight numeric loops.",
      ownerAction: "Move hot paths back to Maximum mode or attach measured protected-build performance evidence."
    });
  }

  if ((buildId && !buildId.ok) || (releaseLabel && !releaseLabel.ok)) {
    questions.push({
      topic: "Build identity",
      prompt: "Confirm the proof pack can be tied to one release artifact, CI run, commit, or customer handoff.",
      ownerAction: "Regenerate protection with --label when reviewers need release traceability."
    });
  }

  questions.push({
    topic: "Protected-build smoke",
    prompt: "Confirm the affected login, activation, checkout, license-validation, or entitlement flow still passes on the protected build.",
    ownerAction: "Attach smoke-test results or reduce the review decision to manual review until the affected flow is tested."
  });

  if (reviewDecision && reviewDecision.decision === "ready") {
    questions.push({
      topic: "Clean VM handoff",
      prompt: "Confirm the current source-free proof pack, VM scope, smoke evidence, and claim boundary are ready for security review.",
      ownerAction: "Attach the proof pack beside the signed manifest and protected artifact."
    });
  }

  const safeInputs = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.includes) ? sourceBoundary.includes : [])
    .concat([
      "review decision",
      "recommendations",
      "performance guidance",
      "compatibility guidance",
      "protected-build smoke result names"
    ])));
  const doNotInclude = Array.from(new Set([]
    .concat(sourceBoundary && Array.isArray(sourceBoundary.doNotInclude) ? sourceBoundary.doNotInclude : [])
    .concat([
      "raw performance traces with customer data",
      "function source snippets",
      "decompiled VM output"
    ])));

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to review VM proof evidence without sending source code, protected output, VM bytecode, source maps, provider keys, customer data, or secrets.",
    reviewerPrompt: "Review this JSO VM proof pack. Use only the source-free build identity, enabled options, VM proof checks, virtualized count, warning count/text, compatibility guidance, hot-path/cold-path guidance, review decision, and smoke-test names. Produce owner actions without requesting source code, protected output, or VM bytecode.",
    safeInputs,
    doNotInclude,
    questions
  };
}

function buildVmProofPerformanceGuidance() {
  return [
    {
      scope: "Good VM candidates",
      recommendation: "Virtualize cold sensitive functions.",
      examples: "License validation, paid-feature gates, anti-tamper checks, fingerprinting routines, and proprietary algorithms.",
      rationale: "These paths run rarely, so VM overhead is usually hidden by network, UI, or application work."
    },
    {
      scope: "Measure before shipping",
      recommendation: "Use VM protection only after an application smoke test and a representative interaction check.",
      examples: "Checkout eligibility checks, activation flows, and user-triggered policy decisions.",
      rationale: "Occasional user-triggered checks are normally the intended range, but the release owner should test the real flow."
    },
    {
      scope: "Do not virtualize",
      recommendation: "Keep hot paths on Maximum mode instead of VM bytecode.",
      examples: "Render loops, animation tick handlers, scroll handlers, high-volume parsers, and tight numeric loops.",
      rationale: "The VM interpreter adds work per instruction; high-frequency paths can turn that cost into visible latency."
    }
  ];
}

function buildVmProofCompatibilityGuidance() {
  return [
    {
      scope: "Supported function shape",
      guidance: "Use small synchronous function declarations with // @virtualize on the line immediately above the function.",
      examples: "License checks, activation gates, entitlement checks, tamper checks, and proprietary scoring functions.",
      action: "Keep the marker strict and keep the selected function narrow."
    },
    {
      scope: "Skipped with warning",
      guidance: "Unsupported syntax should stay on Maximum mode and be recorded in VMProtectionWarnings when it was marked for VM protection.",
      examples: "async functions, closures, class methods, this-dependent code, destructured parameters, template literals, and var-heavy legacy bodies.",
      action: "Read VMProtectionWarnings before approving the release as VM-protected."
    },
    {
      scope: "Avoid",
      guidance: "Do not virtualize code that depends on framework reflection, public callback names, vendor SDK contracts, or high-frequency execution.",
      examples: "React render paths, Angular template hooks, checkout-provider callbacks, analytics tags, scroll handlers, and parsers.",
      action: "Exclude public contracts and hot code, then protect the surrounding bundle with Maximum mode."
    }
  ];
}

function buildAiResistanceEvidenceReport(reportPath, options = {}) {
  const resolvedPath = path.resolve(reportPath);
  const raw = readJsonObjectFile(resolvedPath, "AI resistance evidence report");
  const report = raw.Report && typeof raw.Report === "object" && !Array.isArray(raw.Report) ? raw.Report : raw;
  const minVirtualizedFunctions = Math.max(1, Math.floor(Number(options.minVirtualizedFunctions || options.minVmFunctions || 1) || 1));
  const requireVmProof = options.requireVmProof === true;
  const buildId = stringOrNull(firstReportValue(report, "BuildID", "BuildId", "buildID", "buildId") || firstReportValue(raw, "BuildID", "BuildId", "buildID", "buildId"));
  const polymorphismFingerprint = stringOrNull(firstReportValue(report, "PolymorphismFingerprint", "polymorphismFingerprint", "Fingerprint", "fingerprint"));
  const enabledOptions = normalizedOptionNames(
    firstReportValue(report, "EnabledOptions", "enabledOptions", "Options", "options", "RequestOptions", "requestOptions")
  );
  const strongOptionNames = enabledOptions.filter((name) => AI_RESISTANCE_STRONG_OPTIONS.has(name.toLowerCase()));
  const compatibilitySummary = firstReportValue(report, "CompatibilitySummary", "compatibilitySummary", "Compatibility", "compatibility");
  const runtimeDefenseSummary = firstReportValue(report, "RuntimeDefenseSummary", "runtimeDefenseSummary");
  const runtimeBeaconUrl = stringOrNull(firstReportValue(report, "RuntimeDefenseBeaconUrl", "runtimeDefenseBeaconUrl", "BeaconUrl", "beaconUrl"));
  const symbolPack = firstReportValue(report, "RecoverySymbolPackJson", "recoverySymbolPackJson", "Symbolication", "symbolication");
  const globalMap = firstReportValue(report, "GlobalIdentifierMap", "globalIdentifierMap");
  const memberMap = firstReportValue(report, "MemberIdentifierMap", "memberIdentifierMap");
  const vmProof = summarizeVmProofFromReport(report, minVirtualizedFunctions);
  const hasRuntimeEvidence = !!runtimeDefenseSummary || !!runtimeBeaconUrl;
  const hasCompatibilityEvidence = compatibilitySummary != null;
  const hasSourceFreeMaps = !!symbolPack || Array.isArray(globalMap) || Array.isArray(memberMap) || !!polymorphismFingerprint;
  const checks = [
    {
      name: "build-id",
      required: true,
      ok: !!buildId,
      message: buildId ? `BuildID is ${buildId}.` : "The report does not include a BuildID."
    },
    {
      name: "strong-protection-options",
      required: true,
      ok: strongOptionNames.length > 0,
      message: strongOptionNames.length
        ? `Strong protection option evidence: ${strongOptionNames.join(", ")}.`
        : "The report does not show strong protection options such as EncryptStrings, FlatTransform, DeepObfuscate, or UseVMProtection."
    },
    {
      name: "source-free-review-data",
      required: false,
      ok: hasSourceFreeMaps,
      message: hasSourceFreeMaps
        ? "Source-free review data is present through a fingerprint, symbol pack, or identifier map."
        : "No source-free fingerprint, symbol pack, or identifier map was found in the report."
    },
    {
      name: "vm-proof",
      required: requireVmProof || vmProof.requested,
      ok: vmProof.ok || (!requireVmProof && !vmProof.requested),
      message: vmProof.requested
        ? `VM proof requested=${vmProof.requested}, applied=${vmProof.applied}, virtualized=${vmProof.virtualizedCount}, warnings=${vmProof.warnings.length}.`
        : "VM proof was not requested for this report."
    },
    {
      name: "runtime-defense-evidence",
      required: false,
      ok: hasRuntimeEvidence,
      message: hasRuntimeEvidence
        ? "Runtime-defense beacon or summary evidence is present."
        : "No runtime-defense beacon or summary evidence was found."
    },
    {
      name: "compatibility-evidence",
      required: false,
      ok: hasCompatibilityEvidence,
      message: hasCompatibilityEvidence
        ? "Compatibility evidence is present."
        : "No compatibility summary was found."
    },
    {
      name: "resistance-score-status",
      required: false,
      ok: true,
      message: "Resistance Score remains a planned methodology, not a production score in this report."
    }
  ];

  const requiredFailures = checks.filter((check) => check.required && !check.ok);
  const reviewMatrix = buildAiResistanceReviewMatrix({
    enabledOptions,
    vmProof,
    hasRuntimeEvidence,
    hasCompatibilityEvidence,
    hasSourceFreeMaps
  });
  const reviewDecision = buildAiResistanceEvidenceReviewDecision(checks, reviewMatrix);
  const claimBoundaries = buildAiResistanceClaimBoundaries();
  return {
    format: "jso-protector-ai-resistance-evidence",
    version: 1,
    ok: requiredFailures.length === 0,
    scoreStatus: "planned-methodology-not-production-score",
    reportPath: resolvedPath,
    generatedAt: new Date().toISOString(),
    buildId,
    polymorphismFingerprint,
    evidence: {
      enabledOptions,
      strongOptions: strongOptionNames,
      vmProof,
      runtimeDefense: {
        present: hasRuntimeEvidence,
        hasSummary: !!runtimeDefenseSummary,
        hasBeaconUrl: !!runtimeBeaconUrl
      },
      compatibility: {
        present: hasCompatibilityEvidence
      },
      sourceFreeReviewData: {
        present: hasSourceFreeMaps,
        hasPolymorphismFingerprint: !!polymorphismFingerprint,
        hasSymbolPack: !!symbolPack,
        hasGlobalIdentifierMap: Array.isArray(globalMap),
        hasMemberIdentifierMap: Array.isArray(memberMap)
      }
    },
    reviewMatrix,
    reviewDecision,
    reviewAssistant: buildAiResistanceReviewAssistant(reviewDecision, reviewMatrix, checks, claimBoundaries),
    claimBoundaries,
    checks,
    recommendations: buildAiResistanceEvidenceRecommendations(checks, vmProof, {
      requireVmProof,
      hasRuntimeEvidence,
      hasCompatibilityEvidence,
      hasSourceFreeMaps
    })
  };
}

function renderAiResistanceEvidenceText(report) {
  const out = [];
  out.push(`jso-protector ai-resistance-evidence: ${report.ok ? "ok" : "needs review"}`);
  out.push(`report: ${report.reportPath}`);
  out.push(`score status: ${report.scoreStatus}`);
  if (report.reviewDecision && report.reviewDecision.label) {
    out.push(`review decision: ${report.reviewDecision.label}`);
  }
  if (report.buildId) out.push(`BuildID: ${report.buildId}`);
  for (const check of report.checks) {
    const prefix = check.required ? (check.ok ? "OK" : "FAIL") : (check.ok ? "INFO" : "NOTE");
    out.push(`${prefix} ${check.name}: ${check.message}`);
  }
  out.push("Review matrix:");
  for (const row of report.reviewMatrix || []) {
    out.push(`- ${row.id} [${row.status}]: ${row.reviewerAction}`);
  }
  out.push("Claim boundaries:");
  for (const item of report.claimBoundaries || []) {
    out.push(`- ${item.claim}: ${item.approvedWording}`);
  }
  renderAiResistanceReviewAssistantText(out, report.reviewAssistant);
  out.push("Recommendations:");
  for (const item of report.recommendations) {
    out.push(`- ${item}`);
  }
  return out.join("\n");
}

function renderAiResistanceReviewAssistantText(out, assistant) {
  if (!assistant) return;
  out.push("Review assistant packet:");
  out.push(`- intended use: ${assistant.intendedUse}`);
  out.push(`- reviewer prompt: ${assistant.reviewerPrompt}`);
  out.push(`- safe inputs: ${(assistant.safeInputs || []).join("; ")}`);
  out.push(`- do not include: ${(assistant.doNotInclude || []).join("; ")}`);
  out.push("Assistant questions:");
  for (const item of assistant.questions || []) {
    out.push(`- ${item.topic}: ${item.prompt}`);
    if (item.ownerAction) out.push(`  owner action: ${item.ownerAction}`);
  }
}

function writeAiResistanceEvidenceReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : `${renderAiResistanceEvidenceText(report)}\n`;
  if (!args.aiResistanceEvidenceOutput) {
    process.stdout.write(text);
    return;
  }

  const resolvedPath = path.resolve(args.aiResistanceEvidenceOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`AI resistance evidence report written: ${resolvedPath}\n`);
}

function buildScriptInventoryFromSnapshot(snapshotPath, options = {}) {
  const resolvedPath = path.resolve(snapshotPath);
  const sourceText = readTextFile(resolvedPath, "third-party-inventory snapshot");
  const payload = parseJsonText(sourceText, `third-party-inventory snapshot ${resolvedPath}`);
  const snapshots = collectInventorySnapshots(payload);
  if (snapshots.length === 0) {
    throw new Error(`third-party-inventory snapshot ${resolvedPath} must include a scripts array.`);
  }

  const scripts = [];
  const byKey = new Map();
  const buildIds = new Set();
  const pageHrefs = new Set();

  for (const snapshot of snapshots) {
    const buildId = stringOrNull(firstReportValue(snapshot, "buildId", "BuildId", "buildID"));
    const pageHref = stringOrNull(firstReportValue(snapshot, "pageHref", "PageHref", "url", "href"));
    const surfaceContext = buildSurfaceContext(snapshot, { pageHref });
    if (buildId) buildIds.add(buildId);
    if (pageHref) pageHrefs.add(pageHref);

    for (const item of snapshot.scripts || []) {
      const row = buildScriptInventoryRow(item, surfaceContext);
      if (!row.source) continue;
      const key = [
        row.source,
        row.integrity || "",
        row.checkoutSurface || "",
        row.frameContext || "",
        row.frameOwner || "",
        row.frameHref || ""
      ].join("\n");
      const existing = byKey.get(key);
      if (existing) {
        mergeScriptInventoryRow(existing, row);
        continue;
      }
      byKey.set(key, row);
      scripts.push(row);
    }
  }

  if (scripts.length === 0) {
    throw new Error(`third-party-inventory snapshot ${resolvedPath} did not contain any script records.`);
  }

  scripts.sort((a, b) => String(a.source).localeCompare(String(b.source)));
  const generatedUtc = options.generatedUtc || new Date().toISOString();
  const sourceSnapshotSha256 = sha256(sourceText);
  return {
    format: "jso-payment-script-inventory",
    version: 1,
    sourceFree: true,
    generatedUtc,
    generatedBy: "jso-protector --script-inventory-from-snapshot",
    sourceSnapshot: path.basename(resolvedPath),
    sourceSnapshotSha256,
    snapshotCount: snapshots.length,
    buildIds: Array.from(buildIds).sort(),
    pageHrefs: Array.from(pageHrefs).sort(),
    reviewStatus: "starter-generated-review-required",
    reviewInstructions: [
      "Review every script before audit use.",
      "Set authorized to true only for approved scripts.",
      "Add written justification, owner, lastReviewedUtc, risk, dataAccess, and approvalTicket for each approved payment-page script when available."
    ],
    scripts
  };
}

function buildScriptInventoryRow(record, context = {}) {
  const src = stringOrNull(firstReportValue(record, "src", "source", "url", "href"));
  const inline = boolishTrue(firstReportValue(record, "inline", "isInline")) || !src;
  const sha = normalizeSha256(firstReportValue(record, "sha256", "hash", "contentSha256", "integrity"));
  const source = src || (sha ? `inline:sha256-${sha}` : "inline:unknown");
  const allowlisted = normalizeAuthorizationValue(firstReportValue(record, "allowlisted", "allowed", "authorized"));
  const observedAt = stringOrNull(firstReportValue(record, "observedAt", "firstSeenUtc", "timestamp", "createdUtc"));
  const injectedAfterLoad = boolishTrue(firstReportValue(record, "injectedAfterLoad", "lateInjected", "injected"));
  const surface = buildSurfaceContext(record, context);

  return {
    source,
    authorized: allowlisted,
    justification: "",
    owner: "",
    category: categorizePaymentScriptSource(source, context.pageHref, inline),
    integrity: sha ? `sha256-${sha}` : "",
    lastReviewedUtc: "",
    checkoutSurface: surface.checkoutSurface,
    frameContext: surface.frameContext,
    frameOwner: surface.frameOwner,
    parentPageHref: surface.parentPageHref,
    frameHref: surface.frameHref,
    frameOrigin: surface.frameOrigin,
    risk: "",
    dataAccess: "",
    approvalTicket: "",
    observedAt: observedAt || "",
    injectedAfterLoad,
    allowlisted
  };
}

function mergeScriptInventoryRow(target, source) {
  if (target.authorized !== false && source.authorized === false) {
    target.authorized = false;
    target.allowlisted = false;
  }
  if (target.authorized === "" && source.authorized === true) {
    target.authorized = true;
    target.allowlisted = true;
  }
  target.injectedAfterLoad = target.injectedAfterLoad || source.injectedAfterLoad;
  if (!target.observedAt && source.observedAt) target.observedAt = source.observedAt;
  for (const field of ["checkoutSurface", "frameContext", "frameOwner", "parentPageHref", "frameHref", "frameOrigin"]) {
    if (!target[field] && source[field]) target[field] = source[field];
  }
}

function collectInventorySnapshots(value, output = []) {
  if (value == null) return output;
  if (typeof value === "string") {
    const parsed = parseMaybeJsonString(value);
    if (parsed !== undefined) collectInventorySnapshots(parsed, output);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectInventorySnapshots(item, output);
    return output;
  }
  if (typeof value !== "object") return output;

  if (Array.isArray(value.scripts)) {
    output.push(value);
  }

  for (const key of ["snapshot", "payload", "event", "body", "data", "PayloadJson", "payloadJson", "payloadJSON"]) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      collectInventorySnapshots(value[key], output);
    }
  }
  for (const key of ["snapshots", "events", "incidents", "items"]) {
    if (Array.isArray(value[key])) {
      collectInventorySnapshots(value[key], output);
    }
  }
  return output;
}

function normalizeAuthorizationValue(value) {
  if (value === undefined || value === null || value === "") return "";
  return boolishTrue(value);
}

function normalizeSha256(value) {
  const text = stringOrNull(value);
  if (!text) return null;
  const match = text.match(/(?:sha256-)?([a-f0-9]{32,128}|[A-Za-z0-9+/=_-]{32,128})/);
  return match ? match[1] : null;
}

function categorizePaymentScriptSource(source, pageHref, inline) {
  if (inline || String(source || "").startsWith("inline:")) return "inline";
  const text = String(source || "").trim();
  if (!/^https?:\/\//i.test(text)) return "first-party";
  try {
    const srcUrl = new URL(text);
    if (pageHref && /^https?:\/\//i.test(pageHref)) {
      const pageUrl = new URL(pageHref);
      if (srcUrl.origin === pageUrl.origin) return "first-party";
    }
  } catch (error) {
    return "third-party";
  }
  return "third-party";
}

function buildSurfaceContext(record, fallback = {}) {
  record = record && typeof record === "object" ? record : {};
  fallback = fallback && typeof fallback === "object" ? fallback : {};
  return {
    pageHref: surfaceText(fallback.pageHref),
    checkoutSurface: surfaceText(firstReportValue(record, "checkoutSurface", "CheckoutSurface", "paymentSurface", "PaymentSurface", "surface", "Surface")) || surfaceText(fallback.checkoutSurface),
    frameContext: surfaceText(firstReportValue(record, "frameContext", "FrameContext", "frameRole", "FrameRole", "frame", "Frame")) || surfaceText(fallback.frameContext),
    frameOwner: surfaceText(firstReportValue(record, "frameOwner", "FrameOwner", "iframeOwner", "IframeOwner")) || surfaceText(fallback.frameOwner),
    parentPageHref: surfaceText(firstReportValue(record, "parentPageHref", "ParentPageHref", "parentHref", "ParentHref")) || surfaceText(fallback.parentPageHref),
    frameHref: surfaceText(firstReportValue(record, "frameHref", "FrameHref", "iframeHref", "IframeHref")) || surfaceText(fallback.frameHref),
    frameOrigin: surfaceText(firstReportValue(record, "frameOrigin", "FrameOrigin", "iframeOrigin", "IframeOrigin")) || surfaceText(fallback.frameOrigin)
  };
}

function surfaceText(value) {
  const text = stringOrNull(value);
  return text || "";
}

function writeScriptInventoryFromSnapshotReport(report, outputPath) {
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (!outputPath) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(outputPath);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`script inventory written: ${resolvedPath}\n`);
}

const PAYMENT_PAGE_SECURITY_HEADER_NAMES = [
  "content-security-policy",
  "content-security-policy-report-only",
  "strict-transport-security",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "reporting-endpoints",
  "nel",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cross-origin-embedder-policy"
];

function buildPaymentPageHeadersFromHar(harPath, options = {}) {
  if (!harPath) {
    throw new Error("--payment-page-headers-from-har requires a browser HAR file.");
  }
  const resolvedPath = path.resolve(harPath);
  const sourceText = readTextFile(resolvedPath, "payment-page HAR");
  const payload = parseJsonText(sourceText, `payment-page HAR ${resolvedPath}`);
  const entries = payload && payload.log && Array.isArray(payload.log.entries)
    ? payload.log.entries
    : null;
  if (!entries) {
    throw new Error(`payment-page HAR ${resolvedPath} must include log.entries[].`);
  }

  const urlPattern = options.urlPattern ? buildPaymentPageUrlPattern(options.urlPattern) : null;
  const pages = [];
  for (const entry of entries) {
    const row = paymentPageHeaderRowFromHarEntry(entry, urlPattern);
    if (row) pages.push(row);
  }
  if (pages.length === 0) {
    throw new Error("payment-page HAR did not contain matching document or iframe HTML responses.");
  }
  const baseline = options.baselinePath ? readPaymentPageHeaderBaseline(options.baselinePath) : null;
  const baselineSummary = baseline ? applyPaymentPageHeaderBaseline(pages, baseline.pages) : null;
  const summary = summarizePaymentPageHeaderRows(pages);

  return {
    format: "jso-payment-page-security-headers",
    version: 1,
    sourceFree: true,
    generatedUtc: new Date().toISOString(),
    generatedBy: "jso-protector --payment-page-headers-from-har",
    source: {
      file: path.basename(resolvedPath),
      sha256: sha256(sourceText),
      urlPattern: options.urlPattern || null,
      baselineFile: baseline ? path.basename(baseline.path) : null,
      baselineSha256: baseline ? baseline.sha256 : null
    },
    baseline: baseline ? Object.assign({
      source: path.basename(baseline.path),
      sourceSha256: baseline.sha256
    }, baselineSummary) : null,
    summary,
    reviewAssistant: buildPaymentPageHeaderReviewAssistant(summary),
    pages
  };
}

function buildPaymentPageUrlPattern(pattern) {
  try {
    return new RegExp(pattern);
  } catch (error) {
    throw new Error(`--payment-page-url-pattern is not a valid regular expression: ${error.message}`);
  }
}

function paymentPageHeaderRowFromHarEntry(entry, urlPattern) {
  entry = entry && typeof entry === "object" ? entry : {};
  const request = entry.request && typeof entry.request === "object" ? entry.request : {};
  const response = entry.response && typeof entry.response === "object" ? entry.response : {};
  const pageUrl = stringOrNull(firstReportValue(request, "url", "Url", "URL")) || stringOrNull(firstReportValue(entry, "url", "Url", "URL"));
  if (!pageUrl) return null;
  if (urlPattern && !urlPattern.test(pageUrl)) return null;

  const headers = normalizeHarHeaders(response.headers);
  const contentType = headers["content-type"] || stringOrNull(response.content && response.content.mimeType);
  const resourceType = stringOrNull(firstReportValue(entry, "_resourceType", "resourceType", "type")).toLowerCase();
  if (!isPaymentPageHarDocument(contentType, resourceType)) return null;

  const selectedHeaders = selectPaymentPageSecurityHeaders(headers);
  const observedUtc = stringOrNull(firstReportValue(entry, "startedDateTime", "time", "timestamp"));
  return {
    pageUrl,
    statusCode: response.status == null ? "" : String(response.status),
    observedUtc,
    checkoutSurface: "",
    frameContext: resourceType === "iframe" ? "iframe" : "parent-page",
    frameOwner: "",
    headers: selectedHeaders,
    headerSha256: sha256(canonicalHeaderSnapshot(selectedHeaders)),
    baselineSha256: "",
    matchesBaseline: "",
    monitor: "browser-har",
    alertRoute: ""
  };
}

function normalizeHarHeaders(headers) {
  const out = {};
  if (!Array.isArray(headers)) return out;
  for (const header of headers) {
    if (!header || typeof header !== "object") continue;
    const name = normalizeHeaderName(firstReportValue(header, "name", "Name"));
    const value = stringOrNull(firstReportValue(header, "value", "Value"));
    if (!name || !value) continue;
    out[name] = out[name] ? `${out[name]}, ${value}` : value;
  }
  return out;
}

function selectPaymentPageSecurityHeaders(headers) {
  const selected = {};
  for (const name of PAYMENT_PAGE_SECURITY_HEADER_NAMES) {
    if (headers[name]) selected[name] = headers[name];
  }
  return selected;
}

function canonicalHeaderSnapshot(headers) {
  const keys = Object.keys(headers || {}).sort();
  return JSON.stringify(keys.map((key) => [key, headers[key]]));
}

function normalizeHeaderName(value) {
  return stringOrNull(value).toLowerCase().replace(/_/g, "-");
}

function isPaymentPageHarDocument(contentType, resourceType) {
  if (resourceType === "document" || resourceType === "iframe") return true;
  const ct = stringOrNull(contentType).toLowerCase();
  return /\b(text\/html|application\/xhtml\+xml)\b/.test(ct);
}

function summarizePaymentPageHeaderRows(pages) {
  const domains = Array.from(new Set(pages.map((page) => {
    try {
      return new URL(page.pageUrl).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }).filter(Boolean))).sort();
  return {
    pages: pages.length,
    withCsp: pages.filter((page) => !!page.headers["content-security-policy"]).length,
    withReportOnlyCsp: pages.filter((page) => !!page.headers["content-security-policy-report-only"]).length,
    withScriptSrc: pages.filter((page) => paymentPageHeaderCspHasDirective(page.headers, ["script-src", "script-src-elem", "default-src"])).length,
    withFrameSrc: pages.filter((page) => paymentPageHeaderCspHasDirective(page.headers, ["frame-src", "child-src"])).length,
    withHsts: pages.filter((page) => !!page.headers["strict-transport-security"]).length,
    withReportEndpoint: pages.filter((page) => hasPaymentPageHeaderReportEndpoint(page.headers)).length,
    baselineKnown: pages.filter((page) => !!page.baselineSha256).length,
    baselineMatches: pages.filter((page) => page.matchesBaseline === "match").length,
    baselineMismatches: pages.filter((page) => page.matchesBaseline === "mismatch").length,
    baselineMissing: pages.filter((page) => page.matchesBaseline === "missing").length,
    domains: domains.slice(0, 20)
  };
}

function paymentPageHeaderCspHasDirective(headers, directives) {
  headers = headers || {};
  const csp = `${headers["content-security-policy"] || ""};${headers["content-security-policy-report-only"] || ""}`.toLowerCase();
  if (!csp) return false;
  return directives.some((directive) => {
    const escaped = directive.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
    return new RegExp(`(^|;)\\s*${escaped}\\b`).test(csp);
  });
}

function buildPaymentPageHeaderReviewAssistant(summary) {
  summary = summary || {};
  const pageCount = summary.pages || 0;
  const questions = [];
  if ((summary.baselineMismatches || 0) > 0 || (summary.baselineMissing || 0) > 0) {
    questions.push({
      topic: "Baseline drift",
      prompt: "Identify each checkout page or frame whose security-header snapshot changed or is missing from the approved baseline. Confirm whether the change maps to an approved release, provider update, or required rollback.",
      ownerAction: "Attach the release ticket, provider notice, or remediation owner before reviewer handoff."
    });
  }
  if (pageCount > 0 && (summary.withCsp || 0) < pageCount) {
    questions.push({
      topic: "CSP coverage",
      prompt: "List every checkout page or frame without an enforced Content-Security-Policy header and decide whether a report-only phase, provider constraint, or missing deployment step explains the gap.",
      ownerAction: "Name the checkout owner and target date for enforced CSP coverage."
    });
  }
  if (pageCount > 0 && (summary.withScriptSrc || 0) < pageCount) {
    questions.push({
      topic: "Script policy",
      prompt: "Review pages or frames without script-src, script-src-elem, or default-src coverage. Confirm how payment-page script loading is constrained for those surfaces.",
      ownerAction: "Record the approved script-loading policy or add a CSP directive before release approval."
    });
  }
  if (pageCount > 0 && (summary.withFrameSrc || 0) < pageCount) {
    questions.push({
      topic: "Frame policy",
      prompt: "Review pages or frames without frame-src or child-src coverage. Confirm hosted checkout, PSP iframe, wallet frame, and embedded payment-frame boundaries are intentional.",
      ownerAction: "Document the approved frame providers or tighten the frame directive."
    });
  }
  if (pageCount > 0 && (summary.withReportEndpoint || 0) < pageCount) {
    questions.push({
      topic: "CSP reporting",
      prompt: "Find checkout pages or frames without report-uri, report-to, Reporting-Endpoints, or NEL coverage. Decide where CSP/header violations should be routed.",
      ownerAction: "Wire the missing reporting endpoint or record why the surface is intentionally monitor-only."
    });
  }
  if (pageCount > 0 && (summary.withHsts || 0) < pageCount) {
    questions.push({
      topic: "HSTS coverage",
      prompt: "Identify checkout hosts without Strict-Transport-Security in the snapshot and confirm whether HTTPS enforcement is handled upstream or missing from the response.",
      ownerAction: "Attach the platform or CDN control evidence, or add HSTS before release approval."
    });
  }
  if (questions.length === 0) {
    questions.push({
      topic: "Clean review",
      prompt: "Confirm the approved security-header baseline still matches the checkout scope, CSP reporting reaches the right owner, and the snapshot is ready for PCI evidence handoff.",
      ownerAction: "Attach this source-free packet next to the header snapshot and release evidence."
    });
  }

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to triage payment-page security-header evidence without sending source code, cookies, raw response headers, or secrets.",
    reviewerPrompt: "Review this JSO payment-page security-header packet. Use only the source-free summary, domains, baseline states, header-presence counts, frame context, monitor, and alert-route fields. Produce checkout-owner actions for baseline drift, CSP/reporting, HSTS, and frame-policy gaps without claiming this replaces a QSA assessment.",
    safeInputs: [
      "summary counts",
      "page domains",
      "baseline match, mismatch, and missing counts",
      "checkout surface, iframe context, and frame owner metadata",
      "CSP, reporting, HSTS, frame-policy, monitor, and alert-route coverage counts",
      "header snapshot SHA-256 values"
    ],
    doNotInclude: [
      "raw response headers",
      "cookies",
      "authorization headers",
      "raw source code",
      "payment-card data",
      "customer personal data",
      "provider API keys",
      "collector tokens",
      "session tokens or secrets"
    ],
    questions
  };
}

function readPaymentPageHeaderBaseline(baselinePath) {
  const resolvedPath = path.resolve(baselinePath);
  const sourceText = readTextFile(resolvedPath, "payment-page security-header baseline");
  const payload = parseJsonText(sourceText, `payment-page security-header baseline ${resolvedPath}`);
  const pages = Array.isArray(payload)
    ? payload
    : (payload && Array.isArray(payload.pages) ? payload.pages : null);
  if (!pages) {
    throw new Error(`payment-page security-header baseline ${resolvedPath} must include pages[].`);
  }
  return {
    path: resolvedPath,
    sha256: sha256(sourceText),
    pages
  };
}

function applyPaymentPageHeaderBaseline(pages, baselinePages) {
  const index = new Map();
  for (const page of baselinePages || []) {
    const key = paymentPageHeaderBaselineKey(page);
    if (!key) continue;
    const headerSha256 = stringOrNull(firstReportValue(page, "headerSha256", "HeaderSha256", "headersSha256", "snapshotSha256"));
    const headers = page && typeof page === "object" && page.headers && typeof page.headers === "object" ? page.headers : null;
    index.set(key, headerSha256 || sha256(canonicalHeaderSnapshot(selectPaymentPageSecurityHeaders(normalizeBaselineHeaderObject(headers)))));
  }

  let matched = 0;
  let mismatched = 0;
  let missing = 0;
  for (const page of pages) {
    const key = paymentPageHeaderBaselineKey(page);
    const baselineSha256 = key ? index.get(key) : "";
    if (!baselineSha256) {
      page.baselineSha256 = "";
      page.matchesBaseline = "missing";
      missing += 1;
      continue;
    }
    page.baselineSha256 = baselineSha256;
    if (page.headerSha256 === baselineSha256) {
      page.matchesBaseline = "match";
      matched += 1;
    } else {
      page.matchesBaseline = "mismatch";
      mismatched += 1;
    }
  }

  return {
    baselinePages: index.size,
    matchedPages: matched,
    mismatchedPages: mismatched,
    missingPages: missing
  };
}

function paymentPageHeaderBaselineKey(page) {
  page = page && typeof page === "object" ? page : {};
  const pageUrl = stringOrNull(firstReportValue(page, "pageUrl", "PageUrl", "url", "URL"));
  if (!pageUrl) return "";
  const frameContext = stringOrNull(firstReportValue(page, "frameContext", "FrameContext", "frame", "Frame")).toLowerCase();
  return `${pageUrl}\n${frameContext}`;
}

function normalizeBaselineHeaderObject(headers) {
  const normalized = {};
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return normalized;
  for (const key of Object.keys(headers)) {
    const name = normalizeHeaderName(key);
    const value = stringOrNull(headers[key]);
    if (name && value) normalized[name] = value;
  }
  return normalized;
}

function hasPaymentPageHeaderReportEndpoint(headers) {
  headers = headers || {};
  if (headers["reporting-endpoints"] || headers.nel) return true;
  const csp = `${headers["content-security-policy"] || ""};${headers["content-security-policy-report-only"] || ""}`.toLowerCase();
  return /(^|;)\s*(report-uri|report-to)\b/.test(csp);
}

function writePaymentPageHeadersFromHarReport(report, outputPath) {
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (!outputPath) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(outputPath);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`payment-page security headers written: ${resolvedPath}\n`);
}

function buildScriptInventoryAudit(inventoryPath, snapshotPath, options = {}) {
  if (!inventoryPath) {
    throw new Error("--script-inventory-audit requires an approved script inventory file.");
  }
  if (!snapshotPath) {
    throw new Error("--script-inventory-audit requires --runtime-inventory-snapshot <file>.");
  }

  const inventory = readPaymentScriptInventory(inventoryPath);
  const runtime = readRuntimeInventorySnapshot(snapshotPath);
  const approvedByKey = new Map();
  const duplicateApproved = [];

  for (const row of inventory.scripts) {
    if (!row.key) continue;
    if (approvedByKey.has(row.key)) {
      duplicateApproved.push({
        source: row.source,
        firstSource: approvedByKey.get(row.key).source
      });
      continue;
    }
    approvedByKey.set(row.key, row);
  }

  const unknownObserved = [];
  const unauthorizedObserved = [];
  const integrityMismatches = [];
  const observedWithoutIntegrityReference = [];
  const injectedAfterLoad = [];
  const runtimeViolations = [];

  for (const observed of runtime.scripts) {
    const approved = approvedByKey.get(observed.key);
    if (!approved) {
      unknownObserved.push(observedIssueRow(observed, "Observed script is not present in the approved inventory."));
    } else {
      if (approved.authorization !== "authorized") {
        unauthorizedObserved.push(Object.assign(
          observedIssueRow(observed, "Observed script is not marked authorized in the approved inventory."),
          { authorization: approved.authorization }
        ));
      }
      if (approved.integritySha256 && observed.sha256 && approved.integritySha256 !== observed.sha256) {
        integrityMismatches.push(Object.assign(
          observedIssueRow(observed, "Observed SHA-256 does not match the approved integrity reference."),
          {
            approvedSha256: approved.integritySha256,
            observedSha256: observed.sha256
          }
        ));
      }
      if (approved.authorization === "authorized" && !approved.integrity && observed.sha256) {
        observedWithoutIntegrityReference.push(Object.assign(
          observedIssueRow(observed, "Authorized script was observed with a hash, but the approved inventory has no integrity reference."),
          { observedSha256: observed.sha256 }
        ));
      }
    }
    if (observed.injectedAfterLoad) {
      injectedAfterLoad.push(observedIssueRow(observed, "Script was injected after page load."));
    }
    if (observed.reasons.length > 0) {
      runtimeViolations.push(Object.assign(
        observedIssueRow(observed, "Runtime snapshot already classified this script as a violation."),
        { reasons: observed.reasons }
      ));
    }
  }

  const missingApproved = [];
  const inventoryGaps = [];
  const reviewMetadataGaps = [];
  const approvedCheckoutSurfaces = countValueOccurrences(inventory.scripts, "checkoutSurface");
  const approvedFrameContexts = countValueOccurrences(inventory.scripts, "frameContext");
  const approvedFrameOwners = countValueOccurrences(inventory.scripts, "frameOwner");
  const observedCheckoutSurfaces = countValueOccurrences(runtime.scripts, "checkoutSurfaces");
  const observedFrameContexts = countValueOccurrences(runtime.scripts, "frameContexts");
  const observedFrameOwners = countValueOccurrences(runtime.scripts, "frameOwners");
  const approvedIframeScopedScripts = countIframeScopedRows(inventory.scripts);
  const observedIframeScopedScripts = countIframeScopedRows(runtime.scripts);
  let authorizedApprovedScripts = 0;
  let withRiskRating = 0;
  let withDataAccess = 0;
  let withApprovalTicket = 0;
  let missingRiskRating = 0;
  let missingDataAccess = 0;
  let missingApprovalTicket = 0;
  for (const approved of inventory.scripts) {
    if (approved.authorization === "authorized" && !runtime.byKey.has(approved.key)) {
      missingApproved.push(approvedIssueRow(approved, "Approved script was not observed in the runtime snapshot."));
    }
    if (approved.authorization === "authorized") {
      authorizedApprovedScripts += 1;
      const missingReviewMetadata = [];
      if (approved.risk) {
        withRiskRating += 1;
      } else {
        missingRiskRating += 1;
        missingReviewMetadata.push("risk");
      }
      if (approved.dataAccess) {
        withDataAccess += 1;
      } else {
        missingDataAccess += 1;
        missingReviewMetadata.push("dataAccess");
      }
      if (approved.approvalTicket) {
        withApprovalTicket += 1;
      } else {
        missingApprovalTicket += 1;
        missingReviewMetadata.push("approvalTicket");
      }
      if (missingReviewMetadata.length) {
        reviewMetadataGaps.push(Object.assign(
          approvedIssueRow(approved, "Authorized inventory row is missing optional review context."),
          { missing: missingReviewMetadata }
        ));
      }
    }
    const gapReasons = [];
    if (approved.authorization === "unknown") gapReasons.push("authorization");
    if (approved.authorization === "authorized" && !approved.justification) gapReasons.push("justification");
    if (approved.authorization === "authorized" && !approved.owner) gapReasons.push("owner");
    if (approved.authorization === "authorized" && !approved.lastReviewedUtc) gapReasons.push("lastReviewedUtc");
    if (approved.authorization === "authorized" && !approved.integrity) gapReasons.push("integrity");
    if (gapReasons.length) {
      inventoryGaps.push(Object.assign(
        approvedIssueRow(approved, "Approved inventory row is missing audit metadata."),
        { missing: gapReasons }
      ));
    }
  }

  const blockingIssueCount =
    unknownObserved.length +
    unauthorizedObserved.length +
    integrityMismatches.length +
    missingApproved.length +
    injectedAfterLoad.length +
    runtimeViolations.length +
    inventoryGaps.length +
    duplicateApproved.length;

  const summary = {
    approvedScripts: inventory.scripts.length,
    observedScripts: runtime.scripts.length,
    unknownObserved: unknownObserved.length,
    unauthorizedObserved: unauthorizedObserved.length,
    integrityMismatches: integrityMismatches.length,
    missingApproved: missingApproved.length,
    injectedAfterLoad: injectedAfterLoad.length,
    runtimeViolations: runtimeViolations.length,
    observedWithoutIntegrityReference: observedWithoutIntegrityReference.length,
    inventoryGaps: inventoryGaps.length,
    duplicateApproved: duplicateApproved.length,
    authorizedApprovedScripts,
    withRiskRating,
    withDataAccess,
    withApprovalTicket,
    missingRiskRating,
    missingDataAccess,
    missingApprovalTicket,
    reviewMetadataGaps: reviewMetadataGaps.length,
    approvedCheckoutSurfaces,
    observedCheckoutSurfaces,
    approvedFrameContexts,
    observedFrameContexts,
    approvedFrameOwners,
    observedFrameOwners,
    approvedIframeScopedScripts,
    observedIframeScopedScripts,
    blockingIssues: blockingIssueCount
  };

  const checklist = [
    {
      name: "approved-inventory",
      required: true,
      ok: inventory.scripts.length > 0,
      message: inventory.scripts.length + " approved inventory row(s) loaded."
    },
    {
      name: "runtime-snapshot",
      required: true,
      ok: runtime.scripts.length > 0,
      message: runtime.scripts.length + " observed runtime script(s) loaded from " + runtime.snapshotCount + " snapshot(s)."
    },
    {
      name: "unknown-observed",
      required: true,
      ok: unknownObserved.length === 0,
      message: unknownObserved.length === 0 ? "No observed script is missing from the approved inventory." : unknownObserved.length + " observed script(s) are not approved."
    },
    {
      name: "unauthorized-observed",
      required: true,
      ok: unauthorizedObserved.length === 0,
      message: unauthorizedObserved.length === 0 ? "No observed script is marked unauthorized or unknown." : unauthorizedObserved.length + " observed script(s) need authorization review."
    },
    {
      name: "integrity-match",
      required: true,
      ok: integrityMismatches.length === 0,
      message: integrityMismatches.length === 0 ? "Observed script hashes match approved integrity references where both are available." : integrityMismatches.length + " observed script hash(es) differ from approved references."
    },
    {
      name: "missing-approved",
      required: true,
      ok: missingApproved.length === 0,
      message: missingApproved.length === 0 ? "Every authorized inventory row was observed." : missingApproved.length + " authorized script(s) were not observed."
    },
    {
      name: "late-injection",
      required: true,
      ok: injectedAfterLoad.length === 0,
      message: injectedAfterLoad.length === 0 ? "No observed external script was injected after page load." : injectedAfterLoad.length + " observed script(s) were injected after page load."
    },
    {
      name: "runtime-violations",
      required: true,
      ok: runtimeViolations.length === 0,
      message: runtimeViolations.length === 0 ? "Runtime snapshot did not contain violation rows." : runtimeViolations.length + " observed script(s) have runtime violation reasons."
    },
    {
      name: "inventory-metadata",
      required: true,
      ok: inventoryGaps.length === 0 && duplicateApproved.length === 0,
      message: inventoryGaps.length === 0 && duplicateApproved.length === 0
        ? "Approved inventory rows include authorization, justification, owner, review date, and integrity references."
        : (inventoryGaps.length + " inventory metadata gap(s), " + duplicateApproved.length + " duplicate row(s).")
    },
    {
      name: "review-context",
      required: false,
      ok: reviewMetadataGaps.length === 0,
      message: reviewMetadataGaps.length === 0
        ? "Authorized inventory rows include risk, data-access, approval-ticket, and optional checkout-surface context where available."
        : reviewMetadataGaps.length + " authorized inventory row(s) are missing optional risk, data-access, or approval-ticket context."
    },
    {
      name: "checkout-surface-context",
      required: false,
      ok: Object.keys(approvedFrameContexts).length > 0 || Object.keys(observedFrameContexts).length > 0,
      message: (Object.keys(approvedFrameContexts).length > 0 || Object.keys(observedFrameContexts).length > 0)
        ? "Inventory or runtime evidence includes checkout frame context for hosted, parent-page, or iframe review."
        : "No checkout frame context was supplied; add checkoutSurface/frameContext when iframe or PSP evidence needs a clearer boundary."
    }
  ];

  const generatedAt = options.generatedAt || new Date().toISOString();
  return {
    format: "jso-payment-script-inventory-audit",
    version: 1,
    sourceFree: true,
    generatedAt,
    generatedBy: "jso-protector --script-inventory-audit",
    ok: blockingIssueCount === 0,
    approvedInventory: {
      source: path.basename(inventory.resolvedPath),
      sourceFormat: inventory.sourceFormat,
      sourceSha256: inventory.sourceSha256
    },
    runtimeSnapshot: {
      source: path.basename(runtime.resolvedPath),
      sourceSha256: runtime.sourceSha256,
      snapshotCount: runtime.snapshotCount,
      buildIds: runtime.buildIds,
      pageHrefs: runtime.pageHrefs
    },
    summary,
    checklist,
    findings: {
      unknownObserved,
      unauthorizedObserved,
      integrityMismatches,
      missingApproved,
      injectedAfterLoad,
      runtimeViolations,
      observedWithoutIntegrityReference,
      inventoryGaps,
      duplicateApproved,
      reviewMetadataGaps
    },
    reviewAssistant: buildScriptInventoryReviewAssistant(summary),
    recommendations: buildScriptInventoryAuditRecommendations(summary)
  };
}

function readPaymentScriptInventory(inventoryPath) {
  const resolvedPath = path.resolve(inventoryPath);
  const sourceText = readTextFile(resolvedPath, "payment-page script inventory");
  const trimmed = sourceText.trimStart();
  let rows;
  let sourceFormat;
  if (/\.json$/i.test(resolvedPath) || trimmed[0] === "{") {
    const payload = parseJsonText(sourceText, `payment-page script inventory ${resolvedPath}`);
    rows = payload && typeof payload === "object"
      ? (payload.scripts || payload.inventory || payload.items)
      : null;
    if (!Array.isArray(rows)) {
      throw new Error(`payment-page script inventory ${resolvedPath} must include scripts[].`);
    }
    sourceFormat = "json";
  } else {
    rows = parseScriptInventoryCsv(sourceText, resolvedPath);
    sourceFormat = "csv";
  }
  const scripts = rows
    .map(normalizeAuditInventoryRow)
    .filter((row) => row.source);
  if (scripts.length === 0) {
    throw new Error(`payment-page script inventory ${resolvedPath} did not contain script rows.`);
  }
  return {
    resolvedPath,
    sourceFormat,
    sourceSha256: sha256(sourceText),
    scripts
  };
}

function readRuntimeInventorySnapshot(snapshotPath) {
  const resolvedPath = path.resolve(snapshotPath);
  const sourceText = readTextFile(resolvedPath, "third-party-inventory runtime snapshot");
  const payload = parseJsonText(sourceText, `third-party-inventory runtime snapshot ${resolvedPath}`);
  const snapshots = collectInventorySnapshots(payload);
  if (snapshots.length === 0) {
    throw new Error(`third-party-inventory runtime snapshot ${resolvedPath} must include a scripts array.`);
  }

  const byKey = new Map();
  const buildIds = new Set();
  const pageHrefs = new Set();
  for (const snapshot of snapshots) {
    const buildId = stringOrNull(firstReportValue(snapshot, "buildId", "BuildId", "buildID"));
    const pageHref = stringOrNull(firstReportValue(snapshot, "pageHref", "PageHref", "url", "href"));
    const surfaceContext = buildSurfaceContext(snapshot, { pageHref });
    if (buildId) buildIds.add(buildId);
    if (pageHref) pageHrefs.add(pageHref);

    for (const item of snapshot.scripts || []) {
      addObservedAuditScript(byKey, normalizeObservedAuditScript(item, {
        buildId,
        pageHref,
        surfaceContext,
        violationReason: null
      }));
    }
    for (const violation of snapshot.violations || []) {
      addObservedAuditScript(byKey, normalizeObservedAuditScript(violation, {
        buildId,
        pageHref,
        surfaceContext,
        violationReason: stringOrNull(firstReportValue(violation, "reason", "Reason"))
      }));
    }
  }

  return {
    resolvedPath,
    sourceSha256: sha256(sourceText),
    snapshotCount: snapshots.length,
    buildIds: Array.from(buildIds).sort(),
    pageHrefs: Array.from(pageHrefs).sort(),
    byKey,
    scripts: Array.from(byKey.values()).map(finalizeObservedAuditScript).sort(compareBySource)
  };
}

function normalizeAuditInventoryRow(row) {
  row = row && typeof row === "object" ? row : {};
  const source = normalizeAuditCell(firstReportValue(row, "Source", "source", "Src", "src", "Url", "URL", "url"));
  const integrity = normalizeAuditCell(firstReportValue(row, "Integrity", "integrity", "Sri", "SRI", "sri", "Sha256", "sha256", "Hash", "hash"));
  const integritySha256 = normalizeSha256(integrity);
  const key = normalizeScriptAuditKey(source);
  return {
    source,
    key,
    authorization: auditAuthorizationState(firstReportValue(row, "Authorized", "authorized", "Approved", "approved", "Status", "status")),
    justification: normalizeAuditCell(firstReportValue(row, "Justification", "justification", "Reason", "reason", "BusinessJustification", "businessJustification")),
    owner: normalizeAuditCell(firstReportValue(row, "Owner", "owner", "Team", "team")),
    category: normalizeAuditCell(firstReportValue(row, "Category", "category", "Type", "type")),
    integrity,
    integritySha256,
    lastReviewedUtc: normalizeAuditCell(firstReportValue(row, "LastReviewedUtc", "lastReviewedUtc", "LastReviewed", "lastReviewed", "ReviewedUtc", "reviewedUtc")),
    checkoutSurface: normalizeAuditCell(firstReportValue(row, "CheckoutSurface", "checkoutSurface", "PaymentSurface", "paymentSurface", "Surface", "surface")),
    frameContext: normalizeAuditCell(firstReportValue(row, "FrameContext", "frameContext", "FrameRole", "frameRole", "Frame", "frame")),
    frameOwner: normalizeAuditCell(firstReportValue(row, "FrameOwner", "frameOwner", "IframeOwner", "iframeOwner")),
    parentPageHref: normalizeAuditCell(firstReportValue(row, "ParentPageHref", "parentPageHref", "ParentHref", "parentHref")),
    frameHref: normalizeAuditCell(firstReportValue(row, "FrameHref", "frameHref", "IframeHref", "iframeHref")),
    frameOrigin: normalizeAuditCell(firstReportValue(row, "FrameOrigin", "frameOrigin", "IframeOrigin", "iframeOrigin")),
    risk: normalizeAuditCell(firstReportValue(row, "Risk", "risk", "RiskRating", "riskRating", "RiskLevel", "riskLevel")),
    dataAccess: normalizeAuditCell(firstReportValue(row, "DataAccess", "dataAccess", "DataAccessScope", "dataAccessScope", "DataCategory", "dataCategory", "SensitiveDataAccess", "sensitiveDataAccess")),
    approvalTicket: normalizeAuditCell(firstReportValue(row, "ApprovalTicket", "approvalTicket", "Ticket", "ticket", "ChangeTicket", "changeTicket", "ApprovalId", "approvalId"))
  };
}

function normalizeObservedAuditScript(record, context) {
  if (!record || typeof record !== "object") return null;
  const src = normalizeAuditCell(firstReportValue(record, "src", "source", "Source", "url", "Url", "href"));
  const sha = normalizeSha256(firstReportValue(record, "sha256", "hash", "contentSha256", "integrity"));
  const inline = boolishTrue(firstReportValue(record, "inline", "isInline")) || !src;
  const source = src || (sha ? `inline:sha256-${sha}` : "inline:unknown");
  const key = normalizeScriptAuditKey(source);
  if (!key) return null;
  const observedAt = normalizeAuditCell(firstReportValue(record, "observedAt", "firstSeenUtc", "timestamp", "createdUtc"));
  const reason = context.violationReason;
  const surface = buildSurfaceContext(record, context.surfaceContext || { pageHref: context.pageHref });
  return {
    source,
    key,
    sha256: sha || "",
    inline,
    allowlisted: normalizeObservedAllowlisted(firstReportValue(record, "allowlisted", "allowed", "authorized")),
    injectedAfterLoad: boolishTrue(firstReportValue(record, "injectedAfterLoad", "lateInjected", "injected")) || reason === "injected-after-load",
    observedAt,
    buildId: context.buildId || "",
    pageHref: context.pageHref || "",
    checkoutSurface: surface.checkoutSurface,
    frameContext: surface.frameContext,
    frameOwner: surface.frameOwner,
    parentPageHref: surface.parentPageHref,
    frameHref: surface.frameHref,
    frameOrigin: surface.frameOrigin,
    reasons: reason ? [reason] : []
  };
}

function addObservedAuditScript(byKey, row) {
  if (!row) return;
  const existing = byKey.get(row.key);
  if (!existing) {
    byKey.set(row.key, {
      source: row.source,
      key: row.key,
      sha256: row.sha256,
      inline: row.inline,
      allowlisted: row.allowlisted,
      injectedAfterLoad: row.injectedAfterLoad,
      observedAtValues: row.observedAt ? [row.observedAt] : [],
      buildIds: row.buildId ? new Set([row.buildId]) : new Set(),
      pageHrefs: row.pageHref ? new Set([row.pageHref]) : new Set(),
      checkoutSurfaces: row.checkoutSurface ? new Set([row.checkoutSurface]) : new Set(),
      frameContexts: row.frameContext ? new Set([row.frameContext]) : new Set(),
      frameOwners: row.frameOwner ? new Set([row.frameOwner]) : new Set(),
      parentPageHrefs: row.parentPageHref ? new Set([row.parentPageHref]) : new Set(),
      frameHrefs: row.frameHref ? new Set([row.frameHref]) : new Set(),
      frameOrigins: row.frameOrigin ? new Set([row.frameOrigin]) : new Set(),
      reasonSet: new Set(row.reasons),
      occurrences: 1
    });
    return;
  }
  existing.occurrences += 1;
  if (!existing.sha256 && row.sha256) existing.sha256 = row.sha256;
  if (existing.sha256 && row.sha256 && existing.sha256 !== row.sha256) {
    existing.reasonSet.add("content-changed-within-snapshot");
  }
  existing.inline = existing.inline && row.inline;
  if (row.allowlisted === false) existing.allowlisted = false;
  if (row.allowlisted === true && existing.allowlisted === null) existing.allowlisted = true;
  existing.injectedAfterLoad = existing.injectedAfterLoad || row.injectedAfterLoad;
  if (row.observedAt) existing.observedAtValues.push(row.observedAt);
  if (row.buildId) existing.buildIds.add(row.buildId);
  if (row.pageHref) existing.pageHrefs.add(row.pageHref);
  if (row.checkoutSurface) existing.checkoutSurfaces.add(row.checkoutSurface);
  if (row.frameContext) existing.frameContexts.add(row.frameContext);
  if (row.frameOwner) existing.frameOwners.add(row.frameOwner);
  if (row.parentPageHref) existing.parentPageHrefs.add(row.parentPageHref);
  if (row.frameHref) existing.frameHrefs.add(row.frameHref);
  if (row.frameOrigin) existing.frameOrigins.add(row.frameOrigin);
  for (const reason of row.reasons) existing.reasonSet.add(reason);
}

function finalizeObservedAuditScript(row) {
  const observedAtValues = row.observedAtValues.slice().sort();
  return {
    source: row.source,
    key: row.key,
    sha256: row.sha256 || "",
    inline: row.inline,
    allowlisted: row.allowlisted,
    injectedAfterLoad: row.injectedAfterLoad,
    firstObservedAt: observedAtValues[0] || "",
    lastObservedAt: observedAtValues[observedAtValues.length - 1] || "",
    buildIds: Array.from(row.buildIds).sort(),
    pageHrefs: Array.from(row.pageHrefs).sort(),
    checkoutSurfaces: Array.from(row.checkoutSurfaces || []).sort(),
    frameContexts: Array.from(row.frameContexts || []).sort(),
    frameOwners: Array.from(row.frameOwners || []).sort(),
    parentPageHrefs: Array.from(row.parentPageHrefs || []).sort(),
    frameHrefs: Array.from(row.frameHrefs || []).sort(),
    frameOrigins: Array.from(row.frameOrigins || []).sort(),
    reasons: Array.from(row.reasonSet).sort(),
    occurrences: row.occurrences
  };
}

function observedIssueRow(row, detail) {
  return {
    source: row.source,
    detail,
    sha256: row.sha256 || "",
    firstObservedAt: row.firstObservedAt || "",
    buildIds: row.buildIds || [],
    pageHrefs: row.pageHrefs || [],
    checkoutSurfaces: row.checkoutSurfaces || [],
    frameContexts: row.frameContexts || [],
    frameOwners: row.frameOwners || [],
    frameHrefs: row.frameHrefs || []
  };
}

function approvedIssueRow(row, detail) {
  return {
    source: row.source,
    detail,
    authorization: row.authorization,
    owner: row.owner,
    lastReviewedUtc: row.lastReviewedUtc,
    integrity: row.integrity,
    checkoutSurface: row.checkoutSurface,
    frameContext: row.frameContext,
    frameOwner: row.frameOwner,
    frameHref: row.frameHref,
    risk: row.risk,
    dataAccess: row.dataAccess,
    approvalTicket: row.approvalTicket
  };
}

function buildScriptInventoryAuditRecommendations(summary) {
  const recommendations = [];
  if (summary.unknownObserved > 0) {
    recommendations.push("Review unknown observed scripts first. Approve them with owner and justification only if they are expected on the payment page.");
  }
  if (summary.unauthorizedObserved > 0) {
    recommendations.push("Resolve scripts that were observed but marked unauthorized or unknown before using the packet as payment-page evidence.");
  }
  if (summary.integrityMismatches > 0) {
    recommendations.push("Investigate hash mismatches as possible third-party content drift or supply-chain compromise.");
  }
  if (summary.injectedAfterLoad > 0) {
    recommendations.push("Review scripts injected after page load; deferred injection is common in skimming and tag-manager abuse.");
  }
  if (summary.missingApproved > 0) {
    recommendations.push("Confirm missing approved scripts are intentionally absent for this checkout path, or split the inventory by page/template.");
  }
  if (summary.inventoryGaps > 0) {
    recommendations.push("Complete inventory metadata before audit handoff: authorization, written justification, owner, review date, and integrity reference.");
  }
  if (summary.reviewMetadataGaps > 0) {
    recommendations.push("Add optional review context for authorized scripts: risk rating, data-access scope, and approval or change ticket.");
  }
  if (Object.keys(summary.approvedFrameContexts || {}).length === 0 && Object.keys(summary.observedFrameContexts || {}).length === 0) {
    recommendations.push("Add checkoutSurface and frameContext values when the payment page uses hosted checkout, parent-page scripts, PSP iframes, or embedded checkout frames.");
  }
  if (summary.observedWithoutIntegrityReference > 0) {
    recommendations.push("Add SRI, provider-managed integrity notes, or deployment hash references for observed authorized scripts.");
  }
  if (recommendations.length === 0) {
    recommendations.push("Attach this audit next to the runtime snapshot and approved inventory in the PCI evidence package.");
  }
  return recommendations;
}

function buildScriptInventoryReviewAssistant(summary) {
  const questions = [];
  if (summary.unknownObserved > 0) {
    questions.push({
      topic: "Unknown observed scripts",
      prompt: "For each unknown observed script, identify the business owner, payment-page purpose, data-access scope, and whether the script should be approved, removed, or escalated."
    });
  }
  if (summary.unauthorizedObserved > 0) {
    questions.push({
      topic: "Unauthorized observed scripts",
      prompt: "For each observed script marked unauthorized or unknown in the approved inventory, confirm whether it is expected on this checkout path and what removal or authorization action is required."
    });
  }
  if (summary.integrityMismatches > 0) {
    questions.push({
      topic: "Integrity mismatches",
      prompt: "For each hash mismatch, decide whether the change is an expected provider update, a deployment drift, or a potential supply-chain incident that needs security review."
    });
  }
  if (summary.injectedAfterLoad > 0 || summary.runtimeViolations > 0) {
    questions.push({
      topic: "Runtime behavior",
      prompt: "Review late-injected scripts and runtime violation reasons. Identify tag-manager, personalization, or skimming-like behavior that needs owner approval or removal."
    });
  }
  if (summary.inventoryGaps > 0 || summary.reviewMetadataGaps > 0) {
    questions.push({
      topic: "Inventory evidence gaps",
      prompt: "List the inventory rows missing authorization, written justification, owner, review date, integrity reference, risk, data-access, or approval-ticket context before reviewer handoff."
    });
  }
  if (summary.approvedIframeScopedScripts > 0 || summary.observedIframeScopedScripts > 0) {
    questions.push({
      topic: "Iframe checkout context",
      prompt: "Confirm which scripts run in the parent page, hosted checkout page, PSP iframe, or embedded payment frame, and whether each owner approves that frame boundary."
    });
  }
  if (summary.missingApproved > 0) {
    questions.push({
      topic: "Missing approved scripts",
      prompt: "Confirm whether approved scripts missing from the runtime snapshot are intentionally absent for this page/template or whether the inventory should be split by checkout path."
    });
  }
  if (questions.length === 0) {
    questions.push({
      topic: "Clean review",
      prompt: "Confirm the approved inventory still matches the payment page scope, the owners are current, and the packet is ready to attach to the PCI evidence handoff."
    });
  }

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to triage payment-page script authorization evidence without sending source code.",
    reviewerPrompt: "Review this JSO payment-page script inventory audit. Use only the source-free inventory metadata, runtime snapshot summary, hashes, URLs, owners, justifications, and findings in the packet. Produce owner actions and reviewer notes without claiming this replaces a QSA assessment.",
    safeInputs: [
      "approved script inventory metadata",
      "runtime inventory summary",
      "script URLs and SHA-256 hashes",
      "checkout surface, iframe context, frame owner, and frame URL metadata",
      "authorization, owner, justification, risk, data-access, and approval-ticket fields",
      "audit findings and recommendations"
    ],
    doNotInclude: [
      "raw source code",
      "payment-card data",
      "customer personal data",
      "provider API keys",
      "session tokens or secrets"
    ],
    questions
  };
}

function renderScriptInventoryAuditMarkdown(report) {
  const out = [];
  out.push("# Payment-Page Script Inventory Audit");
  out.push("");
  out.push("Generated: " + report.generatedAt);
  out.push("Status: " + (report.ok ? "PASS" : "NEEDS REVIEW"));
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push("| Approved inventory | `" + markdownInline(report.approvedInventory.source) + "` |");
  out.push("| Runtime snapshot | `" + markdownInline(report.runtimeSnapshot.source) + "` |");
  out.push("| Approved scripts | " + report.summary.approvedScripts + " |");
  out.push("| Observed scripts | " + report.summary.observedScripts + " |");
  out.push("| Unknown observed | " + report.summary.unknownObserved + " |");
  out.push("| Unauthorized observed | " + report.summary.unauthorizedObserved + " |");
  out.push("| Integrity mismatches | " + report.summary.integrityMismatches + " |");
  out.push("| Missing approved | " + report.summary.missingApproved + " |");
  out.push("| Late injected | " + report.summary.injectedAfterLoad + " |");
  out.push("| Runtime violations | " + report.summary.runtimeViolations + " |");
  out.push("| Inventory metadata gaps | " + report.summary.inventoryGaps + " |");
  out.push("| Review metadata gaps | " + report.summary.reviewMetadataGaps + " |");
  out.push("| Checkout surfaces | " + markdownCell(formatCountObject(report.summary.approvedCheckoutSurfaces)) + " approved / " + markdownCell(formatCountObject(report.summary.observedCheckoutSurfaces)) + " observed |");
  out.push("| Frame contexts | " + markdownCell(formatCountObject(report.summary.approvedFrameContexts)) + " approved / " + markdownCell(formatCountObject(report.summary.observedFrameContexts)) + " observed |");
  out.push("| Iframe-scoped scripts | " + report.summary.approvedIframeScopedScripts + " approved / " + report.summary.observedIframeScopedScripts + " observed |");
  out.push("| Risk ratings | " + report.summary.withRiskRating + " / " + report.summary.authorizedApprovedScripts + " |");
  out.push("| Data-access scopes | " + report.summary.withDataAccess + " / " + report.summary.authorizedApprovedScripts + " |");
  out.push("| Approval tickets | " + report.summary.withApprovalTicket + " / " + report.summary.authorizedApprovedScripts + " |");
  out.push("| Blocking issues | " + report.summary.blockingIssues + " |");
  out.push("");
  out.push("## Checklist");
  out.push("");
  out.push("| Check | Required | Status | Detail |");
  out.push("|---|---|---|---|");
  for (const item of report.checklist) {
    out.push("| " + markdownCell(item.name) + " | " + yesNo(item.required) + " | " + (item.ok ? "PASS" : "REVIEW") + " | " + markdownCell(item.message) + " |");
  }
  out.push("");
  renderAuditFindingSection(out, "Unknown Observed Scripts", report.findings.unknownObserved);
  renderAuditFindingSection(out, "Unauthorized Observed Scripts", report.findings.unauthorizedObserved);
  renderAuditFindingSection(out, "Integrity Mismatches", report.findings.integrityMismatches);
  renderAuditFindingSection(out, "Missing Approved Scripts", report.findings.missingApproved);
  renderAuditFindingSection(out, "Late Injected Scripts", report.findings.injectedAfterLoad);
  renderAuditFindingSection(out, "Runtime Violation Rows", report.findings.runtimeViolations);
  renderAuditFindingSection(out, "Inventory Metadata Gaps", report.findings.inventoryGaps);
  renderAuditFindingSection(out, "Review Metadata Gaps", report.findings.reviewMetadataGaps);
  renderScriptInventoryReviewAssistantSection(out, report.reviewAssistant);
  out.push("## Recommendations");
  out.push("");
  for (const item of report.recommendations) out.push("- " + markdownCell(item));
  out.push("");
  out.push("Generated by `jso-protector --script-inventory-audit`. The report is source-free: it compares an approved payment-page script inventory with a saved runtime `third-party-inventory` snapshot.");
  out.push("");
  return out.join("\n");
}

function renderScriptInventoryReviewAssistantSection(out, assistant) {
  if (!assistant) return;
  out.push("## Review Assistant Packet");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push("- " + markdownCell(item));
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push("- " + markdownCell(item));
  out.push("");
  out.push("| Topic | Question |");
  out.push("|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + markdownCell(item.topic) + " | " + markdownCell(item.prompt) + " |");
  }
  out.push("");
}

function renderAuditFindingSection(out, title, rows) {
  out.push("## " + title);
  out.push("");
  if (!rows || rows.length === 0) {
    out.push("None.");
    out.push("");
    return;
  }
  out.push("| Source | Detail | Evidence |");
  out.push("|---|---|---|");
  for (const row of rows) {
    const evidence = [];
    if (row.authorization) evidence.push("authorization=" + row.authorization);
    if (row.sha256) evidence.push("sha256=" + row.sha256.slice(0, 12) + "...");
    if (row.approvedSha256) evidence.push("approved=" + row.approvedSha256.slice(0, 12) + "...");
    if (row.observedSha256) evidence.push("observed=" + row.observedSha256.slice(0, 12) + "...");
    if (row.missing) evidence.push("missing=" + row.missing.join(","));
    if (row.reasons) evidence.push("reasons=" + row.reasons.join(","));
    if (row.firstObservedAt) evidence.push("firstObservedAt=" + row.firstObservedAt);
    if (row.lastReviewedUtc) evidence.push("lastReviewedUtc=" + row.lastReviewedUtc);
    if (row.checkoutSurface) evidence.push("checkoutSurface=" + row.checkoutSurface);
    if (row.checkoutSurfaces && row.checkoutSurfaces.length) evidence.push("checkoutSurface=" + row.checkoutSurfaces.join(","));
    if (row.frameContext) evidence.push("frameContext=" + row.frameContext);
    if (row.frameContexts && row.frameContexts.length) evidence.push("frameContext=" + row.frameContexts.join(","));
    if (row.frameOwner) evidence.push("frameOwner=" + row.frameOwner);
    if (row.frameOwners && row.frameOwners.length) evidence.push("frameOwner=" + row.frameOwners.join(","));
    if (row.frameHref) evidence.push("frameHref=" + row.frameHref);
    if (row.frameHrefs && row.frameHrefs.length) evidence.push("frameHref=" + row.frameHrefs.join(","));
    if (row.risk) evidence.push("risk=" + row.risk);
    if (row.dataAccess) evidence.push("dataAccess=" + row.dataAccess);
    if (row.approvalTicket) evidence.push("approvalTicket=" + row.approvalTicket);
    out.push("| " + markdownCell(row.source) + " | " + markdownCell(row.detail) + " | " + markdownCell(evidence.join("; ") || "n/a") + " |");
  }
  out.push("");
}

function writeScriptInventoryAuditReport(report, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(report, null, 2)}\n` : renderScriptInventoryAuditMarkdown(report) + "\n";
  if (!args.scriptInventoryAuditOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.scriptInventoryAuditOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`script inventory audit written: ${resolvedPath}\n`);
}

function parseScriptInventoryCsv(text, filePath) {
  const rows = parseCsvRows(text);
  if (rows.length === 0) {
    throw new Error(`payment-page script inventory CSV ${filePath} is empty.`);
  }
  const headers = rows[0].map(normalizeAuditCell);
  return rows.slice(1).filter((row) => row.some((cell) => normalizeAuditCell(cell) !== "")).map((row) => {
    const obj = {};
    for (let i = 0; i < headers.length; i += 1) {
      obj[headers[i]] = normalizeAuditCell(row[i]);
    }
    return obj;
  });
}

function parseCsvRows(text) {
  text = String(text || "").replace(/^\uFEFF/, "");
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === "\"") {
        if (text[i + 1] === "\"") {
          field += "\"";
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === "\"") {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\r" || ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
    } else {
      field += ch;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function normalizeScriptAuditKey(source) {
  const text = normalizeAuditCell(source);
  if (!text) return "";
  const sha = normalizeSha256(text);
  if (/^(inline:)?sha256[-:]/i.test(text) && sha) {
    return "inline:sha256-" + sha.toLowerCase();
  }
  if (/^inline:/i.test(text)) {
    return text.toLowerCase();
  }
  if (/^https?:\/\//i.test(text)) {
    try {
      const url = new URL(text);
      url.protocol = url.protocol.toLowerCase();
      url.hostname = url.hostname.toLowerCase();
      url.hash = "";
      return url.toString();
    } catch (error) {
      return text;
    }
  }
  return text.replace(/\\/g, "/");
}

function normalizeAuditCell(value) {
  return value == null ? "" : String(value).trim();
}

function auditAuthorizationState(value) {
  if (value === true) return "authorized";
  if (value === false) return "unauthorized";
  const v = normalizeAuditCell(value).toLowerCase();
  if (/^(true|yes|y|1|approved|authorized|allowed|active)$/.test(v)) return "authorized";
  if (/^(false|no|n|0|rejected|blocked|denied|unauthorized|not authorized)$/.test(v)) return "unauthorized";
  return "unknown";
}

function normalizeObservedAllowlisted(value) {
  if (value === undefined || value === null || value === "") return null;
  if (value === true) return true;
  if (value === false) return false;
  return boolishTrue(value);
}

function compareBySource(a, b) {
  return String(a.source || "").localeCompare(String(b.source || ""));
}

function countValueOccurrences(rows, fieldName) {
  const counts = {};
  for (const row of rows || []) {
    const raw = row ? row[fieldName] : null;
    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      const text = normalizeAuditCell(value);
      if (!text) continue;
      counts[text] = (counts[text] || 0) + 1;
    }
  }
  return counts;
}

function countIframeScopedRows(rows) {
  let count = 0;
  for (const row of rows || []) {
    const contexts = Array.isArray(row.frameContexts) ? row.frameContexts : [row.frameContext];
    const frameHrefs = Array.isArray(row.frameHrefs) ? row.frameHrefs : [row.frameHref];
    const contextText = contexts.map(normalizeAuditCell).join(" ").toLowerCase();
    if (contextText.indexOf("iframe") >= 0 || contextText.indexOf("frame") >= 0 || frameHrefs.some((value) => normalizeAuditCell(value) !== "")) {
      count += 1;
    }
  }
  return count;
}

function formatCountObject(counts) {
  const entries = Object.keys(counts || {}).sort();
  if (entries.length === 0) return "none";
  return entries.map((key) => `${key}: ${counts[key]}`).join(", ");
}

function readTextFile(filePath, label) {
  try {
    return fs.readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
  } catch (error) {
    throw new Error(`Failed to read ${label} ${filePath}: ${error.message}`);
  }
}

function parseJsonText(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Failed to parse ${label}: ${error.message}`);
  }
}

function parseMaybeJsonString(value) {
  const text = String(value || "").trim();
  if (!text || !/^[\[{]/.test(text)) return undefined;
  try {
    return JSON.parse(text);
  } catch (error) {
    return undefined;
  }
}

function readJsonObjectFile(filePath, label) {
  const resolvedPath = path.resolve(filePath);
  let parsed;
  try {
    const text = fs.readFileSync(resolvedPath, "utf8").replace(/^\uFEFF/, "");
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`Failed to read ${label} ${resolvedPath}: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} ${resolvedPath} must be a JSON object.`);
  }
  return parsed;
}

const AI_RESISTANCE_STRONG_OPTIONS = new Set([
  "encryptstrings",
  "encodestrings",
  "movestrings",
  "flattransform",
  "deepobfuscate",
  "adddeadcode",
  "deadcodelevel",
  "renameglobals",
  "renamemembers",
  "usevmprotection",
  "lockdomain",
  "lockdate"
]);

function summarizeVmProofFromReport(report, minVirtualizedFunctions) {
  const enabledOptions = firstReportValue(report, "EnabledOptions", "enabledOptions", "Options", "options", "RequestOptions", "requestOptions");
  const requested =
    boolishTrue(firstReportValue(report, "UseVMProtection", "useVMProtection")) ||
    optionListIncludes(enabledOptions, "UseVMProtection") ||
    boolishTrue(optionObjectValue(enabledOptions, "UseVMProtection"));
  const applied = boolishTrue(firstReportValue(report, "VMProtectionApplied", "vmProtectionApplied"));
  const virtualizedCount = integerOrZero(firstReportValue(
    report,
    "VMProtectionVirtualizedCount",
    "vmProtectionVirtualizedCount",
    "VirtualizedFunctionCount",
    "virtualizedFunctionCount"
  ));
  const warnings = normalizeVmWarnings(firstReportValue(report, "VMProtectionWarnings", "vmProtectionWarnings"));
  return {
    requested,
    applied,
    virtualizedCount,
    minVirtualizedFunctions,
    warnings,
    ok: requested && applied && virtualizedCount >= minVirtualizedFunctions && warnings.length === 0
  };
}

function normalizedOptionNames(value) {
  if (Array.isArray(value)) {
    return Array.from(new Set(value.map((item) => stringOrNull(item)).filter(Boolean)));
  }
  if (typeof value === "string") {
    return Array.from(new Set(value.split(/[,\s]+/).map((item) => stringOrNull(item)).filter(Boolean)));
  }
  if (value && typeof value === "object") {
    return Object.keys(value).filter((key) => value[key] !== false && value[key] != null);
  }
  return [];
}

function buildAiResistanceEvidenceRecommendations(checks, vmProof, context) {
  const recommendations = [
    "Treat this as current evidence only. Do not describe it as an AI-proof result or as the planned Resistance Score."
  ];
  if (checks.some((check) => check.name === "build-id" && !check.ok)) {
    recommendations.push("Add --label and keep the API report with the release so reviewers can tie evidence to one build.");
  }
  if (checks.some((check) => check.name === "strong-protection-options" && !check.ok)) {
    recommendations.push("Use a stronger profile such as balanced or maximum before using the report as AI-resistance evidence.");
  }
  if (!context.hasSourceFreeMaps) {
    recommendations.push("Keep the source-free API report, polymorphism fingerprint, symbol pack, or identifier maps with the release artifact.");
  }
  if (context.requireVmProof && !vmProof.ok) {
    recommendations.push("Run --verify-vm-proof on the same report and resolve VM warnings before claiming VM-backed evidence.");
  } else if (!vmProof.requested) {
    recommendations.push("Use VM protection only for cold sensitive functions when stronger static-analysis resistance is worth the runtime cost.");
  }
  if (!context.hasRuntimeEvidence) {
    recommendations.push("Add RuntimeDefenseBeaconUrl when tamper attempts need dashboard or SIEM evidence.");
  }
  if (!context.hasCompatibilityEvidence) {
    recommendations.push("Run compatibility checks or keep compatibility findings with the release review package.");
  }
  return recommendations;
}

function buildAiResistanceEvidenceReviewDecision(checks, reviewMatrix) {
  const requiredFailures = (checks || []).filter((check) => check && check.required && !check.ok);
  if (requiredFailures.length) {
    return {
      decision: "blocked",
      label: "Blocked",
      manualReviewRequired: true,
      failedChecks: requiredFailures.map((check) => check.name),
      missingReviewTracks: [],
      reason: "Required AI-resistance evidence checks failed.",
      nextAction: "Resolve the failed checks, regenerate the protected build report, and rerun --ai-resistance-evidence before reviewer handoff."
    };
  }

  const missingReviewTracks = (reviewMatrix || [])
    .filter((row) => row && ["missing", "needs-review", "not-requested"].includes(row.status))
    .map((row) => ({
      id: row.id,
      status: row.status,
      action: row.reviewerAction
    }));

  if (missingReviewTracks.length) {
    return {
      decision: "ready-for-manual-review",
      label: "Ready for manual review",
      manualReviewRequired: true,
      failedChecks: [],
      missingReviewTracks,
      reason: "Required evidence checks passed, but one or more current review tracks still need confirmation or an explicit out-of-scope decision.",
      nextAction: "Attach the source-free packet, document the missing review tracks, and keep protected-build smoke-test results with the release."
    };
  }

  return {
    decision: "ready",
    label: "Ready",
    manualReviewRequired: false,
    failedChecks: [],
    missingReviewTracks: [],
    reason: "Required checks passed and every current AI-resistance review track is evidenced.",
    nextAction: "Attach this packet beside the protected artifact and saved API report for release review."
  };
}

function buildAiResistanceReviewAssistant(reviewDecision, reviewMatrix, checks, claimBoundaries) {
  const questions = [];
  const failedRequired = (checks || []).filter((check) => check && check.required && !check.ok);
  if (failedRequired.length > 0) {
    questions.push({
      topic: "Required evidence failures",
      prompt: "List each failed required check and decide what build, option, VM proof, or report artifact must be regenerated before this packet can be used with a reviewer.",
      ownerAction: "Resolve the failed checks, regenerate the protected-build report, and rerun --ai-resistance-evidence."
    });
  }

  const missingTracks = (reviewMatrix || []).filter((row) => row && ["missing", "needs-review", "not-requested"].includes(row.status));
  if (missingTracks.length > 0) {
    questions.push({
      topic: "Manual review tracks",
      prompt: "Review the missing or needs-review attacker-model tracks. For each one, decide whether to add evidence, document an out-of-scope reason, or lower the claim for this release.",
      ownerAction: "Attach the owner decision for each missing review track before buyer or security handoff."
    });
  }

  if ((reviewMatrix || []).some((row) => row && row.id === "sensitive-function-extraction" && row.status !== "evidenced")) {
    questions.push({
      topic: "VM scope",
      prompt: "If VM-backed AI-resistance evidence is part of the claim, confirm which cold sensitive functions should be virtualized and whether the VM proof packet passes for those functions.",
      ownerAction: "Run --vm-proof-pack or record why VM protection is not in scope for this release."
    });
  }

  if ((reviewMatrix || []).some((row) => row && row.id === "runtime-instrumentation" && row.status === "missing")) {
    questions.push({
      topic: "Runtime evidence",
      prompt: "Decide whether this release needs runtime tamper evidence in addition to static protection evidence, and identify the dashboard, SIEM, or customer-owned route for confirmed events.",
      ownerAction: "Add RuntimeDefenseBeaconUrl or document why runtime evidence is out of scope."
    });
  }

  if ((reviewMatrix || []).some((row) => row && row.id === "compatibility-regression" && row.status === "missing")) {
    questions.push({
      topic: "Compatibility proof",
      prompt: "Confirm which protected-build smoke tests or compatibility checks prove the stronger settings did not break the shipped workflow.",
      ownerAction: "Attach compatibility results or reduce the evidence decision to manual review."
    });
  }

  if ((claimBoundaries || []).some((item) => item && item.claim === "Resistance Score" && item.status === "planned")) {
    questions.push({
      topic: "Resistance Score boundary",
      prompt: "Check the final reviewer wording. It may describe current source-free evidence and planned methodology, but it must not claim a live production Resistance Score.",
      ownerAction: "Use the approved wording from claimBoundaries and remove any AI-proof or production-score language."
    });
  }

  if (questions.length === 0) {
    questions.push({
      topic: "Clean review",
      prompt: "Confirm the current evidence, claim boundaries, runtime scope, compatibility proof, and source-free handoff are ready for reviewer attachment.",
      ownerAction: "Attach this packet beside the saved API report and protected-build smoke evidence."
    });
  }

  return {
    sourceFree: true,
    intendedUse: "Use with a BYO AI key or internal reviewer to triage current AI-resistance evidence without sending source code, protected output, source maps, provider keys, or secrets.",
    reviewerPrompt: "Review this JSO AI-resistance evidence packet. Use only the source-free build metadata, enabled option names, VM proof summary, review matrix, check results, claim boundaries, and recommendations. Produce release-owner actions without claiming the planned Resistance Score is live or that the build is AI-proof.",
    safeInputs: [
      "build ID and release label",
      "polymorphism fingerprint",
      "enabled option names",
      "VM proof summary and warning counts",
      "runtime-defense and compatibility evidence presence",
      "review matrix statuses and reviewer actions",
      "claim boundaries and recommendations"
    ],
    doNotInclude: [
      "raw source code",
      "protected output",
      "source maps",
      "identifier maps with proprietary symbol names",
      "customer personal data",
      "provider API keys",
      "JSO API credentials",
      "session tokens or secrets"
    ],
    questions
  };
}

function buildAiResistanceReviewMatrix(context) {
  const enabled = new Set((context.enabledOptions || []).map((name) => String(name || "").toLowerCase()));
  const hasAny = (names) => names.some((name) => enabled.has(name.toLowerCase()));
  const rows = [];

  rows.push({
    id: "static-identifier-recovery",
    attackerQuestion: "Can automated review recover meaningful variable, global, or member names from this build?",
    status: hasAny(["ReplaceNames", "RenameGlobals", "RenameMembers"]) ? "evidenced" : "needs-review",
    currentEvidence: hasAny(["ReplaceNames", "RenameGlobals", "RenameMembers"])
      ? "Name replacement evidence is present in enabled options."
      : "No name-replacement option was found in the saved report.",
    reviewerAction: hasAny(["ReplaceNames", "RenameGlobals", "RenameMembers"])
      ? "Check public API exclusions and identifier maps before describing identifier recovery as harder."
      : "Use a stronger profile or explain why public contract compatibility prevented name replacement.",
    safeClaim: "Identifier recovery is harder for this build when name replacement is enabled and public contracts are excluded intentionally."
  });

  rows.push({
    id: "string-literal-recovery",
    attackerQuestion: "Can automated review read sensitive string literals directly from protected output?",
    status: hasAny(["EncryptStrings", "EncodeStrings", "MoveStrings"]) ? "evidenced" : "needs-review",
    currentEvidence: hasAny(["EncryptStrings", "EncodeStrings", "MoveStrings"])
      ? "String movement, encoding, or encryption evidence is present in enabled options."
      : "No string-hiding option was found in the saved report.",
    reviewerAction: hasAny(["EncryptStrings", "EncodeStrings", "MoveStrings"])
      ? "Spot-check protected output for expected public strings versus sensitive literals that should be hidden."
      : "Enable string protection for sensitive literals or document why the release does not include sensitive strings.",
    safeClaim: "Sensitive string review is less direct when string protection is enabled; public strings and runtime values may still be observable."
  });

  rows.push({
    id: "control-flow-reconstruction",
    attackerQuestion: "Can automated review reconstruct source-level branch and function intent from the protected output?",
    status: hasAny(["FlatTransform", "DeepObfuscate", "ReorderCode", "AddDeadCode"]) ? "evidenced" : "needs-review",
    currentEvidence: hasAny(["FlatTransform", "DeepObfuscate", "ReorderCode", "AddDeadCode"])
      ? "Control-flow and deeper obfuscation evidence is present in enabled options."
      : "No control-flow or deep-obfuscation option was found in the saved report.",
    reviewerAction: hasAny(["FlatTransform", "DeepObfuscate", "ReorderCode", "AddDeadCode"])
      ? "Run protected-build smoke tests and keep compatibility notes with the release packet."
      : "Use balanced or maximum protection before presenting this build as static-analysis resistant.",
    safeClaim: "Control-flow recovery requires more work for the named build when deeper transforms are enabled and smoke-tested."
  });

  rows.push({
    id: "sensitive-function-extraction",
    attackerQuestion: "Are cold sensitive functions protected beyond the surrounding bundle profile?",
    status: context.vmProof && context.vmProof.ok ? "evidenced" : (context.vmProof && context.vmProof.requested ? "needs-review" : "not-requested"),
    currentEvidence: context.vmProof && context.vmProof.ok
      ? "VM proof passed for the saved report."
      : (context.vmProof && context.vmProof.requested
        ? "VM protection was requested but the proof has warnings or insufficient virtualized functions."
        : "VM proof was not requested for this report."),
    reviewerAction: context.vmProof && context.vmProof.ok
      ? "Confirm the virtualized functions are cold sensitive paths and not hot render or parsing loops."
      : "Use --vm-proof-pack or --verify-vm-proof when VM-backed evidence is part of the review.",
    safeClaim: "VM-backed evidence applies only to the selected functions that passed proof checks."
  });

  rows.push({
    id: "runtime-instrumentation",
    attackerQuestion: "Does the release preserve evidence when protected code is tampered with or probed in the browser?",
    status: context.hasRuntimeEvidence ? "evidenced" : "missing",
    currentEvidence: context.hasRuntimeEvidence
      ? "Runtime-defense summary or beacon evidence is present."
      : "No runtime-defense summary or beacon URL was found in the saved report.",
    reviewerAction: context.hasRuntimeEvidence
      ? "Route confirmed incidents to the customer-owned monitoring path and keep source-free exports for review."
      : "Add RuntimeDefenseBeaconUrl when runtime tamper activity needs evidence beyond static protection.",
    safeClaim: "Runtime evidence helps triage observed tamper activity; it does not make client-side code secret."
  });

  rows.push({
    id: "compatibility-regression",
    attackerQuestion: "Can the team show stronger protection did not break the shipped workflow?",
    status: context.hasCompatibilityEvidence ? "evidenced" : "missing",
    currentEvidence: context.hasCompatibilityEvidence
      ? "Compatibility summary evidence is present."
      : "No compatibility summary was found in the saved report.",
    reviewerAction: context.hasCompatibilityEvidence
      ? "Keep compatibility findings and smoke-test results with the protected release packet."
      : "Run compatibility checks or document protected-build smoke coverage before release approval.",
    safeClaim: "Resistance evidence is more useful when paired with compatibility evidence for the same build."
  });

  rows.push({
    id: "source-free-review-handoff",
    attackerQuestion: "Can reviewers inspect the evidence without receiving source code?",
    status: context.hasSourceFreeMaps ? "evidenced" : "needs-review",
    currentEvidence: context.hasSourceFreeMaps
      ? "Fingerprint, symbol pack, or identifier-map evidence is present."
      : "No source-free fingerprint, symbol pack, or identifier map was found.",
    reviewerAction: context.hasSourceFreeMaps
      ? "Share the evidence packet and keep raw source code out of buyer, QSA, or AI-provider prompts."
      : "Keep a source-free report artifact with the release so reviewers do not need raw source access.",
    safeClaim: "The packet supports source-free review of protection evidence; it is not a deobfuscation benchmark score."
  });

  return rows;
}

function buildAiResistanceClaimBoundaries() {
  return [
    {
      claim: "Current evidence",
      status: "available-now",
      approvedWording: "This report summarizes current source-free release evidence from the saved JavaScript Obfuscator API report.",
      doNotSay: "This report is a Resistance Score."
    },
    {
      claim: "Resistance Score",
      status: "planned",
      approvedWording: "Resistance Score is a planned methodology and is not a live production score in this report.",
      doNotSay: "This build has a production Resistance Score."
    },
    {
      claim: "AI resistance",
      status: "bounded",
      approvedWording: "The enabled protections raise static-analysis and automated-review effort for the named build.",
      doNotSay: "The build is AI-proof or defeats every LLM analysis."
    },
    {
      claim: "Runtime secrecy",
      status: "bounded",
      approvedWording: "Client-side JavaScript can still be executed, observed, instrumented, and reviewed by a determined attacker.",
      doNotSay: "Client-side code becomes secret forever."
    }
  ];
}

function writeVmProofVerificationReport(report, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`jso-protector verify-vm-proof: ${report.ok ? "ok" : "failed"}\n`);
  process.stdout.write(`report: ${report.reportPath}\n`);
  if (report.buildId) process.stdout.write(`BuildID: ${report.buildId}\n`);
  process.stdout.write(`virtualized functions: ${report.summary.virtualizedCount} (minimum ${report.minVirtualizedFunctions})\n`);
  for (const check of report.checks) {
    process.stdout.write(`${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.message}\n`);
  }
  for (const warning of report.warnings || []) {
    process.stdout.write(`WARN vm: ${warning}\n`);
  }
}

function renderVmProofPackMarkdown(pack) {
  const out = [];
  out.push("# JSO VM Proof Pack");
  out.push("");
  out.push("Generated: " + pack.generatedAt);
  out.push("Status: " + (pack.ok ? "PASS" : "NEEDS REVIEW"));
  if (pack.reviewDecision && pack.reviewDecision.label) {
    out.push("Review decision: " + pack.reviewDecision.label);
  }
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Metric | Value |");
  out.push("|---|---|");
  out.push("| Build ID | " + markdownCell(pack.buildId || "missing") + " |");
  out.push("| Release label | " + markdownCell(pack.releaseLabel || "not supplied") + " |");
  out.push("| Polymorphism fingerprint | " + markdownCell(pack.polymorphismFingerprint || "not supplied") + " |");
  out.push("| Minimum virtualized functions | " + pack.minVirtualizedFunctions + " |");
  out.push("| VM requested | " + yesNo(pack.proof.summary.requested) + " |");
  out.push("| VM applied | " + yesNo(pack.proof.summary.applied) + " |");
  out.push("| Virtualized functions | " + pack.proof.summary.virtualizedCount + " |");
  out.push("| VM warnings | " + pack.proof.summary.warnings + " |");
  out.push("| Source-free | yes |");
  out.push("");
  if (pack.reviewDecision) {
    out.push("## Review Decision");
    out.push("");
    out.push("| Field | Value |");
    out.push("|---|---|");
    out.push("| Decision | " + markdownCell(pack.reviewDecision.label || pack.reviewDecision.decision || "not available") + " |");
    out.push("| Manual review required | " + yesNo(pack.reviewDecision.manualReviewRequired) + " |");
    out.push("| Reason | " + markdownCell(pack.reviewDecision.reason || "") + " |");
    out.push("| Next action | " + markdownCell(pack.reviewDecision.nextAction || "") + " |");
    out.push("");
  }
  out.push("## Checklist");
  out.push("");
  out.push("| Check | Required | Status | Detail |");
  out.push("|---|---|---|---|");
  for (const item of pack.checklist) {
    out.push("| " + markdownCell(item.name) + " | " + yesNo(item.required) + " | " + (item.ok ? "PASS" : "REVIEW") + " | " + markdownCell(item.message) + " |");
  }
  out.push("");
  out.push("## Enabled Options");
  out.push("");
  out.push(pack.evidence.enabledOptions.length ? pack.evidence.enabledOptions.map((name) => "- `" + markdownInline(name) + "`").join("\n") : "- none recorded");
  out.push("");
  out.push("## VM Warnings");
  out.push("");
  out.push(pack.evidence.warnings.length ? pack.evidence.warnings.map((warning) => "- " + markdownCell(warning)).join("\n") : "- none");
  out.push("");
  out.push("## Compatibility Guidance");
  out.push("");
  out.push("| Scope | Guidance | Examples | Reviewer action |");
  out.push("|---|---|---|---|");
  for (const item of pack.compatibilityGuidance || []) {
    out.push("| " + markdownCell(item.scope) + " | " + markdownCell(item.guidance) + " | " + markdownCell(item.examples) + " | " + markdownCell(item.action) + " |");
  }
  out.push("");
  out.push("## Hot-Path Guidance");
  out.push("");
  out.push("| Scope | Recommendation | Examples | Rationale |");
  out.push("|---|---|---|---|");
  for (const item of pack.performanceGuidance || []) {
    out.push("| " + markdownCell(item.scope) + " | " + markdownCell(item.recommendation) + " | " + markdownCell(item.examples) + " | " + markdownCell(item.rationale) + " |");
  }
  out.push("");
  renderVmProofReviewAssistant(out, pack.reviewAssistant);
  out.push("## Recommendations");
  out.push("");
  for (const item of pack.recommendations) out.push("- " + markdownCell(item));
  out.push("");
  return out.join("\n");
}

function renderVmProofReviewAssistant(out, assistant) {
  if (!assistant) return;
  out.push("## VM Proof Review Assistant");
  out.push("");
  out.push(markdownCell(assistant.intendedUse));
  out.push("");
  out.push("**Reviewer prompt:** " + markdownCell(assistant.reviewerPrompt));
  out.push("");
  out.push("Safe inputs:");
  for (const item of assistant.safeInputs || []) out.push("- " + markdownCell(item));
  out.push("");
  out.push("Do not include:");
  for (const item of assistant.doNotInclude || []) out.push("- " + markdownCell(item));
  out.push("");
  out.push("| Topic | Question | Owner action |");
  out.push("|---|---|---|");
  for (const item of assistant.questions || []) {
    out.push("| " + [
      item.topic || "",
      item.prompt || "",
      item.ownerAction || ""
    ].map(markdownCell).join(" | ") + " |");
  }
  out.push("");
}

function writeVmProofPackReport(pack, args = {}) {
  const asJson = args.json === true;
  const text = asJson ? `${JSON.stringify(pack, null, 2)}\n` : renderVmProofPackMarkdown(pack) + "\n";
  if (!args.vmProofOutput) {
    process.stdout.write(text);
    return;
  }
  const resolvedPath = path.resolve(args.vmProofOutput);
  const dir = path.dirname(resolvedPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(resolvedPath, text, "utf8");
  process.stderr.write(`VM proof pack written: ${resolvedPath}\n`);
}

function markdownCell(value) {
  return String(value == null ? "" : value).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function markdownInline(value) {
  return String(value == null ? "" : value).replace(/`/g, "'");
}

function yesNo(value) {
  return value ? "yes" : "no";
}

function firstReportValue(obj, ...names) {
  if (!obj || typeof obj !== "object") return undefined;
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(obj, name)) return obj[name];
  }
  return undefined;
}

function boolishTrue(value) {
  if (value === true) return true;
  if (typeof value === "number") return value === 1;
  if (typeof value === "string") return value.trim().toLowerCase() === "true";
  return false;
}

function optionListIncludes(value, optionName) {
  if (Array.isArray(value)) {
    return value.some((item) => String(item || "").trim().toLowerCase() === optionName.toLowerCase());
  }
  if (typeof value === "string") {
    return value.split(/[,\s]+/).some((item) => item.trim().toLowerCase() === optionName.toLowerCase());
  }
  return false;
}

function optionObjectValue(value, optionName) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const key = Object.keys(value).find((name) => name.toLowerCase() === optionName.toLowerCase());
  return key ? value[key] : undefined;
}

function integerOrZero(value) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(0, Math.floor(value));
  if (typeof value === "string") {
    const n = Number(value.trim());
    if (Number.isFinite(n)) return Math.max(0, Math.floor(n));
  }
  return 0;
}

function stringOrNull(value) {
  const s = value == null ? "" : String(value).trim();
  return s || null;
}

function normalizeVmWarnings(value) {
  if (value == null || value === false) return [];
  if (Array.isArray(value)) {
    return value.map((item) => stringOrNull(item)).filter(Boolean);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  return [JSON.stringify(value)];
}

async function main(argv = process.argv.slice(2)) {
  // `jso ai <subcommand>` -- intercept before parseArgs so the AI
  // surface gets its own flag set without bloating the protect-side
  // parser. See ai-cli.js for the subcommand definitions.
  if (argv.length > 0 && argv[0] === "ai") {
    const aiCli = require("../ai-cli.js");
    const code = await aiCli.main(argv.slice(1));
    if (code !== 0) {
      const err = new Error("jso ai exited with code " + code);
      err.exitCode = code;
      throw err;
    }
    return;
  }

  // `jso compliance <framework>` -- same pattern as `ai`. Today the
  // only framework is pci-dss-v4; the dispatcher in compliance/cli.js
  // is structured so SOC 2, ISO 27001, EU DSA, etc. can drop in later
  // without re-wiring this bin. The reporter consumes the manifest +
  // signed envelope already produced by --sign-release, so this stays
  // a pure-offline command (no API calls).
  if (argv.length > 0 && argv[0] === "compliance") {
    const compCli = require("../compliance/cli.js");
    const code = await compCli.main(argv.slice(1));
    if (code !== 0) {
      const err = new Error("jso compliance exited with code " + code);
      err.exitCode = code;
      throw err;
    }
    return;
  }

  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return;
  }
  if (args.version) {
    writeVersion(args.json);
    return;
  }
  if (args.localOnly) {
    writeLocalOnlyGuidance(args.json);
    return;
  }
  if (args.sourceMapEvidence) {
    const report = buildSourceMapEvidenceReport(args.sourceMapEvidence, {
      verifyRoot: args.verifyRoot
    });
    writeSourceMapEvidenceReport(report, args);
    if (!report.ok) {
      throw new Error("source map evidence check failed");
    }
    return;
  }
  if (args.deploymentHygieneEvidence) {
    const report = buildDeploymentHygieneEvidenceReport(args.deploymentHygieneEvidence);
    writeDeploymentHygieneEvidenceReport(report, args);
    if (!report.ok) {
      throw new Error("deployment hygiene evidence needs review");
    }
    return;
  }
  if (args.runtimeIncidentEvidence) {
    const report = buildRuntimeIncidentEvidenceReport(args.runtimeIncidentEvidence);
    writeRuntimeIncidentEvidenceReport(report, args);
    if (!report.ok) {
      throw new Error("runtime incident evidence needs response");
    }
    return;
  }
  if (args.migrationReview) {
    const report = buildMigrationReviewReport(readConfig(args.config, args), args);
    writeMigrationReviewReport(report, args);
    return;
  }
  if (args.identifierCacheReview) {
    const report = buildIdentifierCacheReviewReport(readConfig(args.config, args), args);
    writeIdentifierCacheReviewReport(report, args);
    return;
  }
  if (args.runtimeDefenseReview) {
    const report = buildRuntimeDefenseReviewReport(readConfig(args.config, args), args);
    writeRuntimeDefenseReviewReport(report, args);
    return;
  }
  if (args.verifyManifest) {
    const report = verifyManifestOutputs(args.verifyManifest, {
      verifyRoot: args.verifyRoot,
      auditSourceMaps: args.auditSourceMaps
    });
    writeManifestVerificationReport(report, args.json);
    if (!report.ok) {
      throw new Error("manifest verification failed");
    }
    return;
  }
  if (args.verifyVmProof) {
    const report = verifyVmProofReport(args.verifyVmProof, {
      minVirtualizedFunctions: args.minVmFunctions
    });
    writeVmProofVerificationReport(report, args.json);
    if (!report.ok) {
      throw new Error("VM proof verification failed");
    }
    return;
  }
  if (args.vmProofPack) {
    const pack = buildVmProofPack(args.vmProofPack, {
      minVirtualizedFunctions: args.minVmFunctions
    });
    writeVmProofPackReport(pack, args);
    if (!pack.ok) {
      throw new Error("VM proof pack needs review");
    }
    return;
  }
  if (args.aiResistanceEvidence) {
    const report = buildAiResistanceEvidenceReport(args.aiResistanceEvidence, {
      minVirtualizedFunctions: args.minVmFunctions,
      requireVmProof: args.requireVmProof
    });
    writeAiResistanceEvidenceReport(report, args);
    if (!report.ok) {
      throw new Error("AI resistance evidence check failed");
    }
    return;
  }
  if (args.scriptInventoryFromSnapshot) {
    const report = buildScriptInventoryFromSnapshot(args.scriptInventoryFromSnapshot);
    writeScriptInventoryFromSnapshotReport(report, args.scriptInventoryOutput);
    return;
  }
  if (args.paymentPageHeadersFromHar) {
    const report = buildPaymentPageHeadersFromHar(args.paymentPageHeadersFromHar, {
      urlPattern: args.paymentPageUrlPattern,
      baselinePath: args.paymentPageHeadersBaseline
    });
    writePaymentPageHeadersFromHarReport(report, args.paymentPageHeadersOutput);
    return;
  }
  if (args.scriptInventoryAudit) {
    const report = buildScriptInventoryAudit(args.scriptInventoryAudit, args.runtimeInventorySnapshot);
    writeScriptInventoryAuditReport(report, args);
    if (!report.ok) {
      throw new Error("script inventory audit needs review");
    }
    return;
  }
  if (args.listPresets) {
    writePresetList(args.json);
    return;
  }
  if (args.listOptions) {
    writeOptionList(args.json);
    return;
  }
  if (args.genkeyRelease) {
    // Pure offline operation: mint an Ed25519 keypair and write the
    // two PEM files to disk. No creds, no config, no network.
    const { publicKeyPem, privateKeyPem } = releaseSigner.generateKeyPair();
    const base = path.resolve(args.genkeyRelease);
    const privPath = base + ".priv.pem";
    const pubPath  = base + ".pub.pem";
    fs.writeFileSync(privPath, privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(pubPath,  publicKeyPem,  { mode: 0o644 });
    const out = { privateKey: privPath, publicKey: pubPath };
    if (args.json) process.stdout.write(JSON.stringify(out, null, 2) + "\n");
    else {
      process.stdout.write("Wrote " + privPath + " (KEEP SECRET; do not commit)\n");
      process.stdout.write("Wrote " + pubPath  + " (publish for verifiers)\n");
    }
    return;
  }
  if (args.verifyRelease) {
    // Read a signed envelope from disk, optionally pin to a trusted
    // public key, and (when --verify-root is supplied) also re-hash
    // the output files on disk. Exit 0 valid / 1 invalid / 2 unreadable.
    const sigPath = args.verifyRelease;
    if (!fs.existsSync(sigPath)) {
      throw new Error("--verify-release: file not found: " + sigPath);
    }
    let envelope;
    try {
      envelope = JSON.parse(fs.readFileSync(sigPath, "utf8"));
    } catch (e) {
      throw new Error("--verify-release: invalid JSON in " + sigPath + ": " + e.message);
    }
    const opts = {};
    if (args.publicKey) {
      if (!fs.existsSync(args.publicKey)) {
        throw new Error("--public-key: file not found: " + args.publicKey);
      }
      opts.expectedPublicKeyPem = fs.readFileSync(args.publicKey, "utf8");
    }
    if (args.verifyRoot) {
      opts.fileRoot = args.verifyRoot;
    }
    const r = releaseSigner.verifyRelease(envelope, opts);
    if (args.json) {
      process.stdout.write(JSON.stringify({ file: sigPath, ...r }, null, 2) + "\n");
    } else if (r.valid) {
      const filesNote = r.stage2 && opts.fileRoot ? (", " + envelope.manifest.files.length + " file(s) re-hashed") : "";
      process.stdout.write("OK    " + sigPath + ": signature valid"
        + (envelope.manifest.buildId ? " (BuildId=" + envelope.manifest.buildId + ")" : "")
        + filesNote + "\n");
    } else {
      process.stdout.write("FAIL  " + sigPath + ": " + (r.error || "verification failed") + "\n");
      for (const m of r.mismatches || []) {
        process.stdout.write("        " + m.name + " expected=" + m.expected
          + " actual=" + (m.actual || "(missing)") + "\n");
      }
    }
    if (!r.valid) process.exitCode = 1;
    return;
  }
  if (args.scanWatermarks) {
    // Pure offline tree walk. No creds, no config, no obfuscation.
    // Read every .js file under the directory; for each one with a
    // watermark, record the embedded tag and (if a key was provided)
    // the validity. Aggregate into a single report.
    const root = args.scanWatermarks;
    if (!fs.existsSync(root)) {
      throw new Error("--scan-watermarks: directory not found: " + root);
    }
    const stat = fs.statSync(root);
    if (!stat.isDirectory()) {
      throw new Error("--scan-watermarks: not a directory: " + root);
    }
    const key = args.watermarkKey
      || (process.env.JSO_WATERMARK_KEY && process.env.JSO_WATERMARK_KEY.trim())
      || null;
    const report = scanWatermarksTree(root, key);
    writeScanReport(report, root, args.json);
    // Exit code policy:
    //   0 — at least one watermarked file found, and every one that
    //       could be validated did (or no key supplied: lookup-only).
    //   1 — at least one watermarked file's signature did NOT match
    //       the supplied key (real tampering / cross-key contamination)
    //   2 — zero watermarked files in the tree (probably wrong dir
    //       or this build wasn't watermarked)
    if (report.invalid > 0) { process.exitCode = 1; return; }
    if (report.scanned === 0 || report.watermarked === 0) {
      process.exitCode = 2; return;
    }
    return;
  }
  if (args.verifyWatermark) {
    // Read-only mode: don't need creds or config. Just scan the file.
    const file = args.verifyWatermark;
    if (!fs.existsSync(file)) {
      throw new Error("--verify-watermark: file not found: " + file);
    }
    const src = fs.readFileSync(file, "utf8");
    const key = args.watermarkKey
      || (process.env.JSO_WATERMARK_KEY && process.env.JSO_WATERMARK_KEY.trim())
      || null;
    const result = watermark.verify(src, key);
    if (args.json) {
      process.stdout.write(JSON.stringify({ file: file, ...result }, null, 2) + "\n");
    } else if (!result.present) {
      process.stdout.write("FAIL  " + file + ": " + result.error + "\n");
    } else if (!key) {
      process.stdout.write("INFO  " + file + ": tag=" + result.tag + " (provide --watermark-key to validate signature)\n");
    } else if (result.valid) {
      process.stdout.write("OK    " + file + ": valid watermark, tag=" + result.tag + "\n");
    } else {
      process.stdout.write("FAIL  " + file + ": watermark present but signature does NOT match --watermark-key\n");
    }
    // Exit code: 0 when valid; 1 when present-but-invalid; 2 when missing or key not provided.
    if (!result.present) { process.exitCode = 2; return; }
    if (!key) { process.exitCode = 2; return; }
    if (!result.valid) { process.exitCode = 1; return; }
    return;
  }
  if (args.compatScan) {
    const report = scanCompatibilityRisks(mergeConfig(readConfig(args.config, args), args));
    writeCompatibilityScanReport(report, args.json);
    return;
  }
  if (args.listMigrationMap) {
    writeMigrationMap(args.json);
    return;
  }
  if (args.listJsConfuserMigrationMap) {
    writeJsConfuserMigrationMap(args.json);
    return;
  }
  if (args.competitorGapReport) {
    const report = buildCompetitorGapReport(readConfig(args.config, args), args);
    writeCompetitorGapReport(report, args.json);
    return;
  }
  if (args.explainCompat) {
    writeCompatibilityExplanation(args.explainCompat, args.json);
    return;
  }
  if (args.explainJsConfuserCompat) {
    writeJsConfuserCompatibilityExplanation(args.explainJsConfuserCompat, args.json);
    return;
  }
  if (args.init) {
    initConfig(args);
    return;
  }
  if (args.migrateJavascriptObfuscator) {
    const report = migrateJavascriptObfuscatorConfig(args.migrateJavascriptObfuscator, args);
    writeMigrationReport(report, args);
    return;
  }
  if (args.migrateJsConfuser) {
    const report = migrateJsConfuserConfig(args.migrateJsConfuser, args);
    writeMigrationReport(report, args);
    return;
  }

  writeCompatibilityWarnings(args);

  if (args.releaseCheck) {
    const report = await runReleaseCheck(readConfig(args.config, args), args);
    writeReleaseCheckReport(report, args.json);
    if (!report.ok) {
      throw new Error("release check failed");
    }
    return;
  }

  if (args.validateConfig) {
    const report = validateProtectionConfig(readConfig(args.config, args), args);
    writeValidationReport(report, args.json);
    if (!report.ok) {
      throw new Error("config validation failed");
    }
    return;
  }

  const rawConfig = readConfig(args.config, args);
  const config = mergeConfig(rawConfig, args);
  Object.defineProperty(config, "__rawConfig", {
    value: rawConfig,
    enumerable: false
  });
  if (args.printConfig) {
    writeResolvedConfig(config, args.json);
    return;
  }

  if (args.doctor) {
    const report = await runDoctor(config, {
      ...args,
      rawConfig
    });
    writeDoctorReport(report, args.json);
    if (!report.ok) {
      throw new Error("doctor checks failed");
    }
    return;
  }

  if (args.stdin) {
    const fileName = normalizeName(args.fileName || "stdin.js");
    const summary = {
      endpoint: config.endpoint,
      projectName: config.projectName,
      preset: config.preset,
      fileName,
      output: args.stdout ? "stdout" : path.join(config.output, fileName),
      options: Object.keys(config.options).filter((key) => key !== "reservedNames")
    };

    if (args.dryRun) {
      if (args.json) process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      else process.stdout.write(`Would protect stdin as ${fileName}.\n`);
      return;
    }

    assertReady(config);
    const code = await readStdin();
    if (!code) throw new Error("No input received on stdin.");

    const protectedEntry = await protectCodeDetailed(config, code, fileName);
    const protectedCode = protectedEntry.code;
    const manifestPath = config.manifest || null;
    if (args.stdout) {
      process.stdout.write(protectedCode);
    } else {
      const target = path.join(config.output, fileName);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, protectedCode, "utf8");
      if (args.json) process.stdout.write(`${JSON.stringify({ ...summary, type: "Succeed", written: [target], manifest: manifestPath, processing: protectedEntry.processing }, null, 2)}\n`);
      else process.stdout.write(`Protected stdin into ${target}\n`);
    }
    const manifest = buildStdinManifest(config, fileName, code, protectedCode, args.stdout ? "stdout" : path.join(config.output, fileName), protectedEntry.processing);
    assertSizeBudgets(manifest, config);
    writeManifest(manifestPath, manifest);
    return;
  }

  const files = collectFiles(config.input, config.output, config.extensions, config.exclude, config.include, config.markupExtensions);
  const assets = config.copyAssets ? collectAssets(config.input, config.output, files, config.assetExclude) : [];
  const protection = buildProtectionItems(config, files);
  const request = buildRequestFromItems(config, protection.items);

  const summary = addProtectionSummary({
    endpoint: config.endpoint,
    projectName: config.projectName,
    preset: config.preset,
    input: config.input,
    output: config.output,
    files: files.map((file) => file.relative),
    assets: assets.map((file) => file.relative),
    options: Object.keys(config.options).filter((key) => key !== "reservedNames")
  }, protection);

  if (args.dryRun) {
    if (args.json) process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    else {
      process.stdout.write(`Would protect ${files.length} file(s).\n`);
      for (const file of files) process.stdout.write(`- ${file.relative}\n`);
      process.stdout.write(`API item(s): ${summary.processing.apiItems}\n`);
      for (const entry of summary.processing.transformedFiles) {
        process.stdout.write(`Transform ${entry.fileName}: ${entry.type}, ${entry.apiItems} API item(s), ${entry.preservedParts} preserved part(s)\n`);
      }
    }
    return;
  }

  // --estimate: pre-flight quota check. Don't call assertReady or hit the
  // obfuscation API; just total the inputs, fetch the current quota
  // counters via /v1/ai/usage, and print a CI-friendly summary.
  if (args.estimate) {
    if (!files.length) {
      throw new Error("--estimate: no matching input files found.");
    }
    const stats = computeBuildStats(files);
    let usage = null;
    let usageError = null;
    try {
      const ai = require("../ai.js");
      usage = await ai.usage({
        apiKey: config.apiKey, apiPassword: config.apiPassword,
        endpoint: config.endpoint && config.endpoint.replace(/\/HttpApi\.ashx.*$/i, ""),
      });
    } catch (err) {
      usageError = { code: err.code || "unknown", message: err.message };
    }
    const report = buildEstimateReport(stats, usage, usageError, config);
    writeEstimateReport(report, args.json);
    if (report.gate === "fail") process.exitCode = 1;
    return;
  }

  assertReady(config);
  if (!files.length) {
    throw new Error("No matching input files found.");
  }

  // --ai-precheck: run AI compat-check on every file BEFORE submitting to
  // the obfuscation API. Customers get a fail-fast signal on patterns that
  // would produce a broken protected build (eval, Function constructor,
  // framework reflection, etc.). Same endpoint as `jso ai compat-scan`,
  // just folded into the obfuscation flow so CI doesn't need two commands.
  if (args.aiPrecheck) {
    const gate = await runAiPrecheck(config, files, args);
    writeAiPrecheckReport(gate, args.json);
    if (!gate.ok) {
      throw new Error("ai-precheck gate failed (" + gate.summary.errors + " error(s), "
        + gate.summary.warnings + " warning(s); fail-on=" + gate.summary.failOn + ")");
    }
  }

  let result;
  let manifestTransforms = protection.transforms;
  let overrideGroups = null;
  if (hasNamedSets(config)) {
    const grouped = await protectGroupedFiles(config, files);
    result = grouped.result;
    manifestTransforms = grouped.transforms;
    overrideGroups = grouped.groups;
  } else {
    result = await protectItems(config, request.Items);
    writeResults(files, result, protection.transforms, config);
  }
  copyAssets(assets);
  const manifestPath = config.manifest || null;
  const manifest = buildProtectionManifest(config, files, assets, result, manifestTransforms);
  assertSizeBudgets(manifest, config);
  writeManifest(manifestPath, manifest);

  // --sign-release: produce an Ed25519-signed attestation over the build.
  // Stays alongside the manifest so verifiers can pull both with a single
  // download. Hashes every protected output file by its on-disk bytes
  // (post-finalize, so the signature reflects exactly what shipped).
  if (args.signRelease) {
    if (!fs.existsSync(args.signRelease)) {
      throw new Error("--sign-release: private key file not found: " + args.signRelease);
    }
    const privPem = fs.readFileSync(args.signRelease, "utf8");
    const fileEntries = files.map(f => ({
      name: f.relative,
      sha256: releaseSigner.sha256OfFile(f.target),
    }));
    const envelope = releaseSigner.signRelease({
      buildId: (result.Report && result.Report.BuildId) || null,
      polymorphismFingerprint: (result.Report && result.Report.PolymorphismFingerprint) || null,
      label: config.label || null,
      files: fileEntries,
    }, privPem);
    const sigPath = (config.manifest || path.join(config.output, ".manifest.json")) + ".sig";
    fs.mkdirSync(path.dirname(sigPath), { recursive: true });
    fs.writeFileSync(sigPath, JSON.stringify(envelope, null, 2) + "\n", "utf8");
    if (!args.json) process.stdout.write("Signed release attestation: " + sigPath + "\n");
  }

  // --report writes the full API response JSON to disk. Pairs with
  // jso-symbolicate (consumes Report.GlobalIdentifierMap / MemberIdentifierMap)
  // and the GitHub Action (parses Report.BuildId + PolymorphismFingerprint).
  // The response shape mirrors what HttpApi.ashx returns; we wrap it under a
  // top-level object so multiple iterations could be appended later without a
  // schema change.
  const reportPath = config.report || null;
  if (reportPath) {
    writeReportFile(reportPath, result, config);
  }

  const done = {
    ...summary,
    type: result.Type,
    written: files.map((file) => file.target),
    copied: assets.map((file) => file.target),
    manifest: manifestPath,
    report: reportPath,
    label: config.label || null,
    buildId: (result.Report && result.Report.BuildId) || null,
    polymorphismFingerprint: (result.Report && result.Report.PolymorphismFingerprint) || null
  };
  if (overrideGroups) {
    done.namedSetGroups = overrideGroups;
    if (result.Reports && result.Reports.length > 1) {
      done.buildIds = result.Reports.map((report) => report.BuildId || null);
    }
  }
  if (args.json) process.stdout.write(`${JSON.stringify(done, null, 2)}\n`);
  else if (overrideGroups) process.stdout.write(`Protected ${files.length} file(s) in ${overrideGroups.length} named-set group(s) and copied ${assets.length} asset(s) into ${config.output}\n`);
  else process.stdout.write(`Protected ${files.length} file(s) and copied ${assets.length} asset(s) into ${config.output}\n`);
}

// --scan-watermarks helpers. Walks a directory tree, looks for .js
// files carrying the watermark marker, aggregates into a structured
// report. Skips node_modules / .git by default — they're noise and
// the customer's own build artifacts are what we're auditing.
function scanWatermarksTree(rootDir, key) {
  const report = {
    scanned: 0, watermarked: 0, valid: 0, invalid: 0, unverified: 0,
    keyProvided: !!key,
    files: [],
  };
  const exts = new Set([".js", ".mjs", ".cjs"]);
  // Iterative DFS so we don't blow the stack on deep trees.
  const stack = [rootDir];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { continue; }    // unreadable subdir — skip, not fatal
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "node_modules" || ent.name === ".git") continue;
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      const ext = path.extname(ent.name).toLowerCase();
      if (!exts.has(ext)) continue;

      report.scanned++;
      let src;
      try { src = fs.readFileSync(full, "utf8"); }
      catch (e) { continue; }
      const r = watermark.verify(src, key);
      if (!r.present) continue;
      report.watermarked++;
      const entry = { file: path.relative(rootDir, full), tag: r.tag };
      if (key) {
        entry.valid = r.valid;
        if (r.valid) report.valid++;
        else         report.invalid++;
      } else {
        entry.valid = null;     // lookup-only mode
        report.unverified++;
      }
      report.files.push(entry);
    }
  }
  // Stable ordering for diff-friendly output.
  report.files.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : 0);
  return report;
}

function writeScanReport(r, root, asJson) {
  if (asJson) {
    process.stdout.write(JSON.stringify({ root: root, ...r }, null, 2) + "\n");
    return;
  }
  process.stdout.write("Scanned " + r.scanned + " JS file(s) under " + root + "\n");
  process.stdout.write("Watermarked: " + r.watermarked + "   ");
  if (r.keyProvided) {
    process.stdout.write("valid=" + r.valid + "   invalid=" + r.invalid + "\n");
  } else {
    process.stdout.write("(no --watermark-key; signatures not validated)\n");
  }
  for (const f of r.files) {
    const flag = !r.keyProvided ? "WM" : (f.valid ? "OK" : "FAIL");
    process.stdout.write("  [" + flag + "] " + f.file + "   tag=" + f.tag + "\n");
  }
}

// --estimate helpers: total input stats, weave in quota counters from
// /v1/ai/usage, render a CI-friendly report. The estimate is intentionally
// conservative — we report raw input bytes/files; the customer's real
// billing is on output size which is correlated but not identical.
// "Will this build fit?" answers what CI actually needs: a yes / no /
// warning gate against the remaining monthly quota.
function computeBuildStats(files) {
  let bytes = 0, lines = 0;
  for (const f of files) {
    const buf = fs.readFileSync(f.source);
    bytes += buf.length;
    // Count newlines as a rough proxy for billable lines. Doesn't need
    // to match the server exactly; estimate is a sanity check.
    for (let i = 0; i < buf.length; i++) if (buf[i] === 0x0A) lines++;
  }
  return { files: files.length, bytes: bytes, lines: lines };
}

function buildEstimateReport(stats, usage, usageError, config) {
  const r = {
    input: {
      files: stats.files,
      bytes: stats.bytes,
      lines: stats.lines,
      bytesHuman: humanBytes(stats.bytes),
    },
    quota: null,
    providerKey: null,
    gate: "ok",
    notes: [],
  };
  if (config.label) r.label = config.label;
  if (usageError) {
    r.gate = "warn";
    r.notes.push("Could not read quota: [" + usageError.code + "] " + usageError.message);
    return r;
  }
  if (!usage || !usage.ok) {
    r.gate = "warn";
    r.notes.push("Quota endpoint returned ok:false " + (usage && usage.error ? "(" + usage.error + ")" : ""));
    return r;
  }
  // Surface the quota counters AS-IS — actionsRemaining is the meaningful
  // unit for AI calls; the obfuscation API has its own cost model (bytes)
  // that customers track in their dashboard. We're not trying to predict
  // exact obfuscation cost here, just give the user signal.
  r.quota = {
    tier: usage.tier,
    previewMode: !!usage.previewMode,
    actions:  { used: usage.actionsUsed, cap: usage.actionsCap, remaining: usage.actionsRemaining },
    tokens:   { used: usage.tokensUsed,  cap: usage.tokensCap,  remaining: usage.tokensRemaining },
    cost:     { usedCents: usage.approxCostCents, capCents: usage.costCapCents, remainingCents: usage.costRemainingCents },
    asOfUtc:  usage.asOfUtc,
  };
  r.providerKey = normalizeProviderKeyHealth(usage.providerKey);
  // Heuristics for the gate:
  //   - fail when remaining actions hit zero (build cannot finish)
  //   - warn when remaining actions < 5 OR remaining cost < 20% of cap
  if (usage.actionsRemaining === 0) {
    r.gate = "fail";
    r.notes.push("Action quota exhausted — subscribe or wait for monthly reset.");
  } else {
    if (usage.actionsRemaining < 5) {
      r.gate = "warn";
      r.notes.push("Action quota nearly exhausted: " + usage.actionsRemaining + " left this month.");
    }
    if (usage.costCapCents > 0 && usage.costRemainingCents / usage.costCapCents < 0.20) {
      if (r.gate === "ok") r.gate = "warn";
      r.notes.push("Cost cap below 20%: $" + (usage.costRemainingCents / 100).toFixed(2) + " of $"
        + (usage.costCapCents / 100).toFixed(2) + " remaining.");
    }
  }
  return r;
}

function normalizeProviderKeyHealth(providerKey) {
  if (!providerKey || typeof providerKey !== "object") return null;
  return {
    hasKey: !!providerKey.hasKey,
    provider: String(providerKey.provider || ""),
    status: String(providerKey.status || "unknown"),
    label: String(providerKey.label || providerKey.status || "Unknown"),
    testDue: !!providerKey.testDue,
    rotationDue: !!providerKey.rotationDue,
    lastTestStatus: String(providerKey.lastTestStatus || ""),
    lastTestUtc: providerKey.lastTestUtc || null,
    nextTestDueUtc: providerKey.nextTestDueUtc || null,
    rotationDueUtc: providerKey.rotationDueUtc || null,
    recommendedAction: String(providerKey.recommendedAction || "")
  };
}

function humanBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

function writeEstimateReport(r, asJson) {
  if (asJson) {
    process.stdout.write(JSON.stringify({ estimate: r }, null, 2) + "\n");
    return;
  }
  process.stdout.write("Build inputs:  " + r.input.files + " file(s)   "
    + r.input.bytesHuman + "   " + r.input.lines + " line(s)\n");
  if (r.quota) {
    const q = r.quota;
    process.stdout.write("Quota (" + q.tier + (q.previewMode ? ", preview" : "") + "):\n");
    process.stdout.write("    actions: " + q.actions.used + " / " + q.actions.cap + "   (" + q.actions.remaining + " remaining)\n");
    process.stdout.write("    tokens:  " + q.tokens.used + " / " + q.tokens.cap + "   (" + q.tokens.remaining + " remaining)\n");
    process.stdout.write("    cost:    " + q.cost.usedCents + " / " + q.cost.capCents + " cents   (" + q.cost.remainingCents + " remaining)\n");
    process.stdout.write("    as of:   " + q.asOfUtc + "\n");
  }
  if (r.providerKey) {
    const k = r.providerKey;
    const provider = k.provider ? " (" + k.provider + ")" : "";
    process.stdout.write("AI key health: " + k.label + provider + " [" + k.status + "]\n");
    if (k.nextTestDueUtc) process.stdout.write("    next test due:    " + k.nextTestDueUtc + "\n");
    if (k.rotationDueUtc) process.stdout.write("    rotation review:  " + k.rotationDueUtc + "\n");
    if (k.recommendedAction) process.stdout.write("    action:           " + k.recommendedAction + "\n");
  }
  for (const note of r.notes) process.stdout.write("[" + r.gate.toUpperCase() + "] " + note + "\n");
  process.stdout.write("Gate: " + r.gate.toUpperCase() + "\n");
}

// AI precheck: walks the resolved file set, calls ai.compatCheck on each,
// aggregates findings, evaluates the configurable fail-on gate.
//
// Returns: { ok, summary: { files, errors, warnings, infos, failOn }, results: [...] }
// Throws on transport-level errors (network/auth) — those should not be
// silently swallowed; CI needs to see them just like an obfuscation failure.
async function runAiPrecheck(config, files, args) {
  const ai = require("../ai.js");
  const failOn = (args.aiPrecheckFailOn || "error").toLowerCase();
  const framework = (config.framework || config.Framework || null);
  const results = [];
  let totErr = 0, totWarn = 0, totInfo = 0;
  for (const file of files) {
    const source = fs.readFileSync(file.source, "utf8");
    let env;
    try {
      env = await ai.compatCheck({
        apiKey: config.apiKey, apiPassword: config.apiPassword,
        endpoint: config.endpoint && config.endpoint.replace(/\/HttpApi\.ashx.*$/i, ""),
        source: source, framework: framework,
      });
    } catch (err) {
      // Surface transport-level failures so the user sees auth/network bugs
      // instead of a confusing "0 findings" pass.
      results.push({ file: file.relative, ok: false, error: err.code || "internal_error", message: err.message });
      return { ok: false, summary: { files: files.length, errors: 0, warnings: 0, infos: 0, failOn: failOn, transportError: true }, results: results };
    }
    if (!env.ok) {
      results.push({ file: file.relative, ok: false, error: env.error, message: env.message });
      continue;
    }
    const sum = env.report.summary;
    totErr  += sum.errors   || 0;
    totWarn += sum.warnings || 0;
    totInfo += sum.infos    || 0;
    results.push({ file: file.relative, ok: true, summary: sum, findings: env.report.findings });
  }
  let gateOk = true;
  if (failOn === "error"   && totErr  > 0) gateOk = false;
  if (failOn === "warning" && (totErr + totWarn) > 0) gateOk = false;
  return {
    ok: gateOk,
    summary: { files: files.length, errors: totErr, warnings: totWarn, infos: totInfo, failOn: failOn },
    results: results,
  };
}

function writeAiPrecheckReport(gate, asJson) {
  if (asJson) {
    process.stdout.write(JSON.stringify({ aiPrecheck: gate }, null, 2) + "\n");
    return;
  }
  const s = gate.summary;
  process.stdout.write("AI precheck: " + s.files + " file(s) scanned   "
    + s.errors + " error(s)  " + s.warnings + " warning(s)  " + s.infos + " info(s)   (fail-on=" + s.failOn + ")\n");
  for (const r of gate.results) {
    if (!r.ok) {
      process.stdout.write("  [ERR] " + r.file + ": [" + r.error + "] " + r.message + "\n");
      continue;
    }
    if ((r.summary.errors + r.summary.warnings + r.summary.infos) === 0) continue;
    process.stdout.write("  " + r.file + "  (" + r.summary.errors + "e " + r.summary.warnings + "w " + r.summary.infos + "i)\n");
    for (const f of (r.findings || [])) {
      process.stdout.write("      [" + f.severity.toUpperCase() + "] " + f.category
        + " @" + f.line + ":" + f.column + " - " + f.message + "\n");
    }
  }
  process.stdout.write("Gate: " + (gate.ok ? "PASS" : "FAIL") + "\n");
}

function writeReportFile(reportPath, result, config) {
  // Strip the heavy file payload before persisting — the report's purpose is
  // symbolication metadata (BuildId, fingerprint, identifier maps, warnings),
  // not a second copy of the protected source. Callers who want the source
  // already have it written to config.output by writeResults().
  const trimmed = {
    Type: result.Type,
    Report: result.Report || null,
    FileNames: (result.Items || []).map((it) => it && it.FileName).filter(Boolean),
    GeneratedUtc: new Date().toISOString(),
    Label: config.label || null
  };
  const dir = path.dirname(reportPath);
  if (dir && dir !== "." && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(reportPath, `${JSON.stringify(trimmed, null, 2)}\n`, "utf8");
}

if (require.main === module) {
  main().catch((error) => {
    if (error && error.exitCode) {
      // jso ai subcommand already wrote its own error output.
      process.exitCode = error.exitCode;
      return;
    }
    process.stderr.write(`jso-protector: ${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  DEFAULT_ENDPOINT,
  OPTION_REFERENCE,
  PRESET_OPTIONS,
  buildMigrationMapSummary,
  buildMigrationNextCommands,
  buildMigrationReportSummary,
  buildProtectionManifest,
  buildCompetitorGapReport,
  buildCompetitorGapPlan,
  buildCompetitorGapReviewArtifacts,
  buildCompetitorGapReviewAssistant,
  buildMigrationReviewReport,
  buildMigrationReviewAssistant,
  renderMigrationReviewText,
  writeMigrationReviewReport,
  buildIdentifierCacheReviewReport,
  buildIdentifierCacheReviewAssistant,
  renderIdentifierCacheReviewText,
  writeIdentifierCacheReviewReport,
  buildRuntimeDefenseReviewReport,
  buildRuntimeDefenseReviewAssistant,
  renderRuntimeDefenseReviewText,
  writeRuntimeDefenseReviewReport,
  buildRequest,
  buildRequestFromItems,
  hasNamedSets,
  validateNamedSets,
  groupFilesByNamedSets,
  applyNamedSetToConfig,
  protectGroupedFiles,
  buildProtectionItems,
  buildProtectionItemsFromInputItems,
  describeProtectionTransforms,
  addProtectionSummary,
  buildCodeProtectionPlan,
  buildHtmlProtectionPlan,
  buildItemsManifest,
  buildStdinManifest,
  verifyVmProofReport,
  buildVmProofPack,
  renderVmProofPackMarkdown,
  buildAiResistanceEvidenceReport,
  renderAiResistanceEvidenceText,
  buildScriptInventoryFromSnapshot,
  buildPaymentPageHeadersFromHar,
  buildScriptInventoryAudit,
  renderScriptInventoryAuditMarkdown,
  assertSizeBudgets,
  checkSizeBudgets,
  collectAssets,
  collectFiles,
  copyAssets,
  createExampleConfig,
  getPackageMetadata,
  getRedactedConfig,
  globLikeMatch,
  hasConditionalMarkers,
  hasProtectMarkers,
  validateConditionalMarkers,
  validateProtectMarkers,
  findMarkedHtmlScripts,
  validateMarkedHtmlScripts,
  hasMarkedHtmlScriptAttributes,
  hasHtmlProtectionMarkers,
  formatSourceLocation,
  splitConditionalCode,
  splitProtectMarkedCode,
  stripSourceMapComments,
  finalizeProtectedCode,
  composeProtectionOutput,
  composeProtectionItemOutput,
  isIncluded,
  isExcluded,
  listJsConfuserMigrationMap,
  listJavascriptObfuscatorMigrationMap,
  explainJsConfuserCompatibilityOption,
  explainCompatibilityOption,
  listOptions,
  listPresets,
  mergeConfig,
  migrateJsConfuserConfig,
  migrateJavascriptObfuscatorConfig,
  normalizeExtensions,
  normalizeDomainLockList,
  translateJsConfuserConfigOptions,
  translateJavascriptObfuscatorConfigOptions,
  parseArgs,
  parsePositiveNumber,
  parseOptionOverrides,
  parseOptionValue,
  presetFromJavascriptObfuscatorPreset,
  postJson,
  protectCode,
  protectCodeDetailed,
  protectItems,
  readConfig,
  readEnv,
  readStdin,
  resolveEnv,
  buildReleasePlan,
  runReleaseCheck,
  runDoctor,
  scanCompatibilityRisks,
  scanTextCompatibilityRisks,
  validateProtectionConfig,
  writeCompetitorGapReport,
  writeMigrationReport,
  writeJsConfuserMigrationMap,
  writeMigrationMap,
  writeJsConfuserCompatibilityExplanation,
  writeCompatibilityExplanation,
  writeCompatibilityScanReport,
  writeLocalOnlyGuidance,
  readManifest,
  writeValidationReport,
  writeReleaseCheckReport,
  auditManifestSourceMaps,
  verifyManifestOutputs,
  writeManifestVerificationReport,
  buildSourceMapEvidenceReport,
  buildSourceMapReviewAssistant,
  renderSourceMapEvidenceText,
  writeSourceMapEvidenceReport,
  buildDeploymentHygieneEvidenceReport,
  renderDeploymentHygieneEvidenceText,
  writeDeploymentHygieneEvidenceReport,
  buildRuntimeIncidentEvidenceReport,
  renderRuntimeIncidentEvidenceText,
  writeRuntimeIncidentEvidenceReport,
  writeVmProofPackReport,
  writeScriptInventoryFromSnapshotReport,
  writePaymentPageHeadersFromHarReport,
  writeScriptInventoryAuditReport,
  writeVersion,
  sha256,
  writeResults,
  writeResolvedConfig,
  writeManifest,
  main
};
