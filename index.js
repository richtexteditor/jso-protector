"use strict";

const path = require("node:path");
const core = require("./bin/jso-protector.js");
const ai   = require("./ai.js");

const JAVASCRIPT_OBFUSCATOR_OPTION_KEYS = [
  "compact",
  "controlFlowFlattening",
  "deadCodeInjection",
  "deadCodeInjectionThreshold",
  "domainLock",
  "identifierNamesGenerator",
  "optionsPreset",
  "parseHtml",
  "renameGlobals",
  "renameProperties",
  "reservedNames",
  "strictMode",
  "stringArray",
  "stringArrayEncoding",
  "stringArrayThreshold",
  "target",
  "unicodeEscapeSequence"
];

const JS_CONFUSER_OPTION_KEYS = [
  "compact",
  "controlFlowFlattening",
  "deadCode",
  "duplicateLiteralsRemoval",
  "globalConcealing",
  "identifierGenerator",
  "lock",
  "minify",
  "preset",
  "renameGlobals",
  "renameVariables",
  "stringCompression",
  "stringConcealing",
  "stringEncoding",
  "stringSplitting",
  "target"
];

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

function createProtectionConfig(options = {}) {
  const normalizedOptions = normalizeCompatibilityOptions(options);
  const configPath = normalizedOptions.config || normalizedOptions.configFile;
  const fileConfig = configPath ? core.readConfig(configPath, { mode: options.mode }) : {};
  const overrides = { ...normalizedOptions };
  delete overrides.config;
  delete overrides.configFile;

  const mergedConfig = {
    ...fileConfig,
    ...overrides,
    options: {
      ...(fileConfig.options || {}),
      ...(overrides.options || {})
    }
  };

  const config = core.mergeConfig(mergedConfig, {});
  Object.defineProperty(config, "__jsoMergedConfig", {
    value: true,
    enumerable: false
  });
  Object.defineProperty(config, "__rawConfig", {
    value: mergedConfig,
    enumerable: false
  });
  return config;
}

function normalizeCompatibilityOptions(options) {
  if (!options || typeof options !== "object") return options;

  const normalized = {
    ...options
  };
  const javascriptObfuscatorOptions = {
    ...(options.javascriptObfuscatorOptions || {})
  };
  for (const key of JAVASCRIPT_OBFUSCATOR_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(options, key)) {
      javascriptObfuscatorOptions[key] = options[key];
    }
  }

  const jsConfuserOptions = {
    ...(options.jsConfuserOptions || {})
  };
  if (!Object.keys(jsConfuserOptions).length && hasTopLevelJsConfuserOptions(options)) {
    for (const key of JS_CONFUSER_OPTION_KEYS) {
      if (Object.prototype.hasOwnProperty.call(options, key)) {
        jsConfuserOptions[key] = options[key];
      }
    }
  }

  if (!Object.keys(javascriptObfuscatorOptions).length && !Object.keys(jsConfuserOptions).length) {
    return options;
  }

  const translatedJavascriptObfuscator = Object.keys(javascriptObfuscatorOptions).length
    ? translateJavascriptObfuscatorOptions(javascriptObfuscatorOptions)
    : {};
  const translatedJsConfuser = Object.keys(jsConfuserOptions).length
    ? translateJsConfuserOptions(jsConfuserOptions)
    : {};

  delete normalized.javascriptObfuscatorOptions;
  delete normalized.jsConfuserOptions;

  if (!options.javascriptObfuscatorOptions) {
    for (const key of JAVASCRIPT_OBFUSCATOR_OPTION_KEYS) {
      delete normalized[key];
    }
  }

  if (!options.jsConfuserOptions && hasTopLevelJsConfuserOptions(options)) {
    for (const key of JS_CONFUSER_OPTION_KEYS) {
      delete normalized[key];
    }
  }

  Object.assign(normalized, translatedJavascriptObfuscator, translatedJsConfuser);
  normalized.options = {
    ...(translatedJavascriptObfuscator.options || {}),
    ...(translatedJsConfuser.options || {}),
    ...(options.options || {})
  };
  return normalized;
}

function translateJavascriptObfuscatorOptions(sourceOptions = {}, overrides = {}) {
  const source = sourceOptions || {};
  const translated = {
    preset: "balanced",
    options: {
      OptimizationMode: "Web"
    }
  };

  if (source.optionsPreset !== undefined) {
    translated.preset = core.presetFromJavascriptObfuscatorPreset(source.optionsPreset);
  }

  mapBooleanOption(source, "stringArray", translated.options, "MoveStrings");
  mapBooleanOption(source, "stringArrayIndexShift", translated.options, "StringArrayIndexShift");
  mapBooleanOption(source, "stringArrayShuffle", translated.options, "StringArrayShuffle");
  mapBooleanOption(source, "stringArrayRotate", translated.options, "StringArrayRotate");
  if (source.stringArrayIndexesType !== undefined) translated.options.StringArrayIndexesType = normalizeStringArrayIndexesType(source.stringArrayIndexesType).join("\n");
  mapBooleanOption(source, "stringArrayCallsTransform", translated.options, "StringArrayCallsTransform");
  if (source.stringArrayCallsTransformThreshold !== undefined) translated.options.StringArrayCallsTransformThreshold = normalizeProbability(source.stringArrayCallsTransformThreshold, "stringArrayCallsTransformThreshold");
  if (source.stringArrayWrappersCount !== undefined) translated.options.StringArrayWrappersCount = normalizeIntegerRange(source.stringArrayWrappersCount, "stringArrayWrappersCount", 0, 10);
  mapExplicitBooleanOption(source, "stringArrayWrappersChainedCalls", translated.options, "StringArrayWrappersChainedCalls");
  if (source.stringArrayWrappersParametersMaxCount !== undefined) translated.options.StringArrayWrappersParametersMaxCount = normalizeIntegerRange(source.stringArrayWrappersParametersMaxCount, "stringArrayWrappersParametersMaxCount", 2, 5);
  if (source.stringArrayWrappersType !== undefined) translated.options.StringArrayWrappersType = normalizeStringArrayWrappersType(source.stringArrayWrappersType);
  mapBooleanOption(source, "transformObjectKeys", translated.options, "TransformObjectKeys");
  mapBooleanOption(source, "splitStrings", translated.options, "SplitStrings");
  if (source.splitStringsChunkLength !== undefined) translated.options.SplitStringsChunkLength = normalizeSplitStringsChunkLength(source.splitStringsChunkLength);
  mapBooleanOption(source, "unicodeEscapeSequence", translated.options, "EncodeStrings");
  mapBooleanOption(source, "controlFlowFlattening", translated.options, "DeepObfuscate");
  mapBooleanOption(source, "controlFlowFlattening", translated.options, "FlatTransform");
  mapBooleanOption(source, "deadCodeInjection", translated.options, "AddDeadCode");
  mapBooleanOption(source, "renameGlobals", translated.options, "RenameGlobals");
  mapBooleanOption(source, "renameProperties", translated.options, "RenameMembers");
  mapExplicitBooleanOption(source, "selfDefending", translated.options, "SelfDefending");
  mapExplicitBooleanOption(source, "debugProtection", translated.options, "DebugProtection");
  if (source.debugProtectionInterval !== undefined) translated.options.DebugProtectionIntervalMilliseconds = normalizeDebugProtectionInterval(source.debugProtectionInterval);
  mapExplicitBooleanOption(source, "disableConsoleOutput", translated.options, "DisableConsoleOutput");
  mapExplicitBooleanOption(source, "numbersToExpressions", translated.options, "EncodeNumbers");
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
    const threshold = Number(source.deadCodeInjectionThreshold);
    translated.options.DeadcodeLevel = threshold >= 0.66 ? "High" : threshold >= 0.33 ? "Medium" : "Low";
  }

  if (source.identifierNamesGenerator !== undefined) {
    const generator = String(source.identifierNamesGenerator).toLowerCase();
    translated.options.IdentityStyle = generator.includes("hex") ? "v1hex" : "v2abcd";
  }

  if (source.compact === true) {
    translated.options.SelfCompression = true;
    translated.options.CompressionRatio = "Best";
  } else if (source.compact === false) {
    translated.options.WriteFormats = true;
  }

  if (source.target !== undefined) {
    const target = String(source.target).toLowerCase();
    translated.options.OptimizationMode = target.includes("node") ? "NodeJS" : "Web";
  }

  if (source.parseHtml !== undefined) {
    translated.parseHtml = source.parseHtml === true;
  }

  if (source.strictMode !== undefined) {
    translated.strictMode = source.strictMode;
  }

  if (Array.isArray(source.reservedNames) && source.reservedNames.length) {
    translated.reservedNames = source.reservedNames.map((value) => String(value));
  }

  if (source.domainLock !== undefined) {
    const domains = core.normalizeDomainLockList(source.domainLock);
    if (domains.length) {
      translated.options.LockDomain = true;
      translated.options.LockDomainList = domains.join("\n");
    }
  }

  return {
    ...translated,
    ...overrides,
    options: {
      ...translated.options,
      ...(overrides.options || {})
    }
  };
}

function presetFromJsConfuserPreset(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized || normalized === "low") return "standard";
  if (normalized === "medium") return "balanced";
  if (normalized === "high") return "maximum";
  throw new Error(`Unknown JS-Confuser preset "${value}". Use low, medium, or high.`);
}

function hasTopLevelJsConfuserOptions(options) {
  if (!options || typeof options !== "object") return false;
  if (JS_CONFUSER_DETECT_KEYS.some((key) => Object.prototype.hasOwnProperty.call(options, key))) {
    return true;
  }
  const preset = String(options.preset || "").trim().toLowerCase();
  return preset === "low" || preset === "medium" || preset === "high";
}

function translateJsConfuserOptions(sourceOptions = {}, overrides = {}) {
  const source = sourceOptions || {};
  const translated = {
    preset: "balanced",
    options: {
      OptimizationMode: "Web"
    }
  };

  if (source.preset !== undefined) {
    translated.preset = presetFromJsConfuserPreset(source.preset);
  }

  mapBooleanOption(source, "renameVariables", translated.options, "ReplaceNames");
  mapBooleanOption(source, "renameGlobals", translated.options, "RenameGlobals");
  mapBooleanOption(source, "stringEncoding", translated.options, "EncodeStrings");
  mapBooleanOption(source, "stringConcealing", translated.options, "EncryptStrings");
  mapBooleanOption(source, "duplicateLiteralsRemoval", translated.options, "MoveStrings");
  mapJsConfuserEnablementOption(source, "stringSplitting", translated.options, "SplitStrings");
  mapBooleanOption(source, "controlFlowFlattening", translated.options, "DeepObfuscate");
  mapBooleanOption(source, "controlFlowFlattening", translated.options, "FlatTransform");
  mapBooleanOption(source, "deadCode", translated.options, "AddDeadCode");
  mapBooleanOption(source, "globalConcealing", translated.options, "RenameGlobals");
  mapExplicitBooleanOption(source, "hexadecimalNumbers", translated.options, "EncodeNumbers");

  if (source.stringCompression === true || source.minify === true || source.compact === true) {
    translated.options.SelfCompression = true;
    translated.options.CompressionRatio = "Best";
  } else if (source.minify === false || source.compact === false) {
    translated.options.WriteFormats = true;
  }

  if (source.identifierGenerator !== undefined) {
    const generator = String(source.identifierGenerator).toLowerCase();
    translated.options.IdentityStyle = generator.includes("hex") ? "v1hex" : "v2abcd";
  }

  if (source.target !== undefined) {
    const target = String(source.target).toLowerCase();
    translated.options.OptimizationMode = target.includes("node") ? "NodeJS" : "Web";
  }

  const lock = source.lock && typeof source.lock === "object" && !Array.isArray(source.lock)
    ? source.lock
    : null;
  if (lock && lock.domainLock !== undefined) {
    const domains = core.normalizeDomainLockList(lock.domainLock);
    if (domains.length) {
      translated.options.LockDomain = true;
      translated.options.LockDomainList = domains.join("\n");
    }
  }
  if (lock && lock.endDate !== undefined) {
    translated.options.LockDate = true;
    translated.options.LockDateValue = formatLockDateValue(lock.endDate);
  }
  if (lock && lock.antiDebug !== undefined) {
	translated.options.DebugProtection = jsConfuserLockEnabled(lock.antiDebug);
  }
  if (lock && lock.integrity !== undefined) {
	translated.options.SelfDefending = jsConfuserLockEnabled(lock.integrity);
  }
  if (lock && lock.selfDefending !== undefined) {
	translated.options.SelfDefending = jsConfuserLockEnabled(lock.selfDefending) || translated.options.SelfDefending === true;
  }
  if (lock && lock.startDate !== undefined) {
    translated.options.LockStartDate = true;
    translated.options.LockStartDateValue = formatLockDateValue(lock.startDate);
  }
  if (lock && lock.countermeasures !== undefined) {
    translated.jsConfuserLockCountermeasures = formatReviewString(lock.countermeasures);
  }
  if (lock && lock.tamperProtection !== undefined) {
	translated.options.AntiMonkeyPatching = jsConfuserLockEnabled(lock.tamperProtection);
  }

  return {
    ...translated,
    ...overrides,
    options: {
      ...translated.options,
      ...(overrides.options || {})
    }
  };
}

function jsConfuserLockEnabled(value) {
  return value === true || (typeof value === "number" && Number.isFinite(value) && value > 0);
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

function mapBooleanOption(source, sourceKey, target, targetKey) {
  if (source[sourceKey] === true) target[targetKey] = true;
}

function mapExplicitBooleanOption(source, sourceKey, target, targetKey) {
  if (typeof source[sourceKey] === "boolean") target[targetKey] = source[sourceKey];
}

function mapJsConfuserEnablementOption(source, sourceKey, target, targetKey) {
  const value = source[sourceKey];
  if (typeof value === "function") throw new Error(`${sourceKey} selector functions require manual migration review`);
  if (typeof value === "boolean") target[targetKey] = value;
  else if (typeof value === "number" && Number.isFinite(value) && value >= 0) target[targetKey] = value > 0;
}

function normalizeDebugProtectionInterval(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || (number > 0 && number < 100) || number > 60000) {
    throw new Error("debugProtectionInterval must be 0 or an integer from 100 through 60000 milliseconds");
  }
  return number;
}

function normalizeRuntimeRedirectUrl(value) {
  const text = String(value || "").trim();
  const safeRelative = text.startsWith("/") && !text.startsWith("//") && !text.includes("\\");
  let safeAbsolute = false;
  try {
    const parsed = new URL(text);
    safeAbsolute = parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch { }
  if (!safeRelative && !safeAbsolute) throw new Error("domainLockRedirectUrl must be an HTTP(S) URL or same-origin root-relative path");
  return text;
}

function normalizeSeedValue(value) {
  if ((typeof value !== "string" && typeof value !== "number") || (typeof value === "number" && !Number.isFinite(value))) {
    throw new Error("seed must be a finite number or non-empty string");
  }
  const text = String(value).trim();
  if (!text) throw new Error("seed must be a finite number or non-empty string");
  return text;
}

function normalizeSplitStringsChunkLength(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 1024) throw new Error("splitStringsChunkLength must be an integer from 1 through 1024");
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

function normalizeStringArrayIndexesType(value) {
  const values = Array.isArray(value) ? value : [value];
  if (!values.length) throw new Error("stringArrayIndexesType must include at least one supported value");
  const supported = new Set(["hexadecimal-number", "hexadecimal-numeric-string"]);
  const normalized = values.map((item) => String(item).trim().toLowerCase());
  if (normalized.some((item) => !supported.has(item))) {
    throw new Error("stringArrayIndexesType supports only hexadecimal-number and hexadecimal-numeric-string");
  }
  return [...new Set(normalized)];
}

function ensureProtectionConfig(options) {
  if (options && options.__jsoMergedConfig) return options;
  return createProtectionConfig(options || {});
}

async function protectItems(options, items) {
  return core.protectItems(ensureProtectionConfig(options), items);
}

async function protectCode(options, code, fileName = "bundle.js") {
  return core.protectCode(ensureProtectionConfig(options), code, fileName);
}

function createObfuscationResult(code, fileName, result) {
  return {
    code,
    fileName,
    result,
    getObfuscatedCode() {
      return code;
    },
    toString() {
      return code;
    },
    getSourceMap() {
      return null;
    },
    getIdentifierNamesCache() {
      return null;
    }
  };
}

async function obfuscate(code, options = {}, fileName = "bundle.js") {
  const config = ensureProtectionConfig(options);
  const protectedEntry = await protectSourceEntry(config, String(code), fileName);
  return createObfuscationResult(protectedEntry.code, fileName, protectedEntry.result);
}

async function obfuscateCode(code, options = {}, fileName = "bundle.js") {
  return obfuscate(code, options, fileName);
}

async function obfuscateMultiple(sourceCodesObject, options = {}) {
  if (!sourceCodesObject || typeof sourceCodesObject !== "object" || Array.isArray(sourceCodesObject)) {
    throw new Error("obfuscateMultiple requires an object map of file names to source code.");
  }

  const entries = Object.entries(sourceCodesObject);
  const config = ensureProtectionConfig(options);
  const items = [];
  const plans = new Map();

  for (const [fileName, code] of entries) {
    const plan = buildSourceEntryProtectionPlan(config, fileName, String(code));
    items.push(...plan.items);
    plans.set(normalizeName(fileName), plan);
  }

  const result = await core.protectItems(config, items);
  const byName = new Map((result.Items || []).map((item) => [
    normalizeName(item.FileName),
    item
  ]));
  const output = {};

  for (const [fileName] of entries) {
    const normalizedName = normalizeName(fileName);
    const plan = plans.get(normalizedName);
    const code = composeSourceEntryOutput(fileName, plan, byName, config);
    if (code === null) {
      throw new Error(`API response did not include output for ${fileName}`);
    }
    output[fileName] = createObfuscationResult(code, fileName, result);
  }

  return output;
}

async function protectSourceEntry(config, code, fileName) {
  const plan = buildSourceEntryProtectionPlan(config, fileName, code);
  const result = await core.protectItems(config, plan.items);
  const byName = new Map((result.Items || []).map((item) => [
    normalizeName(item.FileName),
    item
  ]));
  const output = composeSourceEntryOutput(fileName, plan, byName, config);
  if (output === null) {
    throw new Error(`API response did not include output for ${fileName}`);
  }
  return { code: output, result };
}

function composeSourceEntryOutput(fileName, plan, byName, config) {
  const normalizedName = normalizeName(fileName);
  if (plan && plan.transform) {
    return core.finalizeProtectedCode(core.composeProtectionOutput(plan.transform, byName), config);
  }
  const item = byName.get(normalizedName);
  if (!item) return null;
  return core.finalizeProtectedCode(item.FileCode || "", config);
}

function buildSourceEntryProtectionPlan(config, fileName, code) {
  const ext = path.extname(fileName).toLowerCase();
  if (config.parseHtml && config.markupExtensions.includes(ext)) {
    return core.buildHtmlProtectionPlan(config, fileName, code);
  }
  return core.buildCodeProtectionPlan(config, fileName, code);
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

function getOptionsByPreset(optionsPreset = "standard") {
  const preset = String(optionsPreset || "standard").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(core.PRESET_OPTIONS, preset)) {
    throw new Error(`Unknown preset "${optionsPreset}". Use standard, balanced, or maximum.`);
  }
  return { ...core.PRESET_OPTIONS[preset] };
}

function summarizePlan(config, files, assets, protection = null) {
  const summary = {
    endpoint: config.endpoint,
    projectName: config.projectName,
    preset: config.preset,
    input: config.input,
    output: config.output,
    files: files.map((file) => file.relative),
    assets: assets.map((file) => file.relative),
    options: Object.keys(config.options).filter((key) => key !== "reservedNames")
  };
  return protection ? core.addProtectionSummary(summary, protection) : summary;
}

function planProtection(options = {}) {
  const config = ensureProtectionConfig(options);
  const files = core.collectFiles(config.input, config.output, config.extensions, config.exclude, config.include, config.markupExtensions);
  const assets = config.copyAssets ? core.collectAssets(config.input, config.output, files, config.assetExclude) : [];
  const protection = core.buildProtectionItems(config, files);

  return {
    config,
    files,
    assets,
    protection,
    summary: summarizePlan(config, files, assets, protection)
  };
}

async function protectFiles(options = {}) {
  const plan = planProtection(options);
  if (!plan.files.length) {
    throw new Error("No matching input files found.");
  }

  let result;
  let manifestTransforms = plan.protection.transforms;
  if (core.hasNamedSets(plan.config)) {
    const grouped = await core.protectGroupedFiles(plan.config, plan.files);
    result = grouped.result;
    manifestTransforms = grouped.transforms;
  } else {
    const request = core.buildRequestFromItems(plan.config, plan.protection.items);
    result = await core.protectItems(plan.config, request.Items);
    core.writeResults(plan.files, result, plan.protection.transforms, plan.config);
  }
  core.copyAssets(plan.assets);

  const manifest = core.buildProtectionManifest(plan.config, plan.files, plan.assets, result, manifestTransforms);
  core.assertSizeBudgets(manifest, plan.config);
  core.writeManifest(plan.config.manifest, manifest);

  return {
    ...plan.summary,
    type: result.Type,
    written: plan.files.map((file) => file.target),
    copied: plan.assets.map((file) => file.target),
    manifestPath: plan.config.manifest,
    manifest,
    result
  };
}

async function protectDirectory(options = {}) {
  return protectFiles(options);
}

async function obfuscateFiles(options = {}) {
  return protectFiles(options);
}

async function obfuscateDirectory(options = {}) {
  return protectDirectory(options);
}

async function protectFile(options = {}, sourcePath, outputPath) {
  const fileOptions = { ...options };
  if (sourcePath) fileOptions.input = sourcePath;
  if (outputPath) {
    fileOptions.output = outputPath;
  } else if (sourcePath && !options.output) {
    const parsed = path.parse(sourcePath);
    fileOptions.output = path.join(parsed.dir, `${parsed.name}.protected${parsed.ext || ".js"}`);
  }

  const result = await protectFiles({
    ...fileOptions,
    copyAssets: false
  });

  if (result.written.length !== 1) {
    throw new Error(`Expected one protected file, wrote ${result.written.length}.`);
  }

  return result;
}

async function obfuscateFile(options = {}, sourcePath, outputPath) {
  return protectFile(options, sourcePath, outputPath);
}

module.exports = {
  ...core,
  createProtectionConfig,
  ensureProtectionConfig,
  obfuscate,
  obfuscateCode,
  obfuscateDirectory,
  obfuscateFile,
  obfuscateFiles,
  obfuscateMultiple,
  getOptionsByPreset,
  protectCode,
  protectDirectory,
  protectFile,
  protectFiles,
  planProtection,
  protectItems,
  translateJsConfuserOptions,
  translateJavascriptObfuscatorOptions,
  ai,
};
