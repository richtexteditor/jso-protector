"use strict";

const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function createMetroSerializer(options = {}) {
  const baseSerializer = typeof options.serializer === "function"
    ? options.serializer
    : defaultSerializer;

  return async function jsoProtectorMetroSerializer(entryPoint, preModules, graph, serializerOptions) {
    const result = await Promise.resolve(baseSerializer(entryPoint, preModules, graph, serializerOptions));
    const bundle = normalizeSerializerResult(result);
    if (!bundle || typeof bundle.code !== "string") {
      return result;
    }

    const fileName = resolveBundleFileName(entryPoint, serializerOptions, options);
    const config = createProtectionConfig({
      input: serializerOptions && serializerOptions.projectRoot ? serializerOptions.projectRoot : process.cwd(),
      output: serializerOptions && serializerOptions.projectRoot ? serializerOptions.projectRoot : process.cwd(),
      ...options
    });

    if (!shouldProtectBundle(fileName, config, options)) {
      return result;
    }

    const inputItems = [{
      FileName: fileName,
      FileCode: bundle.code,
      SourcePath: entryPoint || fileName,
      OutputPath: fileName
    }];
    const protection = buildProtectionItemsFromInputItems(config, inputItems);
    const apiResult = await (options.protectItems || protectItems)(config, protection.items);
    const manifest = buildItemsManifest(config, inputItems, apiResult, () => fileName, protection.transforms);
    assertSizeBudgets(manifest, config);

    const protectedCode = composeProtectionItemOutput(fileName, apiResult, protection.transforms, config);
    if (config.manifest) {
      writeManifest(config.manifest, manifest);
    }

    return serializeLike(result, bundle, protectedCode, options);
  };
}

function withJsoProtectorMetro(baseConfig = {}, options = {}) {
  const config = baseConfig || {};
  const serializer = config.serializer || {};
  return {
    ...config,
    serializer: {
      ...serializer,
      customSerializer: createMetroSerializer({
        ...options,
        serializer: options.serializer || serializer.customSerializer
      })
    }
  };
}

async function defaultSerializer() {
  throw new Error("Metro customSerializer is required. Pass the existing serializer with options.serializer or use withJsoProtectorMetro(baseConfig, options).");
}

function normalizeSerializerResult(result) {
  if (!result) return null;
  if (typeof result === "string" || Buffer.isBuffer(result)) {
    return { code: Buffer.isBuffer(result) ? result.toString("utf8") : result, kind: "string" };
  }
  if (typeof result === "object" && (typeof result.code === "string" || Buffer.isBuffer(result.code))) {
    return { code: Buffer.isBuffer(result.code) ? result.code.toString("utf8") : result.code, kind: "object" };
  }
  return null;
}

function serializeLike(original, normalized, code, options) {
  const removeSourceMaps = options.removeSourceMaps !== false;
  if (normalized.kind === "string") {
    return code;
  }

  const next = {
    ...original,
    code
  };
  if (removeSourceMaps) {
    delete next.map;
  }
  return next;
}

function resolveBundleFileName(entryPoint, serializerOptions = {}, options = {}) {
  if (options.fileName) return normalizeName(options.fileName);
  const platform = serializerOptions.platform ? `.${serializerOptions.platform}` : "";
  const suffix = serializerOptions.dev ? ".dev" : ".release";
  return normalizeName(`index${platform}${suffix}.bundle.js`);
}

function shouldProtectBundle(fileName, config, options) {
  const normalized = normalizeName(fileName);
  const include = Array.isArray(config.include) && config.include.length ? config.include : options.include;
  if (Array.isArray(include) && include.length && !isExcluded(normalized, include)) {
    return false;
  }
  return !isExcluded(normalized, config.exclude || []);
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

module.exports = createMetroSerializer;
module.exports.createMetroSerializer = createMetroSerializer;
module.exports.withJsoProtectorMetro = withJsoProtectorMetro;
module.exports.default = createMetroSerializer;
