"use strict";

const path = require("path");
const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function jsoProtectorLoader(source, sourceMap, meta) {
  const callback = typeof this.async === "function" ? this.async() : null;
  if (!callback) {
    throw new Error("jso-protector webpack loader requires an async loader context.");
  }
  if (typeof this.cacheable === "function") {
    this.cacheable(false);
  }

  const options = readLoaderOptions(this);
  const config = createProtectionConfig(options);
  const fileName = normalizeName(options.fileName || resourceNameForContext(this));
  if (!shouldProtect(fileName, config)) {
    callback(null, source, sourceMap, meta);
    return;
  }

  const code = Buffer.isBuffer(source) ? source.toString("utf8") : String(source || "");
  const inputItems = [{
    FileName: fileName,
    FileCode: code,
    SourcePath: this.resourcePath || fileName,
    OutputPath: this.resourcePath || fileName
  }];

  const protection = buildProtectionItemsFromInputItems(config, inputItems);

  protectItems(config, protection.items)
    .then((result) => {
      const manifest = buildItemsManifest(config, inputItems, result, () => this.resourcePath || fileName, protection.transforms);
      assertSizeBudgets(manifest, config);
      if (config.manifest) writeManifest(config.manifest, manifest);

      callback(null, composeProtectionItemOutput(fileName, result, protection.transforms, config), null, meta);
    })
    .catch((error) => callback(error));
}

function readLoaderOptions(context) {
  if (typeof context.getOptions === "function") {
    return context.getOptions() || {};
  }
  const query = context.query;
  if (!query) return {};
  if (typeof query === "object") return query;
  if (typeof query !== "string") return {};
  const text = query.startsWith("?") ? query.slice(1) : query;
  if (!text) return {};
  const options = {};
  for (const [key, value] of new URLSearchParams(text).entries()) {
    options[key] = parseQueryValue(value);
  }
  return options;
}

function parseQueryValue(value) {
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === "true";
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return value;
}

function resourceNameForContext(context) {
  const resourcePath = context.resourcePath || "";
  if (!resourcePath) return "module.js";
  const root = context.rootContext || context.context || process.cwd();
  const relative = path.relative(root, resourcePath);
  return normalizeName(relative && !relative.startsWith("..") ? relative : path.basename(resourcePath));
}

function shouldProtect(fileName, config) {
  if (!matchesProtectedScriptExtension(fileName, config)) return false;
  if (Array.isArray(config.include) && config.include.length && !isExcluded(fileName, config.include)) {
    return false;
  }
  return !isExcluded(fileName, config.exclude || []);
}

function matchesProtectedScriptExtension(fileName, config) {
  const normalizedName = normalizeName(fileName).toLowerCase();
  const extensions = Array.isArray(config.extensions) && config.extensions.length
    ? config.extensions
    : [".js"];
  return extensions.some((extension) => normalizedName.endsWith(String(extension || "").toLowerCase()));
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

module.exports = jsoProtectorLoader;
module.exports.jsoProtectorLoader = jsoProtectorLoader;
module.exports.default = jsoProtectorLoader;
