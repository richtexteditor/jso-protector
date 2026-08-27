"use strict";

const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function jsoProtector(options = {}) {
  let config = null;
  const removeSourceMaps = options.removeSourceMaps !== false;

  return {
    name: "jso-protector",
    async generateBundle(outputOptions, bundle) {
      if (!config) {
        const outDir = outputOptions && outputOptions.dir ? outputOptions.dir : "dist";
        config = createProtectionConfig({
          input: outDir,
          output: outDir,
          ...options
        });
      }

      const chunks = Object.values(bundle).filter((entry) => (
        entry &&
        entry.type === "chunk" &&
        typeof entry.code === "string" &&
        entry.fileName &&
        entry.fileName.endsWith(".js") &&
        shouldProtectAsset(entry.fileName, config, options)
      ));

      if (!chunks.length) return;

      const inputItems = chunks.map((chunk) => ({
        FileName: chunk.fileName,
        FileCode: chunk.code
      }));
      const protection = buildProtectionItemsFromInputItems(config, inputItems);
      const result = await protectItems(config, protection.items);
      const manifest = buildItemsManifest(config, inputItems, result, (fileName) => fileName, protection.transforms);
      assertSizeBudgets(manifest, config);

      for (const chunk of chunks) {
        chunk.code = composeProtectionItemOutput(chunk.fileName, result, protection.transforms, config);
        if (removeSourceMaps) {
          chunk.map = null;
          delete bundle[`${chunk.fileName}.map`];
        }
      }

      if (config.manifest) {
        writeManifest(config.manifest, manifest);
      }
    }
  };
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

function shouldProtectAsset(fileName, config, options) {
  const normalized = normalizeName(fileName);
  const include = Array.isArray(config.include) && config.include.length ? config.include : options.include;
  if (Array.isArray(include) && include.length && !isExcluded(normalized, include)) {
    return false;
  }
  return !isExcluded(normalized, config.exclude || []);
}

module.exports = jsoProtector;
module.exports.jsoProtector = jsoProtector;
module.exports.default = jsoProtector;
