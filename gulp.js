"use strict";

const path = require("path");
const { Transform } = require("stream");
const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function jsoProtector(options = {}) {
  const config = createProtectionConfig(options);
  const removeSourceMaps = options.removeSourceMaps !== false;
  const files = [];

  return new Transform({
    objectMode: true,
    transform(file, _encoding, callback) {
      if (!file) {
        callback();
        return;
      }
      if (typeof file.isStream === "function" && file.isStream()) {
        callback(new Error("jso-protector does not support streaming Vinyl contents. Use buffered files."));
        return;
      }
      files.push(file);
      callback();
    },
    async flush(callback) {
      try {
        const targets = files.filter((file) => shouldProtectFile(file, config));
        const inputItems = targets.map((file) => ({
          FileName: assetNameForFile(file),
          FileCode: contentsToString(file.contents),
          SourcePath: file.path || assetNameForFile(file),
          OutputPath: file.path || assetNameForFile(file)
        }));

        let result = null;
        let protection = { items: [], transforms: new Map() };
        let manifest = null;
        if (inputItems.length) {
          protection = buildProtectionItemsFromInputItems(config, inputItems);
          result = await protectItems(config, protection.items);
          manifest = buildItemsManifest(config, inputItems, result, (fileName) => {
            const found = targets.find((target) => normalizeName(assetNameForFile(target)) === normalizeName(fileName));
            return found && found.path ? found.path : fileName;
          }, protection.transforms);
          assertSizeBudgets(manifest, config);
        }

        for (const file of files) {
          if (removeSourceMaps && assetNameForFile(file).endsWith(".js.map")) {
            continue;
          }

          if (shouldProtectFile(file, config)) {
            const assetName = assetNameForFile(file);
            file.contents = Buffer.from(composeProtectionItemOutput(assetName, result, protection.transforms, config), "utf8");
          }
          this.push(file);
        }

        if (config.manifest && manifest) {
          writeManifest(config.manifest, manifest);
        }
        callback();
      } catch (error) {
        callback(error);
      }
    }
  });
}

function shouldProtectFile(file, config) {
  if (!file || (typeof file.isNull === "function" && file.isNull())) return false;
  const assetName = assetNameForFile(file);
  if (!assetName.endsWith(".js")) return false;
  if (Array.isArray(config.include) && config.include.length && !isExcluded(assetName, config.include)) {
    return false;
  }
  return !isExcluded(assetName, config.exclude || []);
}

function assetNameForFile(file) {
  if (file && typeof file.relative === "string" && file.relative) {
    return normalizeName(file.relative);
  }
  if (file && file.path && file.base) {
    return normalizeName(path.relative(file.base, file.path));
  }
  if (file && file.path) {
    return normalizeName(path.basename(file.path));
  }
  return "";
}

function contentsToString(contents) {
  if (!contents) return "";
  return Buffer.isBuffer(contents) ? contents.toString("utf8") : String(contents);
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

module.exports = jsoProtector;
module.exports.jsoProtector = jsoProtector;
module.exports.default = jsoProtector;
