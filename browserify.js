"use strict";

const path = require("path");
const { Transform } = require("stream");
const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function jsoProtectorBrowserify(file, options = {}) {
  const config = createProtectionConfig(options);
  const fileName = normalizeName(options.fileName || assetNameForFile(file, config));
  const shouldProtect = shouldProtectFile(fileName, config);
  const chunks = [];

  return new Transform({
    transform(chunk, _encoding, callback) {
      if (!shouldProtect) {
        this.push(chunk);
      } else {
        chunks.push(Buffer.from(chunk));
      }
      callback();
    },
    async flush(callback) {
      if (!shouldProtect) {
        callback();
        return;
      }

      try {
        const code = Buffer.concat(chunks).toString("utf8");
        const inputItems = [{
          FileName: fileName,
          FileCode: code,
          SourcePath: file || fileName,
          OutputPath: file || fileName
        }];
        const protection = buildProtectionItemsFromInputItems(config, inputItems);
        const result = await protectItems(config, protection.items);
        const manifest = buildItemsManifest(config, inputItems, result, () => file || fileName, protection.transforms);
        assertSizeBudgets(manifest, config);

        if (config.manifest) writeManifest(config.manifest, manifest);
        this.push(composeProtectionItemOutput(fileName, result, protection.transforms, config));
        callback();
      } catch (error) {
        callback(error);
      }
    }
  });
}

function assetNameForFile(file, config) {
  if (!file) return "module.js";
  const normalizedFile = normalizeName(file);
  const input = config.input ? normalizeName(path.resolve(config.input)) : "";
  const resolvedFile = normalizeName(path.resolve(file));
  if (input && resolvedFile.startsWith(`${input}/`)) {
    return resolvedFile.slice(input.length + 1);
  }
  const cwd = normalizeName(process.cwd());
  if (resolvedFile.startsWith(`${cwd}/`)) {
    return resolvedFile.slice(cwd.length + 1);
  }
  return path.basename(normalizedFile);
}

function shouldProtectFile(fileName, config) {
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

module.exports = jsoProtectorBrowserify;
module.exports.jsoProtectorBrowserify = jsoProtectorBrowserify;
module.exports.default = jsoProtectorBrowserify;
