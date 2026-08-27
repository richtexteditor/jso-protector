"use strict";

const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

class JsoProtectorWebpackPlugin {
  constructor(options = {}) {
    this.options = options;
    this.removeSourceMaps = options.removeSourceMaps !== false;
  }

  apply(compiler) {
    const pluginName = "JsoProtectorWebpackPlugin";
    const processAssetsHook = compiler.hooks && compiler.hooks.thisCompilation;
    if (processAssetsHook && compiler.webpack && compiler.webpack.sources && compiler.webpack.Compilation) {
      const RawSource = compiler.webpack.sources.RawSource;
      const stage = compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE;

      processAssetsHook.tap(pluginName, (compilation) => {
        compilation.hooks.processAssets.tapPromise({ name: pluginName, stage }, async (assets) => {
          await this.protectCompilationAssets(compiler, compilation, assets, (value) => new RawSource(value));
        });
      });
      return;
    }

    if (compiler.hooks && compiler.hooks.emit) {
      compiler.hooks.emit.tapPromise(pluginName, async (compilation) => {
        await this.protectCompilationAssets(compiler, compilation, compilation.assets, createRawSourceAsset);
      });
    }
  }

  async protectCompilationAssets(compiler, compilation, assets, createAsset) {
    const outputPath = compiler.options && compiler.options.output && compiler.options.output.path
      ? compiler.options.output.path
      : "dist";
    const config = createProtectionConfig({
      input: outputPath,
      output: outputPath,
      ...this.options
    });

    const names = Object.keys(assets || {}).filter((name) => (
      matchesProtectedScriptExtension(name, config) &&
      shouldProtectAsset(name, config, this.options)
    ));
    if (!names.length) return;

    const inputItems = names.map((name) => ({
      FileName: name,
      FileCode: assetToString(getAssetSource(compilation, assets, name))
    }));
    const protection = buildProtectionItemsFromInputItems(config, inputItems);
    const result = await protectItems(config, protection.items);
    const manifest = buildItemsManifest(config, inputItems, result, (fileName) => fileName, protection.transforms);
    assertSizeBudgets(manifest, config);

    for (const name of names) {
      const output = composeProtectionItemOutput(name, result, protection.transforms, config);
      if (typeof compilation.updateAsset === "function") {
        compilation.updateAsset(name, createAsset(output));
      } else if (compilation.assets) {
        compilation.assets[name] = createAsset(output);
      }

      if (this.removeSourceMaps) {
        removeSourceMapAsset(compilation, `${name}.map`);
      }
    }

    if (config.manifest) {
      writeManifest(config.manifest, manifest);
    }
  }
}

function getAssetSource(compilation, assets, name) {
  if (compilation && typeof compilation.getAsset === "function") {
    const asset = compilation.getAsset(name);
    if (asset && asset.source) return asset.source;
  }
  return assets ? assets[name] : null;
}

function removeSourceMapAsset(compilation, name) {
  if (!compilation) return;
  if (typeof compilation.deleteAsset === "function") {
    compilation.deleteAsset(name);
    return;
  }
  if (compilation.assets && Object.prototype.hasOwnProperty.call(compilation.assets, name)) {
    delete compilation.assets[name];
  }
}

function createRawSourceAsset(value) {
  return {
    source() {
      return value;
    },
    size() {
      return Buffer.byteLength(value, "utf8");
    }
  };
}

function assetToString(assetOrSource) {
  if (!assetOrSource) return "";
  if (typeof assetOrSource.source === "function") {
    const value = assetOrSource.source();
    return Buffer.isBuffer(value) ? value.toString("utf8") : String(value || "");
  }
  if (assetOrSource.source) {
    return assetToString(assetOrSource.source);
  }
  const value = assetOrSource;
  return Buffer.isBuffer(value) ? value.toString("utf8") : String(value || "");
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

function matchesProtectedScriptExtension(fileName, config) {
  const normalizedName = normalizeName(fileName).toLowerCase();
  const extensions = Array.isArray(config.extensions) && config.extensions.length
    ? config.extensions
    : [".js"];
  return extensions.some((extension) => normalizedName.endsWith(String(extension || "").toLowerCase()));
}

module.exports = JsoProtectorWebpackPlugin;
module.exports.JsoProtectorWebpackPlugin = JsoProtectorWebpackPlugin;
module.exports.default = JsoProtectorWebpackPlugin;
