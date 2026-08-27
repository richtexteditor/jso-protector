"use strict";

const fs = require("fs");
const path = require("path");
const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function jsoProtector(options = {}) {
  const removeSourceMaps = options.removeSourceMaps !== false;

  return {
    name: "jso-protector",
    setup(build) {
      build.onEnd(async (result) => {
        const initialOptions = build.initialOptions || {};
        const outputRoot = getOutputRoot(initialOptions);
        const config = createProtectionConfig({
          input: outputRoot,
          output: outputRoot,
          ...options
        });

        if (Array.isArray(result.outputFiles)) {
          await protectOutputFiles(result.outputFiles, config, options, removeSourceMaps, outputRoot);
          return;
        }

        await protectWrittenFiles(initialOptions, config, options, removeSourceMaps, outputRoot);
      });
    }
  };
}

async function protectOutputFiles(outputFiles, config, options, removeSourceMaps, outputRoot) {
  const files = outputFiles.filter((file) => (
    file &&
    file.path &&
    hasProtectedExtension(file.path, config.extensions) &&
    shouldProtectAsset(toAssetName(outputRoot, file.path), config, options)
  ));

  if (!files.length) return;

  const inputItems = files.map((file) => ({
    FileName: toAssetName(outputRoot, file.path),
    FileCode: outputFileText(file),
    SourcePath: file.path,
    OutputPath: file.path
  }));
  const protection = buildProtectionItemsFromInputItems(config, inputItems);
  const result = await protectItems(config, protection.items);
  const manifest = buildItemsManifest(config, inputItems, result, (fileName) => fileName, protection.transforms);
  assertSizeBudgets(manifest, config);

  for (const file of files) {
    const assetName = toAssetName(outputRoot, file.path);
    const code = composeProtectionItemOutput(assetName, result, protection.transforms, config);
    file.contents = Buffer.from(code, "utf8");
    if (Object.prototype.hasOwnProperty.call(file, "text")) {
      try {
        file.text = code;
      } catch (_error) {
        // esbuild exposes text as a getter; tests may use a writable field.
      }
    }
  }

  if (removeSourceMaps) {
    for (let i = outputFiles.length - 1; i >= 0; i -= 1) {
      const assetName = toAssetName(outputRoot, outputFiles[i].path || "");
      if (isProtectedSourceMap(assetName, config.extensions)) outputFiles.splice(i, 1);
    }
  }

  if (config.manifest) {
    writeManifest(config.manifest, manifest);
  }
}

async function protectWrittenFiles(initialOptions, config, options, removeSourceMaps, outputRoot) {
  const targets = collectWrittenJavaScript(initialOptions, outputRoot, config.extensions)
    .filter((file) => shouldProtectAsset(file.relative, config, options));

  if (!targets.length) return;

  const inputItems = targets.map((file) => ({
    FileName: file.relative,
    FileCode: fs.readFileSync(file.path, "utf8"),
    SourcePath: file.path,
    OutputPath: file.path
  }));
  const protection = buildProtectionItemsFromInputItems(config, inputItems);
  const result = await protectItems(config, protection.items);
  const manifest = buildItemsManifest(config, inputItems, result, (fileName) => {
    const found = targets.find((target) => normalizeName(target.relative) === normalizeName(fileName));
    return found ? found.path : fileName;
  }, protection.transforms);
  assertSizeBudgets(manifest, config);

  for (const file of targets) {
    fs.writeFileSync(file.path, composeProtectionItemOutput(file.relative, result, protection.transforms, config), "utf8");
    if (removeSourceMaps) {
      const mapPath = `${file.path}.map`;
      if (fs.existsSync(mapPath)) fs.unlinkSync(mapPath);
    }
  }

  if (config.manifest) {
    writeManifest(config.manifest, manifest);
  }
}

function collectWrittenJavaScript(initialOptions, outputRoot, extensions) {
  if (initialOptions.outfile) {
    if (!hasProtectedExtension(initialOptions.outfile, extensions) || !fs.existsSync(initialOptions.outfile)) return [];
    return [{
      path: initialOptions.outfile,
      relative: path.basename(initialOptions.outfile)
    }];
  }

  if (!outputRoot || !fs.existsSync(outputRoot)) return [];

  const files = [];
  walk(outputRoot, (filePath) => {
    if (!hasProtectedExtension(filePath, extensions)) return;
    files.push({
      path: filePath,
      relative: normalizeName(path.relative(outputRoot, filePath))
    });
  });
  return files;
}

function walk(dir, visit) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(entryPath, visit);
    else if (entry.isFile()) visit(entryPath);
  }
}

function getOutputRoot(initialOptions) {
  if (initialOptions.outdir) return initialOptions.outdir;
  if (initialOptions.outfile) return path.dirname(initialOptions.outfile);
  return "dist";
}

function outputFileText(file) {
  if (typeof file.text === "string") return file.text;
  if (file.contents) return Buffer.from(file.contents).toString("utf8");
  return "";
}

function toAssetName(outputRoot, filePath) {
  if (!filePath) return "";
  const normalizedPath = normalizeName(filePath);
  const normalizedRoot = normalizeName(path.resolve(outputRoot || "."));
  const resolvedPath = normalizeName(path.resolve(filePath));
  if (resolvedPath.startsWith(`${normalizedRoot}/`)) {
    return resolvedPath.slice(normalizedRoot.length + 1);
  }
  return path.basename(normalizedPath);
}

function shouldProtectAsset(fileName, config, options) {
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

function hasProtectedExtension(filePath, extensions) {
  const normalizedExtensions = Array.isArray(extensions) && extensions.length ? extensions : [".js"];
  return normalizedExtensions.some((extension) => String(filePath || "").endsWith(extension));
}

function isProtectedSourceMap(filePath, extensions) {
  const normalizedExtensions = Array.isArray(extensions) && extensions.length ? extensions : [".js"];
  return normalizedExtensions.some((extension) => String(filePath || "").endsWith(`${extension}.map`));
}

module.exports = jsoProtector;
module.exports.jsoProtector = jsoProtector;
module.exports.default = jsoProtector;
