"use strict";

const fs = require("fs");
const path = require("path");
const { assertSizeBudgets, buildItemsManifest, buildProtectionItemsFromInputItems, composeProtectionItemOutput, createProtectionConfig, isExcluded, protectItems, writeManifest } = require("./index.js");

function registerJsoProtectorGrunt(grunt) {
  grunt.registerMultiTask("jsoProtector", "Protect JavaScript files with the JavaScript Obfuscator HTTP API.", function task() {
    const done = this.async();
    const options = this.options({});
    const config = createProtectionConfig(options);

    runGruntTask(grunt, this.files || [], config)
      .then(() => done())
      .catch((error) => done(error));
  });
}

async function runGruntTask(grunt, fileGroups, config) {
  const files = collectGruntFiles(grunt, fileGroups, config);
  if (!files.length) return;

  const inputItems = files.map((file) => ({
    FileName: file.fileName,
    FileCode: grunt.file.read(file.source),
    SourcePath: file.source,
    OutputPath: file.target
  }));
  const protection = buildProtectionItemsFromInputItems(config, inputItems);
  const result = await protectItems(config, protection.items);
  const manifest = buildItemsManifest(config, inputItems, result, (fileName) => {
    const found = files.find((file) => normalizeName(file.fileName) === normalizeName(fileName));
    return found ? found.target : fileName;
  }, protection.transforms);
  assertSizeBudgets(manifest, config);

  for (const file of files) {
    grunt.file.mkdir(path.dirname(file.target));
    grunt.file.write(file.target, composeProtectionItemOutput(file.fileName, result, protection.transforms, config));
  }

  if (config.manifest) {
    writeManifest(config.manifest, manifest);
  }
}

function collectGruntFiles(grunt, fileGroups, config) {
  const files = [];
  for (const group of fileGroups || []) {
    const sources = Array.isArray(group.src) ? group.src : [group.src].filter(Boolean);
    for (const source of sources) {
      if (!source || !grunt.file.exists(source)) continue;
      const target = targetPathForGroup(source, group);
      const fileName = assetNameForFile(source, target, config);
      if (!shouldProtect(fileName, config)) continue;
      files.push({ source, target, fileName });
    }
  }
  return files;
}

function targetPathForGroup(source, group) {
  if (!group.dest) return source;
  const sourceCount = Array.isArray(group.src) ? group.src.length : 1;
  if (sourceCount > 1 || looksLikeDirectory(group.dest)) {
    return path.join(group.dest, path.basename(source));
  }
  return group.dest;
}

function looksLikeDirectory(value) {
  return /[\\/]$/.test(String(value || ""));
}

function assetNameForFile(source, target, config) {
  const output = config.output ? path.resolve(config.output) : "";
  const resolvedTarget = path.resolve(target || source);
  if (output && isInside(output, resolvedTarget)) {
    return normalizeName(path.relative(output, resolvedTarget));
  }

  const input = config.input ? path.resolve(config.input) : "";
  const resolvedSource = path.resolve(source);
  if (input && isInside(input, resolvedSource)) {
    return normalizeName(path.relative(input, resolvedSource));
  }

  return normalizeName(path.basename(target || source));
}

function shouldProtect(fileName, config) {
  if (!fileName.endsWith(".js")) return false;
  if (Array.isArray(config.include) && config.include.length && !isExcluded(fileName, config.include)) {
    return false;
  }
  return !isExcluded(fileName, config.exclude || []);
}

function isInside(root, filePath) {
  const relative = path.relative(root, filePath);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function normalizeName(name) {
  return String(name || "").replace(/\\/g, "/");
}

module.exports = registerJsoProtectorGrunt;
module.exports.registerJsoProtectorGrunt = registerJsoProtectorGrunt;
module.exports._runGruntTask = runGruntTask;
module.exports.default = registerJsoProtectorGrunt;
