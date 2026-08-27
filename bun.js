"use strict";

const { createProtectionConfig, planProtection, protectFiles } = require("./index.js");

function createBunProtectionConfig(options = {}) {
  return createProtectionConfig({
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    exclude: ["**/*.map", "**/vendor/**"],
    assetExclude: ["**/*.map"],
    maxOutputBytes: 250000,
    maxGrowthRatio: 8,
    manifest: defaultManifestForOutput(options, "dist-protected/jso-manifest.json"),
    ...options
  });
}

function planBunBuild(options = {}) {
  return planProtection(createBunProtectionConfig(options));
}

async function protectBunBuild(options = {}) {
  return protectFiles(createBunProtectionConfig(options));
}

function defaultManifestForOutput(options, fallback) {
  if (Object.prototype.hasOwnProperty.call(options || {}, "manifest")) {
    return options.manifest;
  }
  if (options && options.output) {
    return `${String(options.output).replace(/[\\/]$/, "")}/jso-manifest.json`;
  }
  return fallback;
}

module.exports = protectBunBuild;
module.exports.createBunProtectionConfig = createBunProtectionConfig;
module.exports.planBunBuild = planBunBuild;
module.exports.protectBunBuild = protectBunBuild;
module.exports.default = protectBunBuild;
