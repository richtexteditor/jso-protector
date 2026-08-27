"use strict";

const { createProtectionConfig, planProtection, protectFiles } = require("./index.js");

function createParcelProtectionConfig(options = {}) {
  return createProtectionConfig({
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    exclude: ["**/*.map", "**/vendor/**"],
    assetExclude: ["**/*.map"],
    maxGrowthRatio: 8,
    manifest: defaultManifestForOutput(options, "dist-protected/jso-manifest.json"),
    ...options
  });
}

function planParcelBuild(options = {}) {
  return planProtection(createParcelProtectionConfig(options));
}

async function protectParcelBuild(options = {}) {
  return protectFiles(createParcelProtectionConfig(options));
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

module.exports = protectParcelBuild;
module.exports.createParcelProtectionConfig = createParcelProtectionConfig;
module.exports.planParcelBuild = planParcelBuild;
module.exports.protectParcelBuild = protectParcelBuild;
module.exports.default = protectParcelBuild;
