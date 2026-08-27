"use strict";

const { createProtectionConfig, planProtection, protectFiles } = require("./index.js");

function createTurbopackProtectionConfig(options = {}) {
  return createProtectionConfig({
    input: ".next/static",
    output: ".next/static-protected",
    preset: "balanced",
    include: ["chunks/*.js", "chunks/**/*.js"],
    exclude: ["**/*.map", "**/webpack-*.js", "**/polyfills-*.js"],
    assetExclude: ["**/*.map"],
    maxGrowthRatio: 8,
    manifest: defaultManifestForOutput(options, ".next/static-protected/jso-manifest.json"),
    ...options
  });
}

function planTurbopackBuild(options = {}) {
  return planProtection(createTurbopackProtectionConfig(options));
}

async function protectTurbopackBuild(options = {}) {
  return protectFiles(createTurbopackProtectionConfig(options));
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

module.exports = protectTurbopackBuild;
module.exports.createTurbopackProtectionConfig = createTurbopackProtectionConfig;
module.exports.planTurbopackBuild = planTurbopackBuild;
module.exports.protectTurbopackBuild = protectTurbopackBuild;
module.exports.default = protectTurbopackBuild;
