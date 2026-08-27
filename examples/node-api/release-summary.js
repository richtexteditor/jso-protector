"use strict";

const {
  createProtectionConfig,
  getRedactedConfig,
  planProtection,
  protectFiles,
  validateProtectionConfig
} = require("jso-protector");

/**
 * @type {import("jso-protector").ProtectionOptions}
 */
const options = {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  input: "dist",
  output: "dist-protected",
  preset: "balanced",
  exclude: ["**/*.map", "**/vendor/**", "**/polyfills-*.js"],
  assetExclude: ["**/*.map"],
  reservedNames: ["^PublicApi$", "^renderWidget$"],
  manifest: "dist-protected/jso-manifest.json",
  maxOutputBytes: 250000,
  maxGrowthRatio: 8
};

async function main() {
  const validation = validateProtectionConfig(options);
  if (!validation.ok) {
    console.error(JSON.stringify(validation, null, 2));
    process.exitCode = 1;
    return;
  }

  const config = createProtectionConfig(options);
  const plan = planProtection(config);
  const redacted = getRedactedConfig(config);

  console.log(`Project: ${redacted.projectName}`);
  console.log(`Preset: ${redacted.preset}`);
  console.log(`Endpoint: ${redacted.endpoint}`);
  console.log(`Protecting ${plan.files.length} JavaScript file(s).`);
  console.log(`Copying ${plan.assets.length} release asset(s).`);

  if (!plan.files.length) {
    throw new Error("No JavaScript files matched the release plan.");
  }

  const result = await protectFiles(config);
  console.log(`Wrote ${result.written.length} protected file(s).`);
  console.log(`Copied ${result.copied.length} asset(s).`);
  console.log(`Manifest: ${result.manifestPath || "not written"}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
