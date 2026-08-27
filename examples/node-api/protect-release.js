"use strict";

const { planProtection, protectFiles } = require("jso-protector");

async function main() {
  const options = {
    apiKey: process.env.JSO_API_KEY,
    apiPassword: process.env.JSO_API_PASSWORD,
    input: "dist",
    output: "dist-protected",
    preset: "balanced",
    exclude: ["**/*.map", "**/vendor/**"],
    assetExclude: ["**/*.map"],
    manifest: "dist-protected/jso-manifest.json",
    maxGrowthRatio: 8
  };

  const plan = planProtection(options);
  console.log(`Protecting ${plan.summary.files.length} JavaScript file(s).`);

  const result = await protectFiles(options);
  console.log(`Wrote ${result.written.length} protected file(s) and copied ${result.copied.length} asset(s).`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
