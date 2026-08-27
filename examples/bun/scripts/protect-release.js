"use strict";

const protectBunBuild = require("jso-protector/bun");

const options = {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD
};

async function main() {
  const planOnly = process.argv.includes("--plan");
  const plan = protectBunBuild.planBunBuild(options);

  console.log(`Protecting ${plan.summary.files.length} Bun output file(s).`);

  if (planOnly) {
    console.log(`Copying ${plan.summary.assets.length} Bun asset(s).`);
    return;
  }

  const result = await protectBunBuild(options);
  console.log(`Wrote ${result.written.length} protected file(s) and copied ${result.copied.length} asset(s).`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
