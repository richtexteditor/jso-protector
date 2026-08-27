"use strict";

const protectTurbopackBuild = require("jso-protector/turbopack");

const options = {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD
};

async function main() {
  const planOnly = process.argv.includes("--plan");
  const plan = protectTurbopackBuild.planTurbopackBuild(options);

  console.log(`Protecting ${plan.summary.files.length} Turbopack chunk(s).`);

  if (planOnly) {
    console.log(`Copying ${plan.summary.assets.length} Turbopack asset(s).`);
    return;
  }

  const result = await protectTurbopackBuild(options);
  console.log(`Wrote ${result.written.length} protected chunk(s) and copied ${result.copied.length} asset(s).`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
