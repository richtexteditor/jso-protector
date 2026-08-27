"use strict";

const protectParcelBuild = require("jso-protector/parcel");

const options = {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD
};

async function main() {
  const planOnly = process.argv.includes("--plan");
  const plan = protectParcelBuild.planParcelBuild(options);

  console.log(`Protecting ${plan.summary.files.length} Parcel JavaScript file(s).`);

  if (planOnly) {
    console.log(`Copying ${plan.summary.assets.length} Parcel asset(s).`);
    return;
  }

  const result = await protectParcelBuild(options);
  console.log(`Wrote ${result.written.length} protected file(s) and copied ${result.copied.length} asset(s).`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
