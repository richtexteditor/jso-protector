#!/usr/bin/env node

"use strict";

const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const packagePath = path.join(root, "package.json");
const packageJson = JSON.parse(fs.readFileSync(packagePath, "utf8"));
const args = new Set(process.argv.slice(2));
const json = args.has("--json");
const allowLocal = args.has("--allow-local") || args.has("--allow-draft");
// Two metadata states are approved, and nothing in between:
//
//   local-only  : private:true  + license "UNLICENSED"
//                 npm publish is blocked outright by prepublishOnly.
//   proprietary : no private    + license "SEE LICENSE IN LICENSE" + a LICENSE file
//                 publicly installable, all rights reserved. See ../LICENSE.
//
// A half-migrated package is the state worth failing loudly on: private removed
// but still "UNLICENSED" publishes a package that grants users nothing, and a
// "SEE LICENSE IN LICENSE" string with no LICENSE file on disk ships a
// proprietary package whose licence text is missing. Both are silent problems
// that only surface after the version is public and immutable.
const PROPRIETARY_LICENSE = "SEE LICENSE IN LICENSE";
const licenseFileExists = fs.existsSync(path.join(root, "LICENSE"));
const localOnly = packageJson.private === true && packageJson.license === "UNLICENSED";
const proprietaryPublic =
  packageJson.private !== true && packageJson.license === PROPRIETARY_LICENSE;

const issues = [];
const warnings = [];

function issue(field, message) {
  issues.push({ field, message });
}

function warning(field, message) {
  warnings.push({ field, message });
}

// "jso-protector" was confirmed as the final public name on 2026-07-27 (the
// registry returned 404 for it, so it was unclaimed). Only an empty name is a
// problem now.
if (!packageJson.name) {
  issue("name", "Provide the public npm package name.");
}

if (!localOnly && !proprietaryPublic) {
  issue(
    "private/license",
    `Metadata is in neither approved state. Local-only is private:true + "UNLICENSED"; ` +
      `public release is private removed + license "${PROPRIETARY_LICENSE}". ` +
      `Found private:${JSON.stringify(packageJson.private)} license:${JSON.stringify(packageJson.license)}. ` +
      `A half-migrated package either blocks a legitimate publish or ships granting no readable rights.`
  );
}

if (proprietaryPublic && !licenseFileExists) {
  issue(
    "license",
    `license is "${PROPRIETARY_LICENSE}" but packages/jso-protector/LICENSE does not exist. ` +
      `npm would publish a proprietary package with no licence text for users to read.`
  );
}

if (proprietaryPublic && !(packageJson.files || []).includes("LICENSE")) {
  warning("files", "Add LICENSE to the files array. npm includes it implicitly, but being explicit keeps the packed set self-documenting.");
}

if (!packageJson.description || packageJson.description.length < 20) {
  issue("description", "Provide a concise npm package description.");
}

if (!packageJson.homepage) {
  issue("homepage", "Provide a homepage that points to the npm CLI documentation.");
}

if (!packageJson.author) {
  issue("author", "Provide the publishing organization or maintainer.");
}

if (!packageJson.bin || !packageJson.bin["jso-protector"]) {
  issue("bin", "Expose the jso-protector CLI binary.");
}

if (!packageJson.files || !packageJson.files.includes("README.md") || !packageJson.files.includes("SECURITY.md")) {
  issue("files", "Pack README.md and SECURITY.md with the npm artifact.");
}

if (!packageJson.scripts || !String(packageJson.scripts.verify || "").includes("verify:package")) {
  warning("scripts.verify", "Consider a single npm run verify script that includes tests and package verification.");
}

if (!packageJson.repository) {
  if (!localOnly) {
    warning("repository", "Add repository metadata when the public source location is final.");
  }
}

if (!packageJson.bugs) {
  if (!localOnly) {
    warning("bugs", "Add issue/support metadata when the public support channel is final.");
  }
}

const report = {
  format: "jso-protector-publish-metadata",
  ok: issues.length === 0,
  publishReady: proprietaryPublic && issues.length === 0,
  localOnly,
  proprietaryPublic,
  licenseFileExists,
  localAllowed: allowLocal,
  issues,
  warnings
};

if (json) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  if (report.ok && localOnly && allowLocal) {
    process.stdout.write("Local-only package metadata is locked. npm publish remains blocked by prepublishOnly.\n");
  } else if (report.ok && localOnly) {
    process.stdout.write("Package is intentionally local-only. Refusing publish-ready mode while private:true and UNLICENSED are set.\n");
  } else if (report.publishReady) {
    process.stdout.write(
      `Publish metadata is ready: proprietary release, license "${PROPRIETARY_LICENSE}", LICENSE file present.\n`
    );
    for (const item of warnings) {
      process.stdout.write(`WARNING ${item.field}: ${item.message}\n`);
    }
  } else {
    process.stdout.write(`Package metadata has ${issues.length} blocking issue(s) and ${warnings.length} warning(s).\n`);
    for (const item of issues) {
      process.stdout.write(`BLOCKER ${item.field}: ${item.message}\n`);
    }
    for (const item of warnings) {
      process.stdout.write(`WARNING ${item.field}: ${item.message}\n`);
    }
  }
}

if ((!allowLocal && localOnly) || (issues.length && !allowLocal)) {
  process.exitCode = 1;
}
