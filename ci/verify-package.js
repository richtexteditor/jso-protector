#!/usr/bin/env node

"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

const REQUIRED_PACKED_FILES = [
  "CHANGELOG.md",
  "MIGRATION.md",
  "README.md",
  "RELEASE.md",
  "SECURITY.md",
	"ai-cli.js",
	"ai.js",
  "bin/jso-protector.js",
  "bun.d.ts",
  "bun.js",
  "browserify.d.ts",
  "browserify.js",
  "ci/azure-pipelines.yml",
  "ci/github-actions.yml",
  "ci/gitlab-ci.yml",
  "ci/verify-package.js",
  "ci/verify-examples.js",
  "ci/verify-publish-metadata.js",
  "esbuild.d.ts",
  "esbuild.js",
  "examples/browserify/build.js",
  "examples/cli-basic/jso.config.cjs",
  "examples/cli-basic/jso.config.json",
  "examples/cli-basic/package.json",
  "examples/cli-basic/scripts/build.js",
  "examples/bun/package.json",
  "examples/bun/scripts/protect-release.js",
  "examples/esbuild/build.js",
  "examples/grunt/Gruntfile.js",
  "examples/gulp/gulpfile.js",
  "examples/metro.config.js",
  "examples/node-api/protect-release.js",
  "examples/node-api/release-summary.js",
  "examples/nextjs/next.config.js",
  "examples/parcel/package.json",
  "examples/parcel/scripts/protect-release.js",
  "examples/README.md",
  "examples/react-native/metro.config.js",
  "examples/rspack/rspack.config.js",
  "examples/rollup/rollup.config.js",
  "examples/turbopack/package.json",
  "examples/turbopack/scripts/protect-release.js",
  "examples/vite/vite.config.js",
  "examples/webpack/webpack.config.js",
  "examples/webpack-loader/webpack.config.js",
  "grunt.d.ts",
  "grunt.js",
  "gulp.d.ts",
  "gulp.js",
  "index.d.ts",
  "index.js",
  "metro.d.ts",
  "metro.js",
  "next.d.ts",
  "next.js",
  "parcel.d.ts",
  "parcel.js",
  "react-native.d.ts",
  "react-native.js",
	"release-signer.js",
  "rspack.d.ts",
  "rspack.js",
  "rspack-loader.d.ts",
  "rspack-loader.js",
  "jso.config.example.json",
  "jso.config.schema.json",
  "package.json",
  "rollup.d.ts",
  "rollup.js",
  "turbopack.d.ts",
  "turbopack.js",
  "vite.d.ts",
  "vite.js",
	"watermark.js",
  "webpack.d.ts",
  "webpack.js",
  "webpack-loader.d.ts",
  "webpack-loader.js"
];

const PACKED_DIRECTORY_PREFIXES = [
	"compliance/",
	"config/",
	"governance/",
	"runtime/"
];

const DISALLOWED_PACKED_PATTERNS = [
  /(^|\/)dist\//,
  /(^|\/)dist-protected\//,
  /(^|\/)node_modules\//,
  /\.tgz$/,
  /jso-manifest\.json$/
];

function exec(command, args, options = {}) {
  return childProcess.execFileSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options
  });
}

function canSpawnChildren() {
  if (process.platform === "win32") {
    return false;
  }
  try {
    const result = childProcess.spawnSync(process.execPath, ["-e", ""], { stdio: "ignore" });
    const error = result && result.error;
    return !(error && (error.code === "EPERM" || error.code === "EINVAL"));
  } catch (error) {
    return !(error && (error.code === "EPERM" || error.code === "EINVAL"));
  }
}

function log(message) {
  process.stdout.write(`${message}\n`);
}

if (!canSpawnChildren()) {
  runPortableVerification();
  process.exit(0);
}

const packOutput = exec(npm, ["pack", "--json"]);
const packInfo = JSON.parse(packOutput)[0];
const tarballPath = path.join(root, packInfo.filename);
const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "jso-package-verify-"));

try {
  assertReleaseWorkflowDocs();
  log(`Packed ${packInfo.filename} with ${packInfo.files.length} files.`);
  assertPackedFiles(packInfo.files);

  exec(npm, ["init", "-y"], { cwd: projectDir });
  exec(npm, ["install", tarballPath, "--ignore-scripts"], { cwd: projectDir });

  const smokeScript = `
const assert = require("node:assert/strict");
const api = require("jso-protector");
const packageJson = require("jso-protector/package.json");
const exportsToCheck = [
  "bun",
  "browserify",
  "metro",
  "react-native",
  "next",
  "parcel",
  "rspack",
  "rspack-loader",
  "esbuild",
  "gulp",
  "grunt",
  "rollup",
  "turbopack",
  "vite",
  "webpack",
  "webpack-loader"
];
for (const name of [
  "obfuscate",
  "obfuscateMultiple",
  "buildProtectionItems",
  "buildProtectionItemsFromInputItems",
  "composeProtectionItemOutput",
  "describeProtectionTransforms",
  "getOptionsByPreset",
  "hasConditionalMarkers",
  "validateConditionalMarkers",
  "findMarkedHtmlScripts",
  "validateMarkedHtmlScripts",
  "hasMarkedHtmlScriptAttributes",
  "hasHtmlProtectionMarkers",
  "formatSourceLocation",
  "planProtection",
  "protectCodeDetailed",
  "protectFiles",
  "explainCompatibilityOption",
  "getPackageMetadata",
    "globLikeMatch",
    "normalizeDomainLockList",
    "parseArgs",
    "readStdin",
    "translateJavascriptObfuscatorConfigOptions",
    "translateJavascriptObfuscatorOptions"
]) {
  assert.equal(typeof api[name], "function", name);
}
assert.deepEqual(api.normalizeDomainLockList("example.com, app.example.com"), ["example.com", "app.example.com"]);
assert.equal(api.globLikeMatch("assets/app.js", "assets/*.js"), true);
assert.equal(api.parseArgs(["--local-only"]).localOnly, true);
assert.equal(api.translateJavascriptObfuscatorConfigOptions({ domainLock: ["example.com"] }).options.LockDomain, true);
assert.equal(api.formatSourceLocation("first\\nsecond", 6), "2:1");
assert.throws(() => api.validateConditionalMarkers("app.js", "// javascript-obfuscator:disable"), /app\\.js:1:1/);
assert.throws(() => api.validateMarkedHtmlScripts("index.html", "<script data-javascript-obfuscator src=\\"app.js\\"></script>"), /index\\.html:1:1/);
for (const name of exportsToCheck) {
  assert.equal(typeof require("jso-protector/" + name), "function", name);
}
assert.equal(api.getOptionsByPreset("balanced").DeepObfuscate, true);
assert.equal(packageJson.bin["jso-protector"], "./bin/jso-protector.js");
assert.equal(packageJson.types, "./index.d.ts");
assert.equal(packageJson.exports["./schema"], "./jso.config.schema.json");
`;
  exec(process.execPath, ["-e", smokeScript], { cwd: projectDir });

  const esmSmokeScript = `
import assert from "node:assert/strict";
import api from "jso-protector";
import protectBunBuild from "jso-protector/bun";
import browserifyProtector from "jso-protector/browserify";
import createMetroSerializer from "jso-protector/metro";
import reactNativeProtector from "jso-protector/react-native";
import withJsoProtector from "jso-protector/next";
import protectParcelBuild from "jso-protector/parcel";
import rspackProtector from "jso-protector/rspack";
import rspackLoader from "jso-protector/rspack-loader";
import esbuildProtector from "jso-protector/esbuild";
import gulpProtector from "jso-protector/gulp";
import registerGruntProtector from "jso-protector/grunt";
import rollupProtector from "jso-protector/rollup";
import protectTurbopackBuild from "jso-protector/turbopack";
import viteProtector from "jso-protector/vite";
import webpackProtector from "jso-protector/webpack";
import webpackLoader from "jso-protector/webpack-loader";
import schema from "jso-protector/schema" assert { type: "json" };

assert.equal(typeof api.obfuscate, "function");
for (const entry of [
  protectBunBuild,
  browserifyProtector,
  createMetroSerializer,
  reactNativeProtector,
  withJsoProtector,
  protectParcelBuild,
  rspackProtector,
  rspackLoader,
  esbuildProtector,
  gulpProtector,
  registerGruntProtector,
  rollupProtector,
  protectTurbopackBuild,
  viteProtector,
  webpackProtector,
  webpackLoader
]) {
  assert.equal(typeof entry, "function");
}
assert.equal(schema.type, "object");
assert.equal(typeof schema.properties.endpoint, "object");
`;
  const esmSmokePath = path.join(projectDir, "esm-smoke.mjs");
  fs.writeFileSync(esmSmokePath, esmSmokeScript, "utf8");
  exec(process.execPath, [esmSmokePath], { cwd: projectDir });

  const packageDir = path.join(projectDir, "node_modules", "jso-protector");
  verifyTypeDeclarations(packageDir);
  verifyExampleFiles(path.join(packageDir, "examples"));
  verifyExamplePackageScripts(path.join(packageDir, "examples"));
  verifyPublishMetadataGuard(packageDir);

  const binPath = path.join(packageDir, "bin", "jso-protector.js");
  exec(process.execPath, [binPath, "--help"], { cwd: projectDir });
  exec(npm, ["exec", "--", "jso-protector", "--help"], { cwd: projectDir });
  const directVersion = JSON.parse(exec(process.execPath, [binPath, "--version", "--json"], { cwd: projectDir }));
  if (directVersion.name !== "jso-protector" || directVersion.version !== packInfo.version) {
    throw new Error(`Direct CLI version metadata is wrong: ${JSON.stringify(directVersion)}`);
  }
  const linkedVersion = exec(npm, ["exec", "--", "jso-protector", "--version"], { cwd: projectDir }).trim();
  if (linkedVersion !== `jso-protector ${packInfo.version}`) {
    throw new Error(`Linked CLI version output is wrong: ${linkedVersion}`);
  }

  const explainCompat = JSON.parse(exec(npm, ["exec", "--", "jso-protector", "--explain-compat", "self-defending", "--json"], { cwd: projectDir }));
  if (
    explainCompat.option !== "selfDefending" ||
    explainCompat.status !== "mapped" ||
    explainCompat.confidence !== "direct" ||
    !Array.isArray(explainCompat.target) ||
    !explainCompat.target.includes("SelfDefending")
  ) {
    throw new Error(`Compatibility explanation output is wrong: ${JSON.stringify(explainCompat)}`);
  }

  const localOnly = JSON.parse(exec(npm, ["exec", "--", "jso-protector", "--local-only", "--json"], { cwd: projectDir }));
  if (
    localOnly.sourceLeavesMachine !== false ||
    !Array.isArray(localOnly.localPreflightCommands) ||
    !localOnly.localPreflightCommands.some((command) => command.includes("--release-check --json")) ||
    !localOnly.localPreflightCommands.some((command) => command.includes("--competitor-gap-report --json"))
  ) {
    throw new Error(`Local-only guidance output is wrong: ${JSON.stringify(localOnly)}`);
  }
  if (localOnly.npmPublished !== false || localOnly.packageDistribution !== "local-only" || !localOnly.localInstallCommands.some((command) => command.includes("./packages/jso-protector"))) {
    throw new Error(`Local package guidance output is wrong: ${JSON.stringify(localOnly)}`);
  }

  const samplePath = path.join(projectDir, "sample.js");
  fs.writeFileSync(samplePath, "console.log('sample');\n", "utf8");
  const resolvedConfig = JSON.parse(exec(process.execPath, [
    binPath,
    samplePath,
    "--print-config",
    "--json"
  ], { cwd: projectDir }));
  assertOutputPath(resolvedConfig.output, path.join(projectDir, "sample-obfuscated.js"));

  const linkedBinConfig = JSON.parse(exec(npm, [
    "exec",
    "--",
    "jso-protector",
    samplePath,
    "--print-config",
    "--json"
  ], { cwd: projectDir }));
  assertOutputPath(linkedBinConfig.output, path.join(projectDir, "sample-obfuscated.js"));

  const configPath = path.join(projectDir, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "$JSO_VERIFY_KEY",
    apiPassword: "$JSO_VERIFY_PASSWORD",
    input: "dist",
    output: "dist-protected",
    manifest: "dist-protected/jso-manifest.json",
    options: {
      EncodeStrings: true
    }
  }, null, 2));
  const distDir = path.join(projectDir, "dist");
  fs.mkdirSync(distDir, { recursive: true });
  fs.mkdirSync(path.join(projectDir, "dist-protected"), { recursive: true });
  fs.writeFileSync(path.join(distDir, "app.js"), "console.log('dist');\n", "utf8");
  fs.writeFileSync(path.join(distDir, "index.html"), "<script src=\"app.js\"></script>\n", "utf8");

  const releaseCheckEnv = {
    ...process.env,
    JSO_VERIFY_KEY: "verify-key",
    JSO_VERIFY_PASSWORD: "verify-password"
  };
  const directReleaseCheck = JSON.parse(exec(process.execPath, [
    binPath,
    "--config",
    configPath,
    "--release-check",
    "--strict",
    "--json"
  ], { cwd: projectDir, env: releaseCheckEnv }));
  assertReleaseCheck(directReleaseCheck);

  const linkedReleaseCheck = JSON.parse(exec(npm, [
    "exec",
    "--",
    "jso-protector",
    "--config",
    configPath,
    "--release-check",
    "--json"
  ], { cwd: projectDir, env: releaseCheckEnv }));
  assertReleaseCheck(linkedReleaseCheck);

  log("Package install verification passed.");
} finally {
  try {
    fs.rmSync(tarballPath, { force: true });
  } catch (error) {
    process.stderr.write(`Could not remove ${tarballPath}: ${error.message}\n`);
  }
  try {
    fs.rmSync(projectDir, { recursive: true, force: true });
  } catch (error) {
    process.stderr.write(`Could not remove ${projectDir}: ${error.message}\n`);
  }
}

function assertOutputPath(actual, expected) {
  if (path.resolve(actual) !== path.resolve(expected)) {
    throw new Error(`Expected output ${expected}, received ${actual}`);
  }
}

function assertReleaseCheck(report) {
  if (!report || report.format !== "jso-protector-release-check" || report.ok !== true) {
    throw new Error(`Release check failed: ${JSON.stringify(report)}`);
  }
  if (!report.plan || !report.plan.files.includes("app.js") || !report.plan.assets.includes("index.html")) {
    throw new Error(`Release check did not plan expected files/assets: ${JSON.stringify(report.plan)}`);
  }
  if (!report.doctor || report.doctor.ok !== true) {
    throw new Error(`Release check doctor report failed: ${JSON.stringify(report.doctor)}`);
  }
}

function assertPackedFiles(files) {
	assertCliRuntimeDependenciesDeclared();
  const packed = new Set(files.map((file) => file.path.replace(/\\/g, "/")));
  const missing = REQUIRED_PACKED_FILES.filter((file) => !packed.has(file));
  if (missing.length) {
    throw new Error(`Packed tarball is missing required file(s): ${missing.join(", ")}`);
  }

  const disallowed = Array.from(packed).filter((file) => DISALLOWED_PACKED_PATTERNS.some((pattern) => pattern.test(file)));
  if (disallowed.length) {
    throw new Error(`Packed tarball includes generated or disallowed file(s): ${disallowed.join(", ")}`);
  }
}

function assertReleaseWorkflowDocs() {
  const releaseSnippets = [
    "npm run verify:package --if-present",
    "npm run verify:publish-metadata --if-present",
    "--release-check --json",
    "--competitor-gap-report --json",
    "--script-inventory-audit",
    "--payment-page-headers-from-har",
    "--manifest dist-protected/jso-manifest.json"
  ];
  const readmeOnlySnippets = [
    "--parse-html",
    "--honor-conditional-comments",
    "--explain-compat",
    "--local-only",
    "\"jso-protector\": \"file:../packages/jso-protector\"",
    "npm pack --json",
    "prepublishOnly",
    "Payment and API Access",
    "payment-script-inventory",
    "hosted API validates the account",
    "API keys and passwords are redacted",
    "Inline `apiKey`, `apiPassword`, `--api-key`, and `--api-password` values also warn",
    "Config files can also carry mapped `javascript-obfuscator` compatibility keys"
    ,
    "jso ai usage --pretty",
    "usage.providerKey.status",
    "AiProviderKeyHealth",
    "estimate.providerKey",
    "Parcel, Bun, and Turbopack",
    "examples/parcel",
    "examples/bun",
    "examples/turbopack"
  ];
  const securitySnippets = [
    "Payment and Entitlements",
    "must not contain billing rules",
    "Unpaid, expired, disabled, or over-limit accounts",
    "redacts API key and password values",
    "--competitor-gap-report` reads config metadata and migration fields only",
    "--validate-config` warns when `apiKey`, `apiPassword`, `--api-key`, or `--api-password` contain inline values"
  ];
  const filesToCheck = [
    "README.md",
    "ci/github-actions.yml",
    "ci/gitlab-ci.yml",
    "ci/azure-pipelines.yml"
  ];

  for (const fileName of filesToCheck) {
    const text = fs.readFileSync(path.join(root, fileName), "utf8");
    for (const snippet of releaseSnippets) {
      if (!text.includes(snippet)) {
        throw new Error(`${fileName} is missing release workflow snippet: ${snippet}`);
      }
    }
  }

  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  for (const snippet of readmeOnlySnippets) {
    if (!readme.includes(snippet)) {
      throw new Error(`README.md is missing feature documentation snippet: ${snippet}`);
    }
  }

  const security = fs.readFileSync(path.join(root, "SECURITY.md"), "utf8");
  for (const snippet of securitySnippets) {
    if (!security.includes(snippet)) {
      throw new Error(`SECURITY.md is missing payment/security snippet: ${snippet}`);
    }
  }

  const migration = fs.readFileSync(path.join(root, "MIGRATION.md"), "utf8");
  if (!migration.includes("npm install --save-dev ./packages/jso-protector") || !migration.includes("\"jso-protector\": \"file:../packages/jso-protector\"")) {
    throw new Error("MIGRATION.md must document local package install paths.");
  }
  if (migration.includes("npm install --save-dev jso-protector")) {
    throw new Error("MIGRATION.md must not suggest installing jso-protector from the public npm registry.");
  }
}

function verifyExampleFiles(examplesDir) {
  for (const filePath of walkFiles(examplesDir)) {
    if (filePath.endsWith(".js") || filePath.endsWith(".cjs")) {
      exec(process.execPath, ["--check", filePath], { cwd: projectDir });
      continue;
    }
    if (filePath.endsWith(".json")) {
      JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  }
}

function runPortableVerification() {
  assertReleaseWorkflowDocs();
	assertCliRuntimeDependenciesDeclared();
  assertLocalFiles(REQUIRED_PACKED_FILES);
  verifyLocalExports();
  verifyTypeDeclarations(root);
  verifyExampleFilesPortable(path.join(root, "examples"));
  verifyExamplePackageScripts(path.join(root, "examples"));
  verifyPublishMetadataGuardPortable();
  log("Portable package verification passed (child processes unavailable in this environment).");
}

function assertCliRuntimeDependenciesDeclared() {
	const entrypoint = path.join(root, "bin", "jso-protector.js");
	const source = fs.readFileSync(entrypoint, "utf8");
	const dependencyPattern = /require\(\s*["'](\.\.\/[A-Za-z0-9_./-]+)["']\s*\)/g;
	const missing = [];
	let match;

	while ((match = dependencyPattern.exec(source))) {
		let resolved = path.relative(root, path.resolve(path.dirname(entrypoint), match[1])).replace(/\\/g, "/");
		if (!path.extname(resolved))
			resolved += ".js";
		const explicitlyIncluded = REQUIRED_PACKED_FILES.includes(resolved);
		const includedByDirectory = PACKED_DIRECTORY_PREFIXES.some((entry) => resolved.startsWith(entry));
		if (!explicitlyIncluded && !includedByDirectory)
			missing.push(resolved);
	}

	if (missing.length) {
		throw new Error(`CLI runtime dependency is not required in the packed artifact: ${Array.from(new Set(missing)).join(", ")}`);
	}
}

function assertLocalFiles(files) {
  const missing = files.filter((file) => !fs.existsSync(path.join(root, file)));
  if (missing.length) {
    throw new Error(`Workspace is missing required file(s): ${missing.join(", ")}`);
  }
}

function verifyLocalExports() {
  const api = require(path.join(root, "index.js"));
  const packageJson = require(path.join(root, "package.json"));
  const exportsToCheck = [
    "bun",
    "browserify",
    "metro",
    "react-native",
    "next",
    "parcel",
    "rspack",
    "rspack-loader",
    "esbuild",
    "gulp",
    "grunt",
    "rollup",
    "turbopack",
    "vite",
    "webpack",
    "webpack-loader"
  ];
  const exportTargets = {
    bun: "./bun.js",
    browserify: "./browserify.js",
    metro: "./metro.js",
    "react-native": "./react-native.js",
    next: "./next.js",
    parcel: "./parcel.js",
    rspack: "./rspack.js",
    "rspack-loader": "./rspack-loader.js",
    esbuild: "./esbuild.js",
    gulp: "./gulp.js",
    grunt: "./grunt.js",
    rollup: "./rollup.js",
    turbopack: "./turbopack.js",
    vite: "./vite.js",
    webpack: "./webpack.js",
    "webpack-loader": "./webpack-loader.js"
  };

  for (const name of [
    "obfuscate",
    "obfuscateMultiple",
    "buildProtectionItems",
    "buildProtectionItemsFromInputItems",
    "composeProtectionItemOutput",
    "describeProtectionTransforms",
    "getOptionsByPreset",
    "hasConditionalMarkers",
    "validateConditionalMarkers",
    "findMarkedHtmlScripts",
    "validateMarkedHtmlScripts",
    "hasMarkedHtmlScriptAttributes",
    "hasHtmlProtectionMarkers",
    "formatSourceLocation",
    "planProtection",
    "protectCodeDetailed",
    "protectFiles",
    "explainCompatibilityOption",
    "getPackageMetadata",
    "globLikeMatch",
    "normalizeDomainLockList",
    "parseArgs",
    "readStdin",
    "translateJavascriptObfuscatorConfigOptions",
    "translateJavascriptObfuscatorOptions"
  ]) {
    if (typeof api[name] !== "function") {
      throw new Error(`Expected root export ${name} to be a function.`);
    }
  }

  for (const name of exportsToCheck) {
    if (typeof require(path.join(root, `${name}.js`)) !== "function") {
      throw new Error(`Expected subpath export ${name} to be callable.`);
    }
    const exportConfig = packageJson.exports[`./${name}`];
    if (!exportConfig || exportConfig.require !== exportTargets[name] || exportConfig.default !== exportTargets[name]) {
      throw new Error(`package.json must export ./${name} to ${exportTargets[name]}.`);
    }
  }

  if (packageJson.exports["./schema"] !== "./jso.config.schema.json") {
    throw new Error("package.json must export ./schema.");
  }
}

function verifyExampleFilesPortable(examplesDir) {
  for (const filePath of walkFiles(examplesDir)) {
    if (filePath.endsWith(".js") || filePath.endsWith(".cjs")) {
      new vm.Script(fs.readFileSync(filePath, "utf8"), { filename: filePath });
      continue;
    }
    if (filePath.endsWith(".json")) {
      JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  }
}

function verifyPublishMetadataGuardPortable() {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

  // Mirrors ci/verify-publish-metadata.js: exactly two states are approved, and
  // a half-migrated package must fail rather than publish. Kept in sync
  // deliberately -- this is the second of two independent guards, so weakening
  // one alone should not be enough to let a bad state through.
  const localOnly = packageJson.private === true && packageJson.license === "UNLICENSED";
  const proprietaryPublic =
    packageJson.private !== true && packageJson.license === "SEE LICENSE IN LICENSE";

  if (!localOnly && !proprietaryPublic) {
    throw new Error(
      "Publish metadata guard: package is in neither approved state. Expected either " +
        "private:true + \"UNLICENSED\" (local-only) or private removed + " +
        "\"SEE LICENSE IN LICENSE\" (proprietary release). Found " +
        `private:${JSON.stringify(packageJson.private)} license:${JSON.stringify(packageJson.license)}.`
    );
  }
  if (proprietaryPublic && !fs.existsSync(path.join(root, "LICENSE"))) {
    throw new Error(
      "Publish metadata guard: license is \"SEE LICENSE IN LICENSE\" but no LICENSE file exists."
    );
  }
  if (!packageJson.bin || packageJson.bin["jso-protector"] !== "./bin/jso-protector.js") {
    throw new Error("Publish metadata guard expects the jso-protector bin export.");
  }
}

function verifyTypeDeclarations(packageDir) {
  const declarations = fs.readFileSync(path.join(packageDir, "index.d.ts"), "utf8");
  const requiredSnippets = [
    "export type InitTemplateName = \"browser-app\" | \"html-app\" | \"node-app\" | \"electron-app\" | \"nextjs-app\" | \"vite-app\" | \"parcel-app\" | \"bun-app\" | \"browserify-app\" | \"webpack-app\" | \"rspack-app\" | \"turbopack-app\" | \"react-native-app\";",
    "export interface PackageMetadata",
    "export interface ParsedCliArgs",
    "export interface CompetitorGapReport",
    "export interface AiProviderKeyHealth",
    "providerKey?: AiProviderKeyHealth;",
    "export function buildCompetitorGapReport",
    "label: \"validate\" | \"preview\" | \"doctor\" | \"release-check\" | \"competitor-gap\" | \"protect\";",
    "export function getPackageMetadata",
    "export function globLikeMatch",
    "export function normalizeDomainLockList",
    "export function parseArgs",
    "export function readStdin",
    "export function translateJavascriptObfuscatorConfigOptions",
    "export function writeLocalOnlyGuidance"
  ];

  for (const snippet of requiredSnippets) {
    if (!declarations.includes(snippet)) {
      throw new Error(`index.d.ts is missing declaration snippet: ${snippet}`);
    }
  }

  const parseHtmlMatches = declarations.match(/parseHtml\?: boolean/g) || [];
  if (parseHtmlMatches.length !== 1) {
    throw new Error(`index.d.ts should declare ProtectionOptions.parseHtml once, found ${parseHtmlMatches.length}.`);
  }
}

function verifyExamplePackageScripts(examplesDir) {
  const cliPackagePath = path.join(examplesDir, "cli-basic", "package.json");
  const cliPackage = JSON.parse(fs.readFileSync(cliPackagePath, "utf8"));
  if (!cliPackage.scripts || !String(cliPackage.scripts.preflight || "").includes("--release-check --json")) {
    throw new Error("examples/cli-basic/package.json must include a release-check preflight script.");
  }
  if (!String(cliPackage.scripts.release || "").includes("npm run preflight")) {
    throw new Error("examples/cli-basic/package.json release script must run preflight before protection.");
  }

  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  if (!packageJson.scripts || !String(packageJson.scripts.prepublishOnly || "").includes("verify-publish-metadata.js")) {
    throw new Error("package.json must block npm publish with ci/verify-publish-metadata.js until metadata is final.");
  }
}

function verifyPublishMetadataGuard(packageDir) {
  const guardPath = path.join(packageDir, "ci", "verify-publish-metadata.js");
  const report = JSON.parse(exec(process.execPath, [guardPath, "--allow-local", "--json"], { cwd: packageDir }));
  if (report.format !== "jso-protector-publish-metadata") {
    throw new Error(`Publish metadata guard reported wrong format: ${JSON.stringify(report)}`);
  }
  if (report.ok !== true || report.localOnly !== true || report.localAllowed !== true || report.publishReady !== false) {
    throw new Error(`Publish metadata guard should confirm the local-only package policy: ${JSON.stringify(report)}`);
  }
  if ((report.issues || []).length) {
    throw new Error(`Publish metadata guard reported unexpected local-only issues: ${JSON.stringify(report)}`);
  }
}

function walkFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(entryPath));
    else if (entry.isFile()) files.push(entryPath);
  }
  return files;
}
