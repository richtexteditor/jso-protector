#!/usr/bin/env node

"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const examplesRoot = path.join(root, "examples");
const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const expectedVersion = packageJson.version;

function fail(message) {
  process.stderr.write(`verify-examples: FAIL: ${message}\n`);
  process.exit(1);
}

function walk(folder) {
  return fs.readdirSync(folder, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(folder, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function runNode(args, options = {}) {
  const result = childProcess.spawnSync(process.execPath, args, { encoding: "utf8", ...options });
  if (result.status !== 0) fail(`${args.join(" ")} failed: ${(result.stderr || result.stdout || result.error || "unknown error").toString().trim()}`);
  return result;
}

const files = walk(examplesRoot);
const scripts = files.filter((file) => /\.(?:js|cjs)$/.test(file));
const jsonFiles = files.filter((file) => path.extname(file) === ".json");

for (const file of scripts) runNode(["--check", file]);
for (const file of jsonFiles) {
  try { JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (error) { fail(`${path.relative(root, file)} is invalid JSON: ${error.message}`); }
}

const readme = fs.readFileSync(path.join(examplesRoot, "README.md"), "utf8");
// The package is published as `javascriptobfuscator-com` since 2026-08-30;
// `jso-protector` is the deprecated former name. Assert the CANONICAL name so
// this gate cannot go on enforcing a name we no longer tell customers to install.
if (!readme.includes(`npm install --save-dev javascriptobfuscator-com@${expectedVersion}`)) fail("examples README does not install the current public version under the canonical package name");
if (readme.includes("intentionally not published to npm")) fail("examples README still says the public package is unpublished");

const reactNativeReadme = fs.readFileSync(path.join(examplesRoot, "react-native", "README.md"), "utf8");
for (const stale of ["jso-protector/metro.js", "npx jso ai compat-scan"]) {
  if (reactNativeReadme.includes(stale)) fail(`React Native guide contains stale command ${JSON.stringify(stale)}`);
}

const exportKeys = new Set(Object.keys(packageJson.exports));
for (const file of files.filter((candidate) => /\.(?:js|cjs|md)$/.test(candidate))) {
  const source = fs.readFileSync(file, "utf8");
  for (const match of source.matchAll(/(?:require\(|from\s+)["']jso-protector(\/[a-z0-9-]+)?["']/gi)) {
    const key = match[1] ? `.${match[1]}` : ".";
    if (!exportKeys.has(key)) fail(`${path.relative(root, file)} references undeclared package export ${key}`);
  }
}

const configPath = path.join(examplesRoot, "cli-basic", "jso.config.json");
if (!fs.existsSync(configPath)) fail("cli-basic/jso.config.json is missing");

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "jso-example-"));
const copied = path.join(temp, "cli-basic");
fs.cpSync(path.join(examplesRoot, "cli-basic"), copied, { recursive: true });
runNode([path.join(copied, "scripts", "build.js")], { cwd: copied });
for (const relative of ["dist/app.js", "dist/index.html"]) {
  if (!fs.existsSync(path.join(copied, relative))) fail(`cli-basic build did not produce ${relative}`);
}

const planScript = [
  `const { planProtection } = require(${JSON.stringify(root)});`,
  `const plan = planProtection({ input: "dist", output: "dist-protected", extensions: [".js"], copyAssets: true });`,
  `if (plan.summary.files.length !== 1) throw new Error("expected one JS input");`,
  `if (!plan.summary.assets.some((item) => item.endsWith("index.html"))) throw new Error("expected copied HTML asset");`
].join("\n");
runNode(["-e", planScript], { cwd: copied });

process.stdout.write(`verify-examples: PASS (${scripts.length} scripts, ${jsonFiles.length} JSON files, CLI build and offline plan)\n`);
