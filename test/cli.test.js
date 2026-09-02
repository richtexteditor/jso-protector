"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const stream = require("node:stream");
const test = require("node:test");

const cli = require("../bin/jso-protector.js");
const api = require("../index.js");
const protectBunBuild = require("../bun.js");
const browserifyProtector = require("../browserify.js");
const esbuildProtector = require("../esbuild.js");
const gulpProtector = require("../gulp.js");
const registerGruntProtector = require("../grunt.js");
const createMetroSerializer = require("../metro.js");
const reactNativeProtector = require("../react-native.js");
const withJsoProtector = require("../next.js");
const protectParcelBuild = require("../parcel.js");
const RspackProtector = require("../rspack.js");
const rspackLoader = require("../rspack-loader.js");
const rollupProtector = require("../rollup.js");
const protectTurbopackBuild = require("../turbopack.js");
const viteProtector = require("../vite.js");
const webpackLoader = require("../webpack-loader.js");
const WebpackProtector = require("../webpack.js");

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "jso-protector-"));
}

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function writeRuntimeIncidentExportJson(root, rows, extras = {}) {
  const exportPath = path.join(root, "runtime-incidents.json");
  const payload = {
    format: "jso-runtime-incident-export",
    version: 1,
    sourceFree: true,
    generatedUtc: extras.generatedUtc || "2026-06-08T12:00:00Z",
    filters: extras.filters || {},
    routing: extras.routing || {},
    responseWindow: extras.responseWindow,
    responseChecklist: extras.responseChecklist,
    dashboardActions: extras.dashboardActions,
    incidentCount: rows.length,
    incidents: rows.map((row) => {
      const incident = {
        incidentId: row.incidentId,
        status: row.status,
        severity: row.severity,
        kind: row.kind || "runtime-defense",
        reason: row.reason || "test incident",
        buildId: row.buildId || "build-runtime",
        fingerprint: row.fingerprint || "fp-runtime",
        pageUrl: row.pageUrl || "https://example.test/checkout",
        remoteIp: row.remoteIp || "203.0.113.10",
        eventUtc: row.eventUtc || "2026-06-08T11:55:00Z",
        receivedUtc: row.receivedUtc || "2026-06-08T11:56:00Z",
        userAgent: row.userAgent || "Test Browser"
      };
      if (row.actionPlan) incident.actionPlan = row.actionPlan;
      return incident;
    })
  };
  fs.writeFileSync(exportPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return exportPath;
}

function writeArchiveHygieneReport(root, overrides = {}) {
  const reportPath = path.join(root, "archive-hygiene.json");
  const payload = {
    schema: "jso.archive-hygiene.v1",
    generatedUtc: "2026-06-08T19:24:02Z",
    cutoffUtc: "2026-05-28T04:00:00Z",
    root: "D:\\secret\\workspace",
    websiteRelativePath: "2026/JSO-Website",
    policy: {
      excludedFileNames: ["Web.config"],
      excludedExtensions: [".zip"],
      excludedDirectories: ["_temp", "_RETempCode", "node_modules", "obj"],
      excludedBuildOutputs: ["bin/Debug", "bin/Release", "2026/JSO-Website/bin"],
      excludedDownloadBinaries: ["2026/JSO-Website/download/javascriptobfuscator/JSObfuscator-v3.1.1/javascriptobfuscator.*"],
      excludedEvidenceFiles: ["*.archive-hygiene.json"],
      failingSignals: [
        "MissingRequiredEntries",
        "BlockedEntries",
        "ContainsWebConfig",
        "ContainsGeneratedTemp",
        "ContainsNodeModules",
        "ContainsBuildOutput",
        "ContainsDownloadBinaries"
      ]
    },
    operatorChecklist: {
      sourceFree: true,
      beforeSharing: [
        "Confirm Web.config is absent from every generated archive.",
        "Confirm blocked entries and missing required entries are empty.",
        "Attach this hygiene report with the updated-files zip for reviewer handoff.",
        "Do not attach secrets, provider keys, webhook signing secrets, database strings, or host-specific deployment transforms."
      ],
      rotationTriggers: [
        "Rotate credentials if Web.config was included in a zip, ticket, email, chat, or source snapshot.",
        "Rotate provider keys or webhook secrets that were pasted into logs or support transcripts."
      ],
      supportBoundary: "This report is source-free. It names archive hygiene status and blocked categories only; it must not include Web.config, raw secrets, tokens, provider keys, or customer data."
    },
    archives: [
      {
        zip: "D:\\secret\\workspace\\jso-website-updated-after-2026-05-28.zip",
        entries: 128,
        size: 973761,
        missingRequiredEntries: [],
        blockedEntries: [],
        contains: {
          webConfig: false,
          generatedTemp: false,
          nodeModules: false,
          buildOutput: false,
          downloadBinaries: false
        }
      },
      {
        zip: "D:\\secret\\workspace\\jso-updated-after-2026-05-28.zip",
        entries: 353,
        size: 2723299,
        missingRequiredEntries: [],
        blockedEntries: [],
        contains: {
          webConfig: false,
          generatedTemp: false,
          nodeModules: false,
          buildOutput: false,
          downloadBinaries: false
        }
      }
    ],
    ok: true,
    ...overrides
  };
  fs.writeFileSync(reportPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return reportPath;
}

function runCli(args, input) {
  if (isChildProcessUnavailable()) {
    return runCliInline(path.join(__dirname, ".."), args, input);
  }
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(process.execPath, [
      path.join(__dirname, "..", "bin", "jso-protector.js"),
      ...args
    ], {
      cwd: path.join(__dirname, "..")
    });

    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`CLI exited with ${code}: ${stderr}`));
        return;
      }
      resolve({ stdout, stderr });
    });
    child.stdin.end(input);
  });
}

function runCliInCwd(cwd, args, input) {
  if (isChildProcessUnavailable()) {
    return runCliInline(cwd, args, input);
  }
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(process.execPath, [
      path.join(__dirname, "..", "bin", "jso-protector.js"),
      ...args
    ], { cwd });

    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`CLI exited with ${code}: ${stderr}`));
        return;
      }
      resolve({ stdout, stderr });
    });
    child.stdin.end(input);
  });
}

function isChildProcessUnavailable() {
  if (process.platform === "win32" && process.env.JSO_TEST_FORCE_CHILD_CLI !== "1") {
    return true;
  }
  try {
    const result = childProcess.spawnSync(process.execPath, ["-e", ""], { stdio: "ignore" });
    const error = result && result.error;
    return !!(error && (error.code === "EPERM" || error.code === "EINVAL"));
  } catch (error) {
    return error && (error.code === "EPERM" || error.code === "EINVAL");
  }
}

async function runCliInline(cwd, args, input) {
  const oldCwd = process.cwd();
  const stdoutChunks = [];
  const stderrChunks = [];
  const oldStdoutWrite = process.stdout.write;
  const oldStderrWrite = process.stderr.write;
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process, "stdin");
  const fakeStdin = new stream.PassThrough();
  const oldExitCode = process.exitCode;

  // Capture ONLY what the CLI writes. The test runner reports each result
  // asynchronously, one test behind, so its lines used to land inside this
  // window and be swallowed along with the CLI's output - three consecutive
  // tests then had no result at all, the runner counted them missing, and the
  // whole file was marked failed with every visible assertion passing. Anything
  // written outside the cli.main call is somebody else's and goes straight
  // through to the real stream.
  let capturing = false;

  // The runner reports asynchronously and its lines can land mid-call, so the
  // window alone is not enough: recognise the reporter's own output and let it
  // through. TAP and the spec reporter both start a result line distinctively,
  // and the CLI under test never writes anything shaped like that.
  const isRunnerOutput = (text) =>
    /^(TAP version|ok \d|not ok \d|# |1\.\.\d|✔ |✖ |ℹ )/.test(text) ||
    text.startsWith("  ---") || text.startsWith("  ...");

  process.stdout.write = function patchedStdout(chunk, encoding, callback) {
    const text = String(chunk);
    if (!capturing || isRunnerOutput(text)) {
      return oldStdoutWrite.call(process.stdout, chunk, encoding, callback);
    }
    stdoutChunks.push(text);
    if (typeof callback === "function") callback();
    return true;
  };
  process.stderr.write = function patchedStderr(chunk, encoding, callback) {
    if (!capturing) return oldStderrWrite.call(process.stderr, chunk, encoding, callback);
    stderrChunks.push(String(chunk));
    if (typeof callback === "function") callback();
    return true;
  };

  try {
    process.chdir(cwd);
    Object.defineProperty(process, "stdin", {
      configurable: true,
      value: fakeStdin
    });
    fakeStdin.end(input);

    process.exitCode = undefined;
    capturing = true;
    try {
      await cli.main(args);
    } finally {
      capturing = false;
    }
    const code = process.exitCode || 0;
    if (code !== 0) {
      const stderr = stderrChunks.join("");
      throw new Error(`CLI exited with ${code}: ${stderr}`);
    }
    return {
      stdout: stdoutChunks.join(""),
      stderr: stderrChunks.join("")
    };
  } catch (error) {
    if (error && /^CLI exited with \d+:/.test(error.message)) {
      throw error;
    }
    const stderr = `${stderrChunks.join("")}jso-protector: ${error.message}\n`;
    throw new Error(`CLI exited with 1: ${stderr}`);
  } finally {
    process.stdout.write = oldStdoutWrite;
    process.stderr.write = oldStderrWrite;
    if (stdinDescriptor) {
      Object.defineProperty(process, "stdin", stdinDescriptor);
    }
    process.exitCode = oldExitCode;
    process.chdir(oldCwd);
  }
}

function runObjectStream(stream, files) {
  return new Promise((resolve, reject) => {
    const output = [];
    stream.on("data", (file) => output.push(file));
    stream.on("error", reject);
    stream.on("finish", () => resolve(output));
    for (const file of files) stream.write(file);
    stream.end();
  });
}

function runTextStream(stream, input) {
  return new Promise((resolve, reject) => {
    let output = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      output += chunk;
    });
    stream.on("error", reject);
    stream.on("finish", () => resolve(output));
    stream.end(input);
  });
}

function runWebpackLoader(loader, context, source, sourceMap, meta) {
  return new Promise((resolve, reject) => {
    const loaderContext = {
      ...context,
      async() {
        return (error, code, map, loaderMeta) => {
          if (error) reject(error);
          else resolve({ code, map, meta: loaderMeta });
        };
      }
    };
    try {
      loader.call(loaderContext, source, sourceMap, meta);
    } catch (error) {
      reject(error);
    }
  });
}

function runRegisteredGruntTask(register, options, files) {
  return new Promise((resolve, reject) => {
    const tasks = {};
    const grunt = {
      file: {
        exists: fs.existsSync,
        read(filePath) {
          return fs.readFileSync(filePath, "utf8");
        },
        mkdir(dir) {
          fs.mkdirSync(dir, { recursive: true });
        },
        write(filePath, contents) {
          fs.writeFileSync(filePath, contents, "utf8");
        }
      },
      registerMultiTask(name, _description, task) {
        tasks[name] = task;
      }
    };
    register(grunt);
    tasks.jsoProtector.call({
      files,
      options(defaults) {
        return { ...defaults, ...options };
      },
      async() {
        return (error) => {
          if (error) reject(error);
          else resolve();
        };
      }
    });
  });
}

function findDuplicateJsonKeys(text, file) {
  let index = 0;
  const duplicates = [];

  const skipWhitespace = () => {
    while (index < text.length && /\s/.test(text[index])) index++;
  };

  const fail = (message) => {
    throw new Error(`${file}: ${message} at index ${index}`);
  };

  const parseString = () => {
    if (text[index] !== "\"") fail("expected string");
    index++;
    let value = "";
    while (index < text.length) {
      const ch = text[index++];
      if (ch === "\"") return value;
      if (ch === "\\") {
        if (index >= text.length) fail("unterminated escape");
        const esc = text[index++];
        if (esc === "u") {
          const hex = text.slice(index, index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("invalid unicode escape");
          value += String.fromCharCode(parseInt(hex, 16));
          index += 4;
          continue;
        }
        const map = {
          "\"": "\"",
          "\\": "\\",
          "/": "/",
          b: "\b",
          f: "\f",
          n: "\n",
          r: "\r",
          t: "\t"
        };
        value += map[esc] || esc;
        continue;
      }
      value += ch;
    }
    fail("unterminated string");
  };

  const parseNumber = () => {
    const match = text.slice(index).match(/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/);
    if (!match) fail("invalid number");
    index += match[0].length;
  };

  const parseLiteral = (literal) => {
    if (!text.startsWith(literal, index)) fail(`expected ${literal}`);
    index += literal.length;
  };

  const parseValue = () => {
    skipWhitespace();
    const ch = text[index];
    if (ch === "{") return parseObject();
    if (ch === "[") return parseArray();
    if (ch === "\"") return parseString();
    if (ch === "-" || /\d/.test(ch)) return parseNumber();
    if (text.startsWith("true", index)) return parseLiteral("true");
    if (text.startsWith("false", index)) return parseLiteral("false");
    if (text.startsWith("null", index)) return parseLiteral("null");
    fail("unexpected token");
  };

  const parseArray = () => {
    index++;
    skipWhitespace();
    if (text[index] === "]") {
      index++;
      return;
    }
    while (index < text.length) {
      parseValue();
      skipWhitespace();
      if (text[index] === ",") {
        index++;
        skipWhitespace();
        continue;
      }
      if (text[index] === "]") {
        index++;
        return;
      }
      fail("expected , or ]");
    }
    fail("unterminated array");
  };

  const parseObject = () => {
    index++;
    skipWhitespace();
    const seen = new Set();
    if (text[index] === "}") {
      index++;
      return;
    }
    while (index < text.length) {
      const key = parseString();
      if (seen.has(key)) duplicates.push(key);
      seen.add(key);
      skipWhitespace();
      if (text[index] !== ":") fail("expected :");
      index++;
      parseValue();
      skipWhitespace();
      if (text[index] === ",") {
        index++;
        skipWhitespace();
        continue;
      }
      if (text[index] === "}") {
        index++;
        return;
      }
      fail("expected , or }");
    }
    fail("unterminated object");
  };

  parseValue();
  skipWhitespace();
  if (index !== text.length) fail("unexpected trailing content");
  return [...new Set(duplicates)];
}

test("parseArgs reads common flags", () => {
  const args = cli.parseArgs([
    "--config", "jso.config.json",
    "--mode", "production",
    "--input", "dist",
    "--output", "protected",
    "--endpoint", "https://example.test/HttpApi.ashx",
    "--api-key", "key",
    "--api-password", "pwd",
    "--doctor",
    "--check-api",
    "--release-check",
    "--strict",
    "--validate-config",
    "--print-config",
    "--list-presets",
    "--list-options",
    "--compat-scan",
    "--stdin",
    "--stdout",
    "--file-name", "pipe.js",
    "--options-preset", "medium-obfuscation",
    "--preset", "maximum",
    "--web-preset", "online-preset.json",
    "--migrate-javascript-obfuscator", "javascript-obfuscator.json",
    "--list-migration-map",
    "--explain-compat", "self-defending",
    "--local-only",
    "--verify-manifest", "dist-protected/jso-manifest.json",
    "--verify-root", "artifact-root",
    "--audit-source-maps",
    "--source-map-evidence", "dist-protected/jso-manifest.json",
    "--source-map-evidence-output", "reports/source-map-evidence.md",
    "--deployment-hygiene-evidence", "reports/archive-hygiene.json",
    "--deployment-hygiene-output", "reports/deployment-hygiene.md",
    "--runtime-incident-evidence", "reports/runtime-incidents.json",
    "--runtime-incident-evidence-output", "reports/runtime-incident-evidence.md",
    "--migration-review",
    "--migration-review-output", "reports/migration-review.md",
    "--identifier-cache-review",
    "--identifier-cache-review-output", "reports/identifier-cache-review.md",
    "--runtime-defense-review",
    "--runtime-defense-review-output", "reports/runtime-defense-review.md",
    "--ai-resistance-evidence", "dist-protected/jso-report.json",
    "--ai-resistance-evidence-output", "reports/ai-resistance-evidence.md",
    "--vm-proof-pack", "dist-protected/jso-report.json",
    "--vm-proof-output", "reports/vm-proof-pack.md",
    "--script-inventory-from-snapshot", "reports/runtime-inventory.json",
    "--script-inventory-output", "reports/payment-script-inventory.json",
    "--payment-page-headers-from-har", "reports/checkout.har",
    "--payment-page-headers-baseline", "reports/payment-page-headers.baseline.json",
    "--payment-page-headers-output", "reports/payment-page-headers.json",
    "--payment-page-url-pattern", "/checkout",
    "--script-inventory-audit", "reports/payment-script-inventory.json",
    "--runtime-inventory-snapshot", "reports/runtime-inventory.json",
    "--script-inventory-audit-output", "reports/payment-script-inventory-audit.md",
    "--option", "LockDomain=true",
    "--option", "SelfCompressionMinSize=64",
    "--reserved-name", "^PublicApi$",
    "--reserved-names", "^LegacyApi$",
    "--include", "assets/*.js",
    "--exclude", "**/legacy/**",
    "--asset-exclude", "**/*.license",
    "--parse-html",
    "--honor-conditional-comments",
    "--protect-marked-comments",
    "--ignore-imports",
    "--keep-header-comment",
    "--protect-object-declaration",
    "--move-nested-function",
    "--formatted-output",
    "--keep-indent",
    "--line-numbers",
    "--string-array",
    "--string-array-encoding", "rc4",
    "--split-strings", "true",
    "--split-strings-chunk-length", "6",
    "--unicode-escape-sequence", "true",
    "--control-flow-flattening",
    "--dead-code-injection-threshold", "0.7",
    "--identifier-names-generator", "hexadecimal",
    "--rename-globals", "true",
    "--rename-properties", "true",
    "--target", "node",
    "--compact", "true",
    "--domain-lock", "example.com",
    "--domain-lock-redirect-url", "/domain-blocked",
    "--source-map", "false",
    "--source-map-sources-mode", "sources-content",
    "--strict-mode", "false",
    "--identifier-names-cache", "cache.json",
    "--identifier-names-cache-path", ".obfuscator-cache.json",
    "--identifiers-dictionary", "alpha,beta",
    "--identifiers-prefix", "release_",
    "--self-defending", "true",
    "--self-defending-interval-seconds", "30",
    "--self-healing", "true",
    "--self-healing-max-attempts", "3",
    "--anti-monkey-patching", "true",
    "--anti-monkey-patching-clean-realm", "false",
    "--runtime-defense-action", "degrade",
    "--runtime-defense-callback", "App.onDefense",
    "--runtime-defense-redirect-url", "/blocked",
    "--debug-protection", "false",
    "--debug-protection-interval", "500",
    "--disable-console-output", "false",
    "--reserved-strings", "^License",
	"--force-transform-strings", "^Forced",
    "--numbers-to-expressions", "true",
    "--rename-properties-mode", "safe",
    "--input-file-name", "bundle.js",
    "--log", "true",
    "--seed", "42",
    "--string-array-index-shift", "true",
    "--string-array-shuffle", "true",
    "--string-array-rotate", "true",
    "--string-array-indexes-type", "hexadecimal-number,hexadecimal-numeric-string",
    "--string-array-threshold", "0.5",
    "--string-array-calls-transform", "true",
    "--string-array-calls-transform-threshold", "0.75",
    "--string-array-wrappers-count", "3",
    "--string-array-wrappers-chained-calls", "false",
    "--string-array-wrappers-parameters-max-count", "5",
    "--string-array-wrappers-type", "function",
    "--transform-object-keys", "true",
    "--manifest", "jso-manifest.json",
    "--max-output-bytes", "4096",
    "--max-growth-ratio", "8",
    "--dry-run",
    "--json",
    "--version"
  ]);

  assert.equal(args.config, "jso.config.json");
  assert.equal(args.mode, "production");
  assert.equal(args.input, "dist");
  assert.equal(args.output, "protected");
  assert.equal(args.endpoint, "https://example.test/HttpApi.ashx");
  assert.equal(args.apiKey, "key");
  assert.equal(args.apiPassword, "pwd");
  assert.equal(args.doctor, true);
  assert.equal(args.checkApi, true);
  assert.equal(args.releaseCheck, true);
  assert.equal(args.strict, true);
  assert.equal(args.validateConfig, true);
  assert.equal(args.printConfig, true);
  assert.equal(args.listPresets, true);
  assert.equal(args.listOptions, true);
  assert.equal(args.compatScan, true);
  assert.equal(args.stdin, true);
  assert.equal(args.stdout, true);
  assert.equal(args.fileName, "pipe.js");
  assert.equal(args.preset, "maximum");
  assert.equal(args.webPreset, "online-preset.json");
  assert.equal(args.migrateJavascriptObfuscator, "javascript-obfuscator.json");
  assert.equal(args.listMigrationMap, true);
  assert.equal(args.explainCompat, "self-defending");
  assert.equal(args.localOnly, true);
  assert.equal(args.verifyManifest, "dist-protected/jso-manifest.json");
  assert.equal(args.verifyRoot, "artifact-root");
  assert.equal(args.auditSourceMaps, true);
  assert.equal(args.sourceMapEvidence, "dist-protected/jso-manifest.json");
  assert.equal(args.sourceMapEvidenceOutput, "reports/source-map-evidence.md");
  assert.equal(args.deploymentHygieneEvidence, "reports/archive-hygiene.json");
  assert.equal(args.deploymentHygieneOutput, "reports/deployment-hygiene.md");
  assert.equal(args.runtimeIncidentEvidence, "reports/runtime-incidents.json");
  assert.equal(args.runtimeIncidentEvidenceOutput, "reports/runtime-incident-evidence.md");
  assert.equal(args.migrationReview, true);
  assert.equal(args.migrationReviewOutput, "reports/migration-review.md");
  assert.equal(args.identifierCacheReview, true);
  assert.equal(args.identifierCacheReviewOutput, "reports/identifier-cache-review.md");
  assert.equal(args.runtimeDefenseReview, true);
  assert.equal(args.runtimeDefenseReviewOutput, "reports/runtime-defense-review.md");
  assert.equal(args.aiResistanceEvidence, "dist-protected/jso-report.json");
  assert.equal(args.aiResistanceEvidenceOutput, "reports/ai-resistance-evidence.md");
  assert.equal(args.vmProofPack, "dist-protected/jso-report.json");
  assert.equal(args.vmProofOutput, "reports/vm-proof-pack.md");
  assert.equal(args.scriptInventoryFromSnapshot, "reports/runtime-inventory.json");
  assert.equal(args.scriptInventoryOutput, "reports/payment-script-inventory.json");
  assert.equal(args.paymentPageHeadersFromHar, "reports/checkout.har");
  assert.equal(args.paymentPageHeadersBaseline, "reports/payment-page-headers.baseline.json");
  assert.equal(args.paymentPageHeadersOutput, "reports/payment-page-headers.json");
  assert.equal(args.paymentPageUrlPattern, "/checkout");
  assert.equal(args.scriptInventoryAudit, "reports/payment-script-inventory.json");
  assert.equal(args.runtimeInventorySnapshot, "reports/runtime-inventory.json");
  assert.equal(args.scriptInventoryAuditOutput, "reports/payment-script-inventory-audit.md");
  assert.deepEqual(args.options, [
    "LockDomain=true",
    "SelfCompressionMinSize=64",
    "MoveStrings=true",
    "EncryptStrings=true",
    "SplitStrings=true",
    "SplitStringsChunkLength=6",
    "EncodeStrings=true",
    "DeepObfuscate=true",
    "FlatTransform=true",
    "DeadcodeLevel=High",
    "IdentityStyle=v1hex",
    "RenameGlobals=true",
    "RenameMembers=true",
    "OptimizationMode=NodeJS",
    "SelfCompression=true",
    "CompressionRatio=Best",
    "LockDomain=true",
    "LockDomainList=example.com",
    "LockDomainRedirectUrl=/domain-blocked",
    "SelfDefending=true",
    "SelfDefendingIntervalSeconds=30",
    "SelfHealing=true",
    "SelfHealingMaxAttempts=3",
    "AntiMonkeyPatching=true",
    "AntiMonkeyPatchingCleanRealm=false",
    "RuntimeDefenseAction=degrade",
    "RuntimeDefenseCallback=App.onDefense",
    "RuntimeDefenseRedirectUrl=/blocked",
    "DebugProtection=false",
    "DebugProtectionIntervalMilliseconds=500",
    "DisableConsoleOutput=false",
	"ReservedStrings=^License",
	"ForceTransformStrings=^Forced",
    "EncodeNumbers=true",
    "Seed=42",
    "StringArrayIndexShift=true",
    "StringArrayShuffle=true",
    "StringArrayRotate=true",
    "StringArrayIndexesType=hexadecimal-number\nhexadecimal-numeric-string"
    ,"MoveStrings=true",
    "StringArrayThreshold=0.5",
    "StringArrayCallsTransform=true",
    "StringArrayCallsTransformThreshold=0.75"
    ,"StringArrayWrappersCount=3",
    "StringArrayWrappersChainedCalls=false",
    "StringArrayWrappersParametersMaxCount=5",
    "StringArrayWrappersType=function",
    "TransformObjectKeys=true"
  ]);
  assert.deepEqual(args.reservedNames, ["^PublicApi$", "^LegacyApi$"]);
  assert.deepEqual(args.include, ["assets/*.js"]);
  assert.deepEqual(args.exclude, ["**/legacy/**"]);
  assert.deepEqual(args.assetExclude, ["**/*.license"]);
  assert.equal(args.parseHtml, true);
  assert.equal(args.honorConditionalComments, true);
  assert.equal(args.protectMarkedComments, true);
  assert.equal(args.ignoreImports, true);
  assert.equal(args.keepHeaderComment, true);
  assert.equal(args.protectObjectDeclaration, true);
  assert.equal(args.moveNestedFunction, true);
  assert.equal(args.formattedOutput, true);
  assert.equal(args.keepIndent, true);
  assert.equal(args.lineNumbers, true);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--self-defending")), false);
  // --seed is now a real, functional option (Seed=42 above), not a compat no-op.
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--seed")), false);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--identifier-names-cache")), true);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--identifiers-dictionary")), true);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--identifiers-prefix")), true);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--source-map-sources-mode")), true);
  assert.equal(args.compatibilityReviewFields.includes("identifierNamesCache"), true);
  assert.equal(args.compatibilityReviewFields.includes("identifierNamesCachePath"), true);
  assert.equal(args.compatibilityReviewFields.includes("identifiersDictionary"), true);
  assert.equal(args.compatibilityReviewFields.includes("identifiersPrefix"), true);
  assert.equal(args.compatibilityReviewFields.includes("sourceMap"), true);
  assert.equal(args.compatibilityReviewFields.includes("sourceMapSourcesMode"), true);
  assert.equal(args.compatibilityReviewFields.includes("selfDefending"), false);
  assert.equal(args.compatibilityReviewFields.includes("debugProtectionInterval"), false);
  assert.equal(args.compatibilityReviewFields.includes("disableConsoleOutput"), false);
  assert.equal(args.compatibilityReviewFields.includes("domainLockRedirectUrl"), false);
  assert.equal(args.compatibilityReviewFields.includes("reservedStrings"), false);
  assert.equal(args.compatibilityReviewFields.includes("forceTransformStrings"), false);
  assert.equal(args.compatibilityReviewFields.includes("strictMode"), true);
  assert.equal(args.compatibilityReviewFields.includes("renamePropertiesMode"), true);
  // seed is no longer a review-only field; it maps to the real Seed option.
  assert.equal(args.compatibilityReviewFields.includes("seed"), false);
  assert.equal(args.compatibilityReviewFields.includes("stringArrayIndexShift"), false);
  assert.equal(args.compatibilityReviewFields.includes("stringArrayShuffle"), false);
  assert.equal(args.compatibilityReviewFields.includes("stringArrayRotate"), false);
  assert.equal(args.compatibilityReviewFields.includes("stringArrayIndexesType"), false);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--strict-mode")), true);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--rename-properties-mode")), true);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--string-array-index-shift")), false);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--string-array-shuffle")), false);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--string-array-rotate")), false);
  assert.equal(args.compatibilityWarnings.some((warning) => warning.includes("--string-array-indexes-type")), false);
  assert.equal(args.manifest, "jso-manifest.json");
  assert.equal(args.maxOutputBytes, 4096);
  assert.equal(args.maxGrowthRatio, 8);
  assert.equal(args.dryRun, true);
  assert.equal(args.json, true);
  assert.equal(args.version, true);
});

test("version output supports text and json metadata", async () => {
  const packageJson = require("../package.json");

  assert.deepEqual(cli.getPackageMetadata(), {
    name: packageJson.name,
    version: packageJson.version,
    description: packageJson.description,
    homepage: packageJson.homepage,
    endpoint: cli.DEFAULT_ENDPOINT
  });

  const text = await runCli(["--version"]);
  assert.equal(text.stdout.trim(), `jso-protector ${packageJson.version}`);

  const json = await runCli(["--version", "--json"]);
  const metadata = JSON.parse(json.stdout);
  assert.equal(metadata.name, "jso-protector");
  assert.equal(metadata.version, packageJson.version);
  assert.equal(metadata.endpoint, cli.DEFAULT_ENDPOINT);
});

test("parseArgs maps javascript-obfuscator options presets", () => {
  assert.equal(cli.parseArgs(["--options-preset", "default"]).preset, "standard");
  assert.equal(cli.parseArgs(["--options-preset", "low-obfuscation"]).preset, "standard");
  assert.equal(cli.parseArgs(["--options-preset", "vm-default"]).preset, "standard");
  assert.equal(cli.parseArgs(["--options-preset", "medium-obfuscation"]).preset, "balanced");
  assert.equal(cli.parseArgs(["--options-preset", "vm-medium-obfuscation"]).preset, "balanced");
  assert.equal(cli.parseArgs(["--options-preset", "high-obfuscation"]).preset, "maximum");
  assert.equal(cli.parseArgs(["--options-preset", "vm-anti-llm"]).preset, "maximum");
  assert.throws(() => cli.parseArgs(["--options-preset", "extreme"]), /Unknown javascript-obfuscator options preset/);
});

test("mergeConfig resolves env references and paths relative to config", () => {
  const root = makeTempDir();
  process.env.JSO_TEST_KEY = "resolved-key";
  process.env.JSO_TEST_PASSWORD = "resolved-password";

  const config = {
    __configDir: root,
    apiKey: "$JSO_TEST_KEY",
    apiPassword: "$JSO_TEST_PASSWORD",
    input: "dist",
    output: "protected",
    extensions: ["js"],
    exclude: ["**/*.map"],
    preset: "balanced",
    include: ["assets/*.js"],
    manifest: "release-manifest.json",
    maxOutputBytes: 2048,
    maxGrowthRatio: 6,
    reservedNames: ["^PublicApi$", "^keep_"],
    options: { EncodeStrings: true }
  };

  const merged = cli.mergeConfig(config, {});
  assert.equal(merged.apiKey, "resolved-key");
  assert.equal(merged.apiPassword, "resolved-password");
  assert.equal(merged.preset, "balanced");
  assert.equal(merged.options.DeepObfuscate, true);
  assert.equal(merged.options.VariableExclusion, "^PublicApi$\n^keep_");
  assert.deepEqual(merged.include, ["assets/*.js"]);
  assert.equal(merged.manifest, path.join(root, "release-manifest.json"));
  assert.equal(merged.maxOutputBytes, 2048);
  assert.equal(merged.maxGrowthRatio, 6);
  assert.deepEqual(merged.extensions, [".js"]);
  assert.equal(merged.input, path.join(root, "dist"));
  assert.equal(merged.output, path.join(root, "protected"));
});

test("mergeConfig reads long-form environment aliases", () => {
  const root = makeTempDir();
  const oldKey = process.env.JAVASCRIPT_OBFUSCATOR_API_KEY;
  const oldPassword = process.env.JAVASCRIPT_OBFUSCATOR_API_PASSWORD;
  const oldEndpoint = process.env.JAVASCRIPT_OBFUSCATOR_ENDPOINT;
  const oldShortKey = process.env.JSO_API_KEY;
  const oldShortPassword = process.env.JSO_API_PASSWORD;
  const oldShortEndpoint = process.env.JSO_ENDPOINT;

  delete process.env.JSO_API_KEY;
  delete process.env.JSO_API_PASSWORD;
  delete process.env.JSO_ENDPOINT;
  process.env.JAVASCRIPT_OBFUSCATOR_API_KEY = "alias-key";
  process.env.JAVASCRIPT_OBFUSCATOR_API_PASSWORD = "alias-password";
  process.env.JAVASCRIPT_OBFUSCATOR_ENDPOINT = "https://example.test/HttpApi.ashx";

  try {
    const merged = cli.mergeConfig({
      __configDir: root,
      input: "dist",
      output: "protected"
    }, {});

    assert.equal(merged.apiKey, "alias-key");
    assert.equal(merged.apiPassword, "alias-password");
    assert.equal(merged.endpoint, "https://example.test/HttpApi.ashx");
  } finally {
    restoreEnv("JAVASCRIPT_OBFUSCATOR_API_KEY", oldKey);
    restoreEnv("JAVASCRIPT_OBFUSCATOR_API_PASSWORD", oldPassword);
    restoreEnv("JAVASCRIPT_OBFUSCATOR_ENDPOINT", oldEndpoint);
    restoreEnv("JSO_API_KEY", oldShortKey);
    restoreEnv("JSO_API_PASSWORD", oldShortPassword);
    restoreEnv("JSO_ENDPOINT", oldShortEndpoint);
  }
});

test("mergeConfig applies command-line option and filter overrides", () => {
  const root = makeTempDir();
  const merged = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    preset: "standard",
    include: ["assets/*.js"],
    exclude: ["**/*.map"],
    assetExclude: ["**/*.map"],
    reservedNames: ["^ConfigName$"],
    options: {
      LockDomain: false,
      LockDomainList: "old.example"
    }
  }, {
    options: ["LockDomain=true", "LockDomainList=example.com", "SelfCompressionMinSize=128"],
    include: ["chunks/*.js"],
    exclude: ["**/legacy/**"],
    assetExclude: ["**/*.license"],
    reservedNames: ["^CliName$"]
  });

  assert.equal(merged.options.LockDomain, true);
  assert.equal(merged.options.LockDomainList, "example.com");
  assert.equal(merged.options.SelfCompressionMinSize, 128);
  assert.equal(merged.options.VariableExclusion, "^CliName$");
  assert.deepEqual(merged.include, ["chunks/*.js"]);
  assert.deepEqual(merged.exclude, ["**/*.map", "**/legacy/**"]);
  assert.deepEqual(merged.assetExclude, ["**/*.map", "**/*.license"]);
});

test("mergeConfig defaults removeSourceMaps to true and respects false overrides", () => {
  const root = makeTempDir();
  const defaultConfig = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected"
  }, {});
  const preservedConfig = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    removeSourceMaps: false
  }, {});

  assert.equal(defaultConfig.removeSourceMaps, true);
  assert.equal(preservedConfig.removeSourceMaps, false);
});

test("mergeConfig applies convenience protection aliases before raw option overrides", () => {
  const root = makeTempDir();
  const merged = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    keepHeaderComment: true,
    targetVersion: "modern",
    downlevelIteration: true,
    protectObjectDeclaration: true,
    moveNestedFunction: true,
    formattedOutput: true,
    keepIndent: true,
    lineNumbers: true,
    lockDomainSubdomains: true,
    lockDomainMessage: "license required",
    lockDate: true,
    lockDateValue: "20260531",
    lockDateMessage: "expired",
    selfHealing: true,
    selfHealingMaxAttempts: 3,
    antiMonkeyPatching: true,
    antiMonkeyPatchingCleanRealm: false,
    antiMonkeyPatchingIncludeGlobals: "crypto.getRandomValues",
    antiMonkeyPatchingExcludeGlobals: "fetch",
    runtimeDefenseAction: "degrade",
    options: {
      MoveNested: false
    }
  }, {
    options: ["LockDateMsg=extended"]
  });

  assert.equal(merged.options.KeepComment, true);
  assert.equal(merged.options.TargetVersion, "modern");
  assert.equal(merged.options.DownlevelIteration, true);
  assert.equal(merged.options.ReorderCodeObjectDeclare, true);
  assert.equal(merged.options.MoveNested, false);
  assert.equal(merged.options.WriteFormats, true);
  assert.equal(merged.options.WriteFormats_KeepIndent, true);
  assert.equal(merged.options.WriteFormats_LineNumbers, true);
  assert.equal(merged.options.LockDomainSubs, true);
  assert.equal(merged.options.LockDomainMsg, "license required");
  assert.equal(merged.options.LockDate, true);
  assert.equal(merged.options.LockDateValue, "20260531");
  assert.equal(merged.options.LockDateMsg, "extended");
  assert.equal(merged.options.SelfHealing, true);
  assert.equal(merged.options.SelfHealingMaxAttempts, 3);
  assert.equal(merged.options.AntiMonkeyPatching, true);
  assert.equal(merged.options.AntiMonkeyPatchingCleanRealm, false);
  assert.equal(merged.options.AntiMonkeyPatchingIncludeGlobals, "crypto.getRandomValues");
  assert.equal(merged.options.AntiMonkeyPatchingExcludeGlobals, "fetch");
  assert.equal(merged.options.RuntimeDefenseAction, "degrade");
});

test("mergeConfig maps javascript-obfuscator compatibility fields in config files", () => {
  const root = makeTempDir();
  const merged = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    optionsPreset: "high-obfuscation",
    controlFlowFlattening: true,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.7,
    domainLock: ["example.com", "app.example.com"],
    identifierNamesGenerator: "hexadecimal",
    parseHtml: true,
    renameGlobals: true,
    renameProperties: true,
    selfDefending: true,
    selfDefendingIntervalSeconds: 45,
    debugProtection: false,
    stringArray: true,
    splitStrings: true,
    splitStringsChunkLength: 7,
    stringArrayEncoding: ["rc4"],
    target: "node",
    unicodeEscapeSequence: true,
    options: {
      LockDomainList: "override.example"
    }
  }, {});

  assert.equal(merged.preset, "maximum");
  assert.equal(merged.parseHtml, true);
  assert.equal(merged.options.MoveStrings, true);
  assert.equal(merged.options.SplitStrings, true);
  assert.equal(merged.options.SplitStringsChunkLength, 7);
  assert.equal(merged.options.EncodeStrings, true);
  assert.equal(merged.options.EncryptStrings, true);
  assert.equal(merged.options.DeepObfuscate, true);
  assert.equal(merged.options.FlatTransform, true);
  assert.equal(merged.options.AddDeadCode, true);
  assert.equal(merged.options.DeadcodeLevel, "High");
  assert.equal(merged.options.IdentityStyle, "v1hex");
  assert.equal(merged.options.RenameGlobals, true);
  assert.equal(merged.options.RenameMembers, true);
  assert.equal(merged.options.SelfDefending, true);
  assert.equal(merged.options.DebugProtection, false);
  assert.equal(merged.options.OptimizationMode, "NodeJS");
  assert.equal(merged.options.LockDomain, true);
  assert.equal(merged.options.LockDomainList, "override.example");
  assert.equal(merged.extensions.includes(".html"), true);
  assert.equal(merged.extensions.includes(".aspx"), true);
  assert.equal(merged.markupExtensions.includes(".php"), true);
});

test("mergeConfig allows custom markup extensions for parseHtml workflows", () => {
  const root = makeTempDir();
  const merged = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    parseHtml: true,
    markupExtensions: [".tpl", ".edge"]
  }, {});

  assert.deepEqual(merged.markupExtensions, [".tpl", ".edge"]);
  assert.equal(merged.extensions.includes(".tpl"), true);
  assert.equal(merged.extensions.includes(".edge"), true);
  assert.equal(merged.extensions.includes(".html"), false);
});

test("api translates JS-Confuser option bags to hosted API options", () => {
  const translated = api.translateJsConfuserOptions({
    preset: "high",
    target: "node",
    renameVariables: true,
    renameGlobals: true,
    stringEncoding: true,
    stringConcealing: true,
    duplicateLiteralsRemoval: true,
    stringSplitting: 0.5,
    stringCompression: true,
    controlFlowFlattening: true,
    deadCode: true,
    identifierGenerator: "hexadecimal",
    hexadecimalNumbers: true,
    lock: {
      domainLock: ["example.com", "app.example.com"],
      endDate: "2026-05-31",
	  antiDebug: true,
	  integrity: 0.5,
	  selfDefending: true,
	  startDate: "2026-05-01",
	  tamperProtection: 1,
      countermeasures: "panic"
    }
  });

  assert.equal(translated.preset, "maximum");
  assert.equal(translated.options.OptimizationMode, "NodeJS");
  assert.equal(translated.options.ReplaceNames, true);
  assert.equal(translated.options.RenameGlobals, true);
  assert.equal(translated.options.EncodeStrings, true);
  assert.equal(translated.options.EncryptStrings, true);
  assert.equal(translated.options.MoveStrings, true);
  assert.equal(translated.options.SplitStrings, true);
  assert.equal(translated.options.SelfCompression, true);
  assert.equal(translated.options.FlatTransform, true);
  assert.equal(translated.options.DeepObfuscate, true);
  assert.equal(translated.options.AddDeadCode, true);
  assert.equal(translated.options.EncodeNumbers, true);
  assert.equal(translated.options.IdentityStyle, "v1hex");
  assert.equal(translated.options.LockDomain, true);
  assert.equal(translated.options.LockDomainList, "example.com\napp.example.com");
  assert.equal(translated.options.LockDate, true);
  assert.equal(translated.options.LockDateValue, "20260531");
  assert.equal(translated.options.DebugProtection, true);
  assert.equal(translated.options.SelfDefending, true);
  assert.equal(translated.options.LockStartDate, true);
  assert.equal(translated.options.LockStartDateValue, "20260501");
  assert.equal(translated.options.AntiMonkeyPatching, true);
  assert.equal(translated.jsConfuserLockCountermeasures, "panic");
});

test("api normalizes top-level JS-Confuser lock options in Node API calls", () => {
  const config = api.createProtectionConfig({
    preset: "high",
    target: "node",
    renameVariables: true,
    lock: {
      domainLock: ["example.com", "app.example.com"],
      endDate: "2026-05-31",
      antiDebug: true,
      integrity: 0.5,
      selfDefending: true,
      startDate: "2026-05-01",
      countermeasures: "panic",
      tamperProtection: 1
    }
  });

  assert.equal(config.preset, "maximum");
  assert.equal(config.options.OptimizationMode, "NodeJS");
  assert.equal(config.options.ReplaceNames, true);
  assert.equal(config.options.LockDomain, true);
  assert.equal(config.options.LockDomainList, "example.com\napp.example.com");
  assert.equal(config.options.LockDate, true);
  assert.equal(config.options.LockDateValue, "20260531");
  assert.equal(config.options.LockStartDate, true);
  assert.equal(config.options.LockStartDateValue, "20260501");
  assert.equal(config.options.DebugProtection, true);
  assert.equal(config.options.SelfDefending, true);
  assert.equal(config.options.AntiMonkeyPatching, true);
  assert.equal(config.jsConfuserLockCountermeasures, "panic");

	const disabled = api.createProtectionConfig({
		lock: { antiDebug: 0, integrity: 0, selfDefending: false, tamperProtection: 0 }
	});
	assert.equal(disabled.options.DebugProtection, false);
	assert.equal(disabled.options.SelfDefending, false);
	assert.equal(disabled.options.AntiMonkeyPatching, false);
});

test("JS-Confuser custom string splitting selectors require manual review", () => {
  assert.throws(() => api.translateJsConfuserOptions({ stringSplitting() { return true; } }), /manual migration review/);
});

test("Node API maps first-class runtime-defense aliases", () => {
  const config = api.createProtectionConfig({
    selfDefending: true,
    selfDefendingIntervalSeconds: 45,
    selfHealing: true,
    selfHealingMaxAttempts: 4,
    antiMonkeyPatching: true,
    antiMonkeyPatchingCleanRealm: false,
    antiMonkeyPatchingIncludeGlobals: "crypto.getRandomValues",
    antiMonkeyPatchingExcludeGlobals: "fetch",
    runtimeDefenseAction: "degrade",
    runtimeDefenseCallback: "App.onDefense",
    runtimeDefenseRedirectUrl: "/blocked",
    options: {
      SelfHealingMaxAttempts: 2
    }
  });

  assert.equal(config.options.SelfDefending, true);
  assert.equal(config.options.SelfDefendingIntervalSeconds, 45);
  assert.equal(config.options.SelfHealing, true);
  assert.equal(config.options.SelfHealingMaxAttempts, 2);
  assert.equal(config.options.AntiMonkeyPatching, true);
  assert.equal(config.options.AntiMonkeyPatchingCleanRealm, false);
  assert.equal(config.options.AntiMonkeyPatchingIncludeGlobals, "crypto.getRandomValues");
  assert.equal(config.options.AntiMonkeyPatchingExcludeGlobals, "fetch");
  assert.equal(config.options.RuntimeDefenseAction, "degrade");
  assert.equal(config.options.RuntimeDefenseCallback, "App.onDefense");
  assert.equal(config.options.RuntimeDefenseRedirectUrl, "/blocked");
});

test("runtime-defense interval CLI rejects unsafe scheduler ranges", () => {
  assert.throws(() => cli.parseArgs(["--self-defending-interval-seconds", "0"]), /1 through 86400/);
  assert.throws(() => cli.parseArgs(["--self-defending-interval-seconds", "86401"]), /1 through 86400/);
  assert.throws(() => cli.parseArgs(["--self-defending-interval-seconds", "1.5"]), /1 through 86400/);
});

test("config validation accepts and bounds first-class runtime-defense aliases", () => {
  const valid = cli.validateProtectionConfig({ apiKey: "key", apiPassword: "pwd", input: ".", output: "protected", selfDefending: true, selfDefendingIntervalSeconds: 60, selfHealing: true, selfHealingMaxAttempts: 2, runtimeDefenseAction: "callback", runtimeDefenseCallback: "App.onDefense" });
  assert.equal(valid.checks.some((check) => check.level === "error"), false);
  const invalid = cli.validateProtectionConfig({ selfDefendingIntervalSeconds: 86401 });
  assert.equal(invalid.checks.some((check) => check.level === "error" && /1 through 86400/.test(check.message)), true);
});

test("mergeConfig accepts VM preset aliases from javascript-obfuscator configs", () => {
  const root = makeTempDir();
  const merged = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    optionsPreset: "vm-ultra-high-obfuscation"
  }, {});

  assert.equal(merged.preset, "maximum");
  assert.equal(merged.options.RenameMembers, true);
  assert.equal(merged.options.DeepObfuscate, true);
});

test("mergeConfig uses javascript-obfuscator-style sibling output for direct file input", () => {
  const root = makeTempDir();
  const input = path.join(root, "sample.js");
  fs.writeFileSync(input, "console.log('sample');");

  const directFile = cli.mergeConfig({
    __configDir: root
  }, {
    input: "sample.js"
  });
  assert.equal(directFile.output, path.join(root, "sample-obfuscated.js"));

  const explicitOutput = cli.mergeConfig({
    __configDir: root
  }, {
    input: "sample.js",
    output: "protected.js"
  });
  assert.equal(explicitOutput.output, path.join(root, "protected.js"));

  const configuredOutput = cli.mergeConfig({
    __configDir: root,
    output: "configured.js"
  }, {
    input: "sample.js"
  });
  assert.equal(configuredOutput.output, path.join(root, "configured.js"));
});

test("readConfig loads CommonJS config files and function exports", () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.cjs");
  const oldKey = process.env.JSO_JS_CONFIG_KEY;
  const oldPassword = process.env.JSO_JS_CONFIG_PASSWORD;
  process.env.JSO_JS_CONFIG_KEY = "js-config-key";
  process.env.JSO_JS_CONFIG_PASSWORD = "js-config-password";
  fs.writeFileSync(configPath, `
module.exports = ({ cwd, env }) => ({
  mode: env.JSO_RELEASE_MODE || null,
  apiKey: "$JSO_JS_CONFIG_KEY",
  apiPassword: "$JSO_JS_CONFIG_PASSWORD",
  projectName: cwd ? "js-config" : "missing-cwd",
  input: "dist",
  output: "protected",
  preset: "balanced",
  reservedNames: ["^PublicApi$"],
  options: {
    LockDomain: Boolean(env.JSO_JS_CONFIG_KEY)
  }
});
`, "utf8");

  try {
    process.env.JSO_RELEASE_MODE = "staging";
    const loaded = cli.readConfig(configPath);
    const merged = cli.mergeConfig(loaded, {});
    assert.equal(loaded.__configDir, root);
    assert.equal(loaded.mode, "staging");
    assert.equal(merged.apiKey, "js-config-key");
    assert.equal(merged.apiPassword, "js-config-password");
    assert.equal(merged.projectName, "js-config");
    assert.equal(merged.preset, "balanced");
    assert.equal(merged.input, path.join(root, "dist"));
    assert.equal(merged.output, path.join(root, "protected"));
    assert.equal(merged.options.LockDomain, true);
    assert.equal(merged.options.VariableExclusion, "^PublicApi$");
  } finally {
    delete process.env.JSO_RELEASE_MODE;
    restoreEnv("JSO_JS_CONFIG_KEY", oldKey);
    restoreEnv("JSO_JS_CONFIG_PASSWORD", oldPassword);
  }
});

test("readConfig discovers jso.config.cjs when no JSON config exists", () => {
  const root = makeTempDir();
  const oldCwd = process.cwd();
  fs.writeFileSync(path.join(root, "jso.config.cjs"), `
module.exports = {
  apiKey: "key",
  apiPassword: "pwd",
  input: "dist",
  output: "protected"
};
`, "utf8");

  try {
    process.chdir(root);
    const loaded = cli.readConfig();
    assert.equal(loaded.__configDir, root);
    assert.equal(loaded.input, "dist");
  } finally {
    process.chdir(oldCwd);
  }
});

test("readConfig loads ES module config files and function exports", () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.mjs");
  const oldKey = process.env.JSO_ESM_CONFIG_KEY;
  const oldPassword = process.env.JSO_ESM_CONFIG_PASSWORD;
  process.env.JSO_ESM_CONFIG_KEY = "esm-config-key";
  process.env.JSO_ESM_CONFIG_PASSWORD = "esm-config-password";
  fs.writeFileSync(configPath, `
export default ({ cwd, env, mode }) => ({
  apiKey: "$JSO_ESM_CONFIG_KEY",
  apiPassword: "$JSO_ESM_CONFIG_PASSWORD",
  mode,
  projectName: cwd ? "esm-config" : "missing-cwd",
  input: "dist",
  output: "protected",
  preset: "balanced",
  reservedNames: ["^PublicApi$"],
  options: {
    LockDomain: Boolean(env.JSO_ESM_CONFIG_KEY)
  }
});
`, "utf8");

  try {
    const loaded = cli.readConfig(configPath, { mode: "production" });
    const merged = cli.mergeConfig(loaded, {});
    assert.equal(loaded.__configDir, root);
    assert.equal(loaded.mode, "production");
    assert.equal(merged.apiKey, "esm-config-key");
    assert.equal(merged.apiPassword, "esm-config-password");
    assert.equal(merged.projectName, "esm-config");
    assert.equal(merged.preset, "balanced");
    assert.equal(merged.input, path.join(root, "dist"));
    assert.equal(merged.output, path.join(root, "protected"));
    assert.equal(merged.options.LockDomain, true);
    assert.equal(merged.options.VariableExclusion, "^PublicApi$");
  } finally {
    restoreEnv("JSO_ESM_CONFIG_KEY", oldKey);
    restoreEnv("JSO_ESM_CONFIG_PASSWORD", oldPassword);
  }
});

test("readConfig discovers jso.config.mjs when no JSON or CommonJS config exists", () => {
  const root = makeTempDir();
  const oldCwd = process.cwd();
  fs.writeFileSync(path.join(root, "jso.config.mjs"), `
export default {
  apiKey: "key",
  apiPassword: "pwd",
  input: "dist",
  output: "protected"
};
`, "utf8");

  try {
    process.chdir(root);
    const loaded = cli.readConfig();
    assert.equal(loaded.__configDir, root);
    assert.equal(loaded.input, "dist");
  } finally {
    process.chdir(oldCwd);
  }
});

test("readConfig loads type-module jso.config.js files through the ESM loader", () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.js");
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
    type: "module"
  }, null, 2));
  fs.writeFileSync(configPath, `
export default {
  apiKey: "key",
  apiPassword: "pwd",
  input: "dist",
  output: "protected",
  projectName: "type-module"
};
`, "utf8");

  const loaded = cli.readConfig(configPath);
  const merged = cli.mergeConfig(loaded, {});
  assert.equal(loaded.__configDir, root);
  assert.equal(merged.projectName, "type-module");
  assert.equal(merged.input, path.join(root, "dist"));
});

test("readConfig falls back to NODE_ENV when mode is not passed explicitly", () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.cjs");
  const oldNodeEnv = process.env.NODE_ENV;
  fs.writeFileSync(configPath, `
module.exports = ({ mode }) => ({
  mode,
  input: "dist",
  output: "protected"
});
`, "utf8");

  process.env.NODE_ENV = "qa";
  try {
    const loaded = cli.readConfig(configPath);
    assert.equal(loaded.mode, "qa");
  } finally {
    restoreEnv("NODE_ENV", oldNodeEnv);
  }
});

test("parseOptionOverrides reads booleans numbers nulls and strings", () => {
  assert.deepEqual(cli.parseOptionOverrides([
    "Flag=true",
    "Count=3",
    "Ratio=3.5",
    "None=null",
    "Name=Best"
  ]), {
    Flag: true,
    Count: 3,
    Ratio: 3.5,
    None: null,
    Name: "Best"
  });
});

test("listPresets and listOptions expose documented CLI references", () => {
  const presets = cli.listPresets();
  const options = cli.listOptions();
  const migrationMap = cli.listJavascriptObfuscatorMigrationMap();

  assert.deepEqual(presets.map((preset) => preset.name), ["free", "standard", "balanced", "maximum"]);
  // `free` is the only preset a credential-less run can actually execute: every
  // other transform is plan-gated server-side.
  assert.deepEqual(Object.keys(presets.find((preset) => preset.name === "free").options).sort(), ["EncodeStrings", "IdentityStyle", "ReplaceNames"]);
  assert.equal(presets.find((preset) => preset.name === "balanced").options.DeepObfuscate, true);
  assert.equal(options.some((option) => option.name === "LockDomain" && option.category === "locks"), true);
  assert.equal(options.some((option) => option.name === "LockBrowser" && option.category === "locks"), true);
  assert.equal(options.some((option) => option.name === "LockBrowserList" && option.description.includes("chrome")), true);
  assert.equal(options.some((option) => option.name === "LockOS" && option.category === "locks"), true);
  assert.equal(options.some((option) => option.name === "LockOSList" && option.description.includes("windows")), true);
  assert.equal(options.some((option) => option.name === "CompressionRatio" && option.values.includes("Best")), true);
  assert.equal(options.some((option) => option.name === "DebugProtectionIntervalMilliseconds" && option.category === "runtime-defense"), true);
  assert.equal(options.some((option) => option.name === "TargetVersion" && option.category === "output" && option.values.includes("modern")), true);
  assert.equal(options.some((option) => option.name === "DownlevelIteration" && option.category === "output" && option.description.includes("for-of")), true);
  assert.equal(migrationMap.summary.mapped, migrationMap.mappings.length);
  assert.equal(migrationMap.summary.totalKnown, migrationMap.mappings.length + migrationMap.review.length);
  assert.equal(migrationMap.summary.approximate > 0, true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "stringArray" && item.target.includes("MoveStrings")), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "domainLock" && item.target.includes("LockDomainList")), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "ignoreImports" && item.target.includes("ignoreImports")), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "selfDefending" && item.target.includes("SelfDefending")), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "debugProtection" && item.target.includes("DebugProtection")), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "debugProtectionInterval" && item.target.includes("DebugProtectionIntervalMilliseconds") && item.confidence === "direct"), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "disableConsoleOutput" && item.target.includes("DisableConsoleOutput") && item.confidence === "direct"), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "domainLockRedirectUrl" && item.target.includes("LockDomainRedirectUrl") && item.confidence === "direct"), true);
  assert.equal(migrationMap.mappings.some((item) => item.source === "seed" && item.target.includes("Seed") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "reservedStrings" && item.target.includes("ReservedStrings") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "forceTransformStrings" && item.target.includes("ForceTransformStrings") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "splitStrings" && item.target.includes("SplitStrings") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "splitStringsChunkLength" && item.target.includes("SplitStringsChunkLength") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayIndexShift" && item.target.includes("StringArrayIndexShift") && item.confidence === "approximate"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayShuffle" && item.target.includes("StringArrayShuffle") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayRotate" && item.target.includes("StringArrayRotate") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayIndexesType" && item.target.includes("StringArrayIndexesType") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayThreshold" && item.target.includes("StringArrayThreshold") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayCallsTransform" && item.target.includes("StringArrayCallsTransform") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayCallsTransformThreshold" && item.target.includes("StringArrayCallsTransformThreshold") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayWrappersCount" && item.target.includes("StringArrayWrappersCount") && item.confidence === "approximate"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayWrappersChainedCalls" && item.target.includes("StringArrayWrappersChainedCalls") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayWrappersParametersMaxCount" && item.target.includes("StringArrayWrappersParametersMaxCount") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "stringArrayWrappersType" && item.target.includes("StringArrayWrappersType") && item.confidence === "direct"), true);
	assert.equal(migrationMap.mappings.some((item) => item.source === "transformObjectKeys" && item.target.includes("TransformObjectKeys") && item.confidence === "approximate"), true);
	assert.equal(migrationMap.review.some((item) => item.option === "seed"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "reservedStrings"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "forceTransformStrings"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "splitStrings"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "splitStringsChunkLength"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayIndexShift"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayShuffle"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayRotate"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayIndexesType"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayCallsTransform"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayCallsTransformThreshold"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayWrappersCount"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayWrappersChainedCalls"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayWrappersParametersMaxCount"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "stringArrayWrappersType"), false);
	assert.equal(migrationMap.review.some((item) => item.option === "transformObjectKeys"), false);
  assert.equal(migrationMap.review.some((item) => item.option === "selfDefending"), false);
  assert.equal(migrationMap.review.some((item) => item.option === "identifiersDictionary"), true);
  assert.equal(migrationMap.review.some((item) => item.option === "identifiersPrefix"), true);
  assert.equal(migrationMap.review.some((item) => item.option === "identifierNamesCachePath"), true);
  assert.equal(migrationMap.review.some((item) => item.option === "sourceMapSourcesMode"), true);
  assert.equal(migrationMap.review.some((item) => item.option === "strictMode"), true);
  assert.equal(migrationMap.review.some((item) => item.option === "simplify"), true);
  assert.equal(migrationMap.review.some((item) => item.option === "ignoreImports"), false);
});

test("Next.js wrapper adds the webpack plugin for production client bundles by default", () => {
  const userPlugin = { name: "existing-plugin" };
  const wrapped = withJsoProtector({
    webpack(config) {
      return {
        ...config,
        plugins: [...config.plugins, userPlugin]
      };
    }
  }, {
    apiKey: "key",
    apiPassword: "pwd",
    manifest: ".next/jso-manifest.json"
  });

  const clientConfig = wrapped.webpack({ plugins: [] }, { dev: false, isServer: false });
  assert.equal(clientConfig.plugins.includes(userPlugin), true);
  assert.equal(clientConfig.plugins.some((plugin) => plugin instanceof WebpackProtector), true);

  const serverConfig = wrapped.webpack({ plugins: [] }, { dev: false, isServer: true });
  assert.equal(serverConfig.plugins.some((plugin) => plugin instanceof WebpackProtector), false);

  const devConfig = wrapped.webpack({ plugins: [] }, { dev: true, isServer: false });
  assert.equal(devConfig.plugins.some((plugin) => plugin instanceof WebpackProtector), false);
});

test("React Native alias re-exports the Metro integration", () => {
  assert.equal(reactNativeProtector, createMetroSerializer);
  assert.equal(reactNativeProtector.createMetroSerializer, createMetroSerializer);
  assert.equal(typeof reactNativeProtector.withJsoProtectorMetro, "function");
});

test("post-build helpers expose tuned defaults for Parcel, Bun, and Turbopack", () => {
  const parcelConfig = protectParcelBuild.createParcelProtectionConfig({
    apiKey: "key",
    apiPassword: "pwd"
  });
  const bunConfig = protectBunBuild.createBunProtectionConfig({
    apiKey: "key",
    apiPassword: "pwd"
  });
  const turbopackConfig = protectTurbopackBuild.createTurbopackProtectionConfig({
    apiKey: "key",
    apiPassword: "pwd"
  });

  assert.equal(path.basename(parcelConfig.input), "dist");
  assert.equal(path.basename(parcelConfig.output), "dist-protected");
  assert.equal(path.basename(parcelConfig.manifest), "jso-manifest.json");
  assert.equal(path.basename(path.dirname(parcelConfig.manifest)), "dist-protected");
  assert.equal(parcelConfig.exclude.includes("**/vendor/**"), true);
  assert.equal(bunConfig.maxOutputBytes, 250000);
  assert.equal(path.basename(bunConfig.manifest), "jso-manifest.json");
  assert.equal(path.basename(path.dirname(bunConfig.manifest)), "dist-protected");
  assert.equal(turbopackConfig.input.endsWith(path.join(".next", "static")), true);
  assert.deepEqual(turbopackConfig.include, ["chunks/*.js", "chunks/**/*.js"]);
  assert.equal(turbopackConfig.exclude.includes("**/webpack-*.js"), true);
});

test("Next.js wrapper supports async config functions and target overrides", async () => {
  const wrappedFactory = withJsoProtector(async () => ({
    poweredByHeader: false
  }), {
    apiKey: "key",
    apiPassword: "pwd",
    target: "both",
    applyInDevelopment: true
  });

  const wrapped = await wrappedFactory();
  const clientConfig = wrapped.webpack({ plugins: [] }, { dev: true, isServer: false });
  const serverConfig = wrapped.webpack({ plugins: [] }, { dev: true, isServer: true });

  assert.equal(clientConfig.plugins.some((plugin) => plugin instanceof WebpackProtector), true);
  assert.equal(serverConfig.plugins.some((plugin) => plugin instanceof WebpackProtector), true);
  assert.equal(wrapped.poweredByHeader, false);
});

test("getRedactedConfig hides API credentials", () => {
  const root = makeTempDir();
  const config = cli.mergeConfig({
    __configDir: root,
    mode: "production",
    apiKey: "secret-key",
    apiPassword: "secret-password",
    input: "dist",
    output: "protected",
    parseHtml: true,
    honorConditionalComments: true,
    ignoreImports: true,
    options: { LockDomain: true }
  }, {});
  const redacted = cli.getRedactedConfig(config);

  assert.equal(redacted.mode, "production");
  assert.equal(redacted.apiKey, "[set]");
  assert.equal(redacted.apiPassword, "[set]");
  assert.equal(JSON.stringify(redacted).includes("secret"), false);
  assert.equal(redacted.parseHtml, true);
  assert.equal(redacted.honorConditionalComments, true);
  assert.equal(redacted.ignoreImports, true);
  assert.equal(redacted.options.LockDomain, true);
});

test("buildStdinManifest records sizes and hashes", () => {
  const root = makeTempDir();
  const config = cli.mergeConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected"
  }, {});
  const manifest = cli.buildStdinManifest(config, "pipe.js", "console.log('in');", "console.log('out');", "stdout");

  assert.equal(manifest.format, "jso-protector-manifest");
  assert.equal(manifest.files[0].fileName, "pipe.js");
  assert.equal(manifest.files[0].sourceBytes, Buffer.byteLength("console.log('in');"));
  assert.equal(manifest.files[0].outputPath, "stdout");
  assert.equal(manifest.files[0].sourceSha256, cli.sha256("console.log('in');"));
});

test("stripSourceMapComments removes stale sourceMappingURL directives", () => {
  const code = [
    "console.log('one');",
    "//# sourceMappingURL=app.js.map",
    "console.log('two');",
    "/*# sourceMappingURL=inline.js.map */"
  ].join("\n");

  assert.equal(cli.stripSourceMapComments(code).includes("sourceMappingURL"), false);
  assert.equal(cli.finalizeProtectedCode(code, { removeSourceMaps: true }).includes("sourceMappingURL"), false);
  assert.equal(cli.finalizeProtectedCode(code, { removeSourceMaps: false }).includes("sourceMappingURL"), true);
});

test("verifyManifestOutputs confirms manifest output at recorded paths", () => {
  const root = makeTempDir();
  const outputDir = path.join(root, "dist-protected");
  fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, "app.js");
  const assetPath = path.join(outputDir, "index.html");
  fs.writeFileSync(filePath, "console.log('protected');", "utf8");
  fs.writeFileSync(assetPath, "<script src=\"app.js\"></script>", "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "manifest-verify",
    preset: "balanced",
    options: ["EncodeStrings"],
    processing: { apiItems: 1, transformedFiles: [] },
    files: [{
      fileName: "app.js",
      sourcePath: path.join(root, "dist", "app.js"),
      outputPath: filePath,
      sourceBytes: 23,
      outputBytes: Buffer.byteLength("console.log('protected');"),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256("console.log('protected');")
    }],
    assets: [{
      fileName: "index.html",
      sourcePath: path.join(root, "dist", "index.html"),
      outputPath: assetPath,
      bytes: Buffer.byteLength("<script src=\"app.js\"></script>"),
      sha256: cli.sha256("<script src=\"app.js\"></script>")
    }]
  }, null, 2), "utf8");

  const report = cli.verifyManifestOutputs(manifestPath);
  assert.equal(report.ok, true);
  assert.equal(report.summary.ok, 2);
  assert.equal(report.summary.missing, 0);
  assert.equal(report.summary.mismatched, 0);
  assert.equal(report.files[0].path, filePath);
});

test("verifyManifestOutputs supports relocated artifact roots", () => {
  const root = makeTempDir();
  const artifactRoot = path.join(root, "artifact");
  fs.mkdirSync(artifactRoot, { recursive: true });
  const filePath = path.join(artifactRoot, "assets", "app.js");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, "console.log('protected');", "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "manifest-relocated",
    preset: "balanced",
    options: [],
    files: [{
      fileName: "assets/app.js",
      sourcePath: path.join(root, "dist", "assets", "app.js"),
      outputPath: path.join(root, "old-output", "assets", "app.js"),
      sourceBytes: 23,
      outputBytes: Buffer.byteLength("console.log('protected');"),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256("console.log('protected');")
    }],
    assets: []
  }, null, 2), "utf8");

  const report = cli.verifyManifestOutputs(manifestPath, { verifyRoot: artifactRoot });
  assert.equal(report.ok, true);
  assert.equal(report.verifyRoot, artifactRoot);
  assert.equal(report.files[0].path, filePath);
});

test("verifyManifestOutputs reports missing and mismatched entries", () => {
  const root = makeTempDir();
  const outputDir = path.join(root, "dist-protected");
  fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, "app.js");
  fs.writeFileSync(filePath, "console.log('tamperedd');", "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "manifest-fail",
    preset: "balanced",
    options: [],
    files: [{
      fileName: "app.js",
      sourcePath: path.join(root, "dist", "app.js"),
      outputPath: filePath,
      sourceBytes: 23,
      outputBytes: Buffer.byteLength("console.log('protected');"),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256("console.log('protected');")
    }],
    assets: [{
      fileName: "index.html",
      sourcePath: path.join(root, "dist", "index.html"),
      outputPath: path.join(outputDir, "index.html"),
      bytes: 10,
      sha256: cli.sha256("0123456789")
    }]
  }, null, 2), "utf8");

  const report = cli.verifyManifestOutputs(manifestPath);
  assert.equal(report.ok, false);
  assert.equal(report.summary.missing, 1);
  assert.equal(report.summary.mismatched, 1);
  assert.equal(report.files[0].reason, "sha256-mismatch");
  assert.equal(report.assets[0].reason, "missing");
});

test("verifyManifestOutputs can audit source-map leaks", () => {
  const root = makeTempDir();
  const outputDir = path.join(root, "dist-protected");
  fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, "app.js");
  const mapPath = path.join(outputDir, "app.js.map");
  const protectedCode = "console.log('protected');\n//# sourceMappingURL=app.js.map\n";
  fs.writeFileSync(filePath, protectedCode, "utf8");
  fs.writeFileSync(mapPath, "{\"version\":3}", "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "manifest-source-map-audit",
    preset: "balanced",
    options: [],
    files: [{
      fileName: "app.js",
      sourcePath: path.join(root, "dist", "app.js"),
      outputPath: filePath,
      sourceBytes: 23,
      outputBytes: Buffer.byteLength(protectedCode),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256(protectedCode)
    }],
    assets: [{
      fileName: "app.js.map",
      sourcePath: path.join(root, "dist", "app.js.map"),
      outputPath: mapPath,
      bytes: Buffer.byteLength("{\"version\":3}"),
      sha256: cli.sha256("{\"version\":3}")
    }]
  }, null, 2), "utf8");

  const report = cli.verifyManifestOutputs(manifestPath, { auditSourceMaps: true });
  assert.equal(report.ok, false);
  assert.equal(report.summary.missing, 0);
  assert.equal(report.summary.mismatched, 0);
  assert.equal(report.summary.sourceMapLeaks, 2);
  assert.equal(report.sourceMapLeaks.some((leak) => leak.reason === "sourceMappingURL"), true);
  assert.equal(report.sourceMapLeaks.some((leak) => leak.reason === "map-file"), true);
});

test("buildSourceMapEvidenceReport summarizes clean source-free release evidence", () => {
  const root = makeTempDir();
  const outputDir = path.join(root, "dist-protected");
  fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, "app.js");
  const protectedCode = "console.log('protected');\n";
  fs.writeFileSync(filePath, protectedCode, "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "source-map-clean",
    preset: "maximum",
    options: [],
    files: [{
      fileName: "app.js",
      sourcePath: path.join(root, "dist", "app.js"),
      outputPath: filePath,
      sourceBytes: 23,
      outputBytes: Buffer.byteLength(protectedCode),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256(protectedCode)
    }],
    assets: []
  }, null, 2), "utf8");

  const report = cli.buildSourceMapEvidenceReport(manifestPath);
  assert.equal(report.format, "jso-protector-source-map-evidence");
  assert.equal(report.ok, true);
  assert.equal(report.summary.sourceMapLeaks, 0);
  assert.equal(report.reviewDecision.decision, "ready");
  assert.equal(report.sourceMapPolicy.reviewerBoundary.includes("source-free"), true);
  assert.equal(report.sourceBoundary.doNotInclude.includes("raw .map files"), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("source-map contents"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("original source paths from source maps"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Secure debugging exception"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Clean source-map handoff"), true);
  assert.equal(report.checks.every((check) => check.ok), true);
});

test("buildSourceMapEvidenceReport blocks leaking maps without exposing local paths in findings", () => {
  const root = makeTempDir();
  const outputDir = path.join(root, "dist-protected");
  fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, "app.js");
  const mapPath = path.join(outputDir, "app.js.map");
  const protectedCode = "console.log('protected');\n//# sourceMappingURL=app.js.map\n";
  fs.writeFileSync(filePath, protectedCode, "utf8");
  fs.writeFileSync(mapPath, "{\"version\":3}", "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "source-map-leak",
    preset: "balanced",
    options: [],
    files: [{
      fileName: "app.js",
      sourcePath: path.join(root, "dist", "app.js"),
      outputPath: filePath,
      sourceBytes: 23,
      outputBytes: Buffer.byteLength(protectedCode),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256(protectedCode)
    }],
    assets: [{
      fileName: "app.js.map",
      sourcePath: path.join(root, "dist", "app.js.map"),
      outputPath: mapPath,
      bytes: Buffer.byteLength("{\"version\":3}"),
      sha256: cli.sha256("{\"version\":3}")
    }]
  }, null, 2), "utf8");

  const report = cli.buildSourceMapEvidenceReport(manifestPath);
  assert.equal(report.ok, false);
  assert.equal(report.reviewDecision.decision, "blocked");
  assert.equal(report.summary.sourceMapLeaks, 2);
  assert.equal(report.summary.mapFiles, 1);
  assert.equal(report.summary.sourceMappingUrlComments, 1);
  assert.equal(report.sourceMapLeaks.every((leak) => !Object.prototype.hasOwnProperty.call(leak, "path")), true);
  assert.equal(report.sourceMapLeaks.some((leak) => leak.reason === "map-file"), true);
  assert.equal(report.sourceMapLeaks.some((leak) => leak.reason === "sourceMappingURL"), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Source-map leak cleanup"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Bundler cleanup order"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Release block"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw source-map sources arrays"), true);
});

test("CLI --source-map-evidence writes Markdown and supports JSON", async () => {
  const root = makeTempDir();
  const outputDir = path.join(root, "dist-protected");
  fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, "app.js");
  const protectedCode = "console.log('protected');\n";
  fs.writeFileSync(filePath, protectedCode, "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  const outputPath = path.join(root, "source-map-evidence.md");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "source-map-cli",
    preset: "maximum",
    options: [],
    files: [{
      fileName: "app.js",
      sourcePath: path.join(root, "dist", "app.js"),
      outputPath: filePath,
      sourceBytes: 23,
      outputBytes: Buffer.byteLength(protectedCode),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256(protectedCode)
    }],
    assets: []
  }, null, 2), "utf8");

  const written = await runCli([
    "--source-map-evidence", manifestPath,
    "--source-map-evidence-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");
  assert.equal(written.stdout, "");
  assert.equal(written.stderr.includes("Source map evidence report written:"), true);
  assert.equal(markdown.includes("# JSO Source Map Evidence"), true);
  assert.equal(markdown.includes("Status: PASS"), true);
  assert.equal(markdown.includes("Review decision: Ready"), true);
  assert.equal(markdown.includes("## Source Map Review Assistant"), true);
  assert.equal(markdown.includes("BYO AI key"), true);
  assert.equal(markdown.includes("raw .map files"), true);
  assert.equal(markdown.includes("Clean source-map handoff"), true);

  const json = JSON.parse((await runCli(["--source-map-evidence", manifestPath, "--json"], "")).stdout);
  assert.equal(json.format, "jso-protector-source-map-evidence");
  assert.equal(json.ok, true);
  assert.equal(json.projectName, "source-map-cli");
  assert.equal(json.summary.sourceMapLeaks, 0);
  assert.equal(json.reviewAssistant.sourceFree, true);
  assert.equal(json.reviewAssistant.questions.some((item) => item.topic === "Clean source-map handoff"), true);
});

test("buildDeploymentHygieneEvidenceReport summarizes clean source-free archive evidence", () => {
  const root = makeTempDir();
  const reportPath = writeArchiveHygieneReport(root);

  const report = cli.buildDeploymentHygieneEvidenceReport(reportPath, { generatedAt: "2026-06-08T20:00:00Z" });
  const json = JSON.stringify(report);

  assert.equal(report.format, "jso-protector-deployment-hygiene-evidence");
  assert.equal(report.ok, true);
  assert.equal(report.summary.archives, 2);
  assert.equal(report.summary.missingRequiredEntries, 0);
  assert.equal(report.summary.blockedEntries, 0);
  assert.equal(report.summary.containsWebConfig, false);
  assert.equal(report.reviewDecision.decision, "ready");
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("Web.config contents"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Config exclusion"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Clean archive handoff"), true);
  assert.equal(report.archives.every((archive) => !archive.zip.includes("secret")), true);
  assert.equal(json.includes("D:\\secret\\workspace"), false);
  assert.equal(json.includes("super-secret"), false);

  const markdown = cli.renderDeploymentHygieneEvidenceText(report);
  assert.equal(markdown.includes("# Deployment Hygiene Evidence"), true);
  assert.equal(markdown.includes("## Deployment Hygiene Review Assistant"), true);
  assert.equal(markdown.includes("Web.config contents"), true);
  assert.equal(markdown.includes("jso-website-updated-after-2026-05-28.zip"), true);
  assert.equal(markdown.includes("D:\\secret\\workspace"), false);
});

test("buildDeploymentHygieneEvidenceReport blocks dirty archive hygiene evidence", () => {
  const root = makeTempDir();
  const reportPath = writeArchiveHygieneReport(root, {
    ok: false,
    archives: [{
      zip: "D:\\secret\\workspace\\jso-updated-after-2026-05-28.zip",
      entries: 12,
      size: 2048,
      missingRequiredEntries: ["2026/JSO-Website/Docs/DeploymentHygiene.aspx"],
      blockedEntries: ["2026/JSO-Website/Web.config"],
      contains: {
        webConfig: true,
        generatedTemp: false,
        nodeModules: false,
        buildOutput: true,
        downloadBinaries: false
      }
    }]
  });

  const report = cli.buildDeploymentHygieneEvidenceReport(reportPath);
  assert.equal(report.ok, false);
  assert.equal(report.reviewDecision.decision, "blocked");
  assert.equal(report.summary.missingRequiredEntries, 1);
  assert.equal(report.summary.blockedEntries, 1);
  assert.equal(report.summary.containsWebConfig, true);
  assert.equal(report.summary.containsBuildOutput, true);
  assert.equal(report.checks.some((check) => check.name === "blocked-entries" && !check.ok), true);
  assert.equal(report.checks.some((check) => check.name === "blocked-category-booleans" && !check.ok), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Blocked deployment file"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Credential rotation"), true);
  assert.equal(report.recommendations.some((item) => item.includes("Rotate credentials")), true);
});

test("CLI --deployment-hygiene-evidence writes Markdown and supports JSON", async () => {
  const root = makeTempDir();
  const reportPath = writeArchiveHygieneReport(root);
  const outputPath = path.join(root, "deployment-hygiene.md");

  const written = await runCli([
    "--deployment-hygiene-evidence", reportPath,
    "--deployment-hygiene-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");
  assert.equal(written.stdout, "");
  assert.equal(written.stderr.includes("Deployment hygiene evidence report written:"), true);
  assert.equal(markdown.includes("# Deployment Hygiene Evidence"), true);
  assert.equal(markdown.includes("Status: PASS"), true);
  assert.equal(markdown.includes("Review decision: Ready"), true);

  const json = JSON.parse((await runCli(["--deployment-hygiene-evidence", reportPath, "--json"], "")).stdout);
  assert.equal(json.format, "jso-protector-deployment-hygiene-evidence");
  assert.equal(json.ok, true);
  assert.equal(json.summary.archives, 2);
  assert.equal(json.reviewAssistant.sourceFree, true);
});

test("CLI --deployment-hygiene-evidence writes failed packet before failing dirty evidence", async () => {
  const root = makeTempDir();
  const reportPath = writeArchiveHygieneReport(root, {
    ok: false,
    archives: [{
      zip: "D:\\secret\\workspace\\jso-updated-after-2026-05-28.zip",
      entries: 1,
      size: 512,
      missingRequiredEntries: ["COMPETITIVE-GAPS-2026-06.md"],
      blockedEntries: ["2026/JSO-Website/Web.config"],
      contains: {
        webConfig: true,
        generatedTemp: true,
        nodeModules: false,
        buildOutput: false,
        downloadBinaries: false
      }
    }]
  });
  const outputPath = path.join(root, "deployment-hygiene.json");

  await assert.rejects(
    () => runCli([
      "--deployment-hygiene-evidence", reportPath,
      "--deployment-hygiene-output", outputPath,
      "--json"
    ], ""),
    /deployment hygiene evidence needs review/
  );
  const written = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  assert.equal(written.ok, false);
  assert.equal(written.reviewDecision.decision, "blocked");
  assert.equal(written.summary.containsWebConfig, true);
  assert.equal(written.reviewAssistant.questions.some((item) => item.topic === "Credential rotation"), true);
});

test("buildMigrationReviewReport summarizes all review-only migration fields without leaking values", () => {
  const report = cli.buildMigrationReviewReport({
    sourceMap: true,
    sourceMapBaseUrl: "https://maps.secret.example/assets",
    identifierNamesCache: { SensitiveInternalName: "x1" },
    identifierNamesCachePath: ".cache-secret.json",
    identifiersDictionary: ["SensitivePublicName"],
    identifiersPrefix: "corp_",
    reservedStrings: ["^LicenseKey"],
    strictMode: false,
    stringArrayIndexShift: true,
    stringArrayShuffle: true,
    selfDefending: true,
    debugProtection: true,
    domainLockRedirectUrl: "https://secret.example/blocked?tenant=acme",
    jsConfuserLockCountermeasures: "panic",
    report: "dist-protected/jso-report.json",
    manifest: "dist-protected/jso-manifest.json"
  }, {
    config: "jso.config.json",
    compatibilityWarnings: [
      "--self-defending was accepted for migration compatibility but has no direct hosted API mapping; review output before release."
    ]
  });

  const json = JSON.stringify(report);
  assert.equal(report.format, "jso-protector-migration-review");
  assert.equal(report.ok, true);
  assert.equal(report.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(report.summary.reviewOnlyFields >= 8, true);
  assert.equal(report.summary.limitationGroups, 4);
  assert.equal(report.summary.cliWarnings, 1);
  assert.equal(report.summary.sourceMapFields >= 2, true);
  assert.equal(report.summary.identifierFields, 4);
  assert.equal(report.summary.runtimeFields >= 1, true);
  assert.equal(report.reviewFields.some((field) => field.field === "seed"), false);
  assert.equal(report.reviewFields.some((field) => field.field === "identifierNamesCache" && field.keyCount === 1), true);
  assert.equal(report.reviewEvidence.some((item) => item.id === "specialized-review-routing" && item.status === "needs-review"), true);
  assert.equal(report.reviewEvidence.some((item) => item.id === "source-free-release-metadata" && item.status === "evidenced"), true);
  assert.equal(report.followUpCommands.some((item) => item.label === "source-map-evidence"), true);
  assert.equal(report.followUpCommands.some((item) => item.label === "identifier-cache-review"), true);
  assert.equal(report.followUpCommands.some((item) => item.label === "runtime-defense-review"), true);
  assert.equal(report.followUpCommands.some((item) => item.label === "runtime-compatibility-scan" && item.sourceFree === false), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.title, "Migration Review Assistant");
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw config files"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("API credentials"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Manual review tracks"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Source-map policy"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Identifier-cache replacement"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Runtime-defense behavior"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Source-reading command boundary"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Protected-build smoke"), true);
  assert.equal(json.includes("maps.secret.example"), false);
  assert.equal(json.includes("SensitiveInternalName"), false);
  assert.equal(json.includes("SensitivePublicName"), false);
  assert.equal(json.includes(".cache-secret.json"), false);
  assert.equal(json.includes("corp_"), false);
  assert.equal(json.includes("LicenseKey"), false);
  assert.equal(json.includes("42-secret"), false);
  assert.equal(json.includes("secret.example"), false);
  assert.equal(json.includes("tenant=acme"), false);
  assert.equal(json.includes("panic"), false);

  const markdown = cli.renderMigrationReviewText(report);
  assert.equal(markdown.includes("# Migration Review"), true);
  assert.equal(markdown.includes("## Migration Review Assistant"), true);
  assert.equal(markdown.includes("BYO AI key"), true);
  assert.equal(markdown.includes("Manual review tracks"), true);
  assert.equal(markdown.includes("Ready for manual review"), true);
  assert.equal(markdown.includes("identifierNamesCache"), true);
  assert.equal(markdown.includes("seed"), true);
  assert.equal(markdown.includes("SensitivePublicName"), false);
  assert.equal(markdown.includes("secret.example"), false);
});

test("CLI --migration-review writes Markdown and supports JSON", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  const outputPath = path.join(root, "migration-review.md");
  fs.writeFileSync(configPath, JSON.stringify({
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    sourceMap: true,
    identifierNamesCachePath: ".cache-secret.json",
    identifiersDictionary: ["SensitivePublicName"],
    identifiersPrefix: "corp_",
    reservedStrings: ["^LicenseKey"],
    seed: "42-secret",
    selfDefending: true,
    domainLockRedirectUrl: "https://secret.example/blocked?tenant=acme",
    jsConfuserLockCountermeasures: "panic"
  }), "utf8");

  const written = await runCliInCwd(root, [
    "--config", configPath,
    "--migration-review",
    "--migration-review-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");
  assert.equal(written.stdout, "");
  assert.equal(written.stderr.includes("Migration review report written:"), true);
  assert.equal(markdown.includes("# Migration Review"), true);
  assert.equal(markdown.includes("## Migration Review Assistant"), true);
  assert.equal(markdown.includes("Migration Review Assistant"), true);
  assert.equal(markdown.includes("Release metadata"), true);
  assert.equal(markdown.includes("identifierNamesCachePath"), true);
  assert.equal(markdown.includes("source-map-evidence"), true);
  assert.equal(markdown.includes(".cache-secret.json"), false);
  assert.equal(markdown.includes("SensitivePublicName"), false);
  assert.equal(markdown.includes("corp_"), false);
  assert.equal(markdown.includes("LicenseKey"), false);
  assert.equal(markdown.includes("42-secret"), false);
  assert.equal(markdown.includes("secret.example"), false);
  assert.equal(markdown.includes("panic"), false);

  const json = JSON.parse((await runCliInCwd(root, [
    "--config", configPath,
    "--migration-review",
    "--json"
  ], "")).stdout);
  const jsonText = JSON.stringify(json);
  assert.equal(json.format, "jso-protector-migration-review");
  assert.equal(json.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(json.reviewAssistant.sourceFree, true);
  assert.equal(json.reviewAssistant.questions.some((item) => item.topic === "Release metadata"), true);
  assert.equal(json.reviewAssistant.doNotInclude.includes("raw config files"), true);
  assert.equal(json.followUpCommands.some((item) => item.label === "identifier-cache-review"), true);
  assert.equal(json.followUpCommands.some((item) => item.label === "runtime-defense-review"), true);
  assert.equal(jsonText.includes(".cache-secret.json"), false);
  assert.equal(jsonText.includes("SensitivePublicName"), false);
  assert.equal(jsonText.includes("corp_"), false);
  assert.equal(jsonText.includes("LicenseKey"), false);
  assert.equal(jsonText.includes("42-secret"), false);
  assert.equal(jsonText.includes("secret.example"), false);
  assert.equal(jsonText.includes("panic"), false);
});

test("buildIdentifierCacheReviewReport summarizes cache replacement review without leaking values", () => {
  const report = cli.buildIdentifierCacheReviewReport({
    identifierNamesCache: { SensitiveInternalName: "x1" },
    identifierNamesCachePath: ".cache-secret.json",
    identifiersDictionary: ["SensitivePublicName"],
    identifiersPrefix: "corp_",
    reservedNames: ["^KeepMe$"],
    report: "dist-protected/jso-report.json",
    manifest: "dist-protected/jso-manifest.json"
  }, {
    config: "jso.config.json"
  });

  const json = JSON.stringify(report);
  assert.equal(report.format, "jso-protector-identifier-cache-review");
  assert.equal(report.ok, true);
  assert.equal(report.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(report.summary.identifierCacheFields, 2);
  assert.equal(report.summary.customDictionaryFields, 2);
  assert.equal(report.summary.reservedNameRules, 1);
  assert.equal(report.requestedFields.some((field) => field.field === "identifierNamesCache" && field.entryCount === 1), true);
  assert.equal(report.requestedFields.some((field) => field.field === "identifiersDictionary" && field.entryCount === 1), true);
  assert.equal(report.replacementEvidence.some((item) => item.id === "reserved-name-review" && item.status === "evidenced"), true);
  assert.equal(report.replacementEvidence.some((item) => item.id === "saved-api-report" && item.status === "evidenced"), true);
  assert.equal(report.replacementEvidence.some((item) => item.id === "release-manifest" && item.status === "evidenced"), true);
  assert.equal(report.replacementEvidence.some((item) => item.id === "protected-build-smoke" && item.status === "needs-review"), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.title, "Identifier Cache Review Assistant");
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("identifierNamesCache contents"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw config files"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Deterministic cache assumption"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Custom dictionary replacement"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Reserved-name coverage"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Protected-build smoke"), true);
  assert.equal(json.includes("SensitiveInternalName"), false);
  assert.equal(json.includes("SensitivePublicName"), false);
  assert.equal(json.includes(".cache-secret.json"), false);
  assert.equal(json.includes("corp_"), false);
  assert.equal(json.includes("KeepMe"), false);

  const markdown = cli.renderIdentifierCacheReviewText(report);
  assert.equal(markdown.includes("# Identifier Cache Replacement Review"), true);
  assert.equal(markdown.includes("## Identifier Cache Review Assistant"), true);
  assert.equal(markdown.includes("BYO AI key"), true);
  assert.equal(markdown.includes("Deterministic cache assumption"), true);
  assert.equal(markdown.includes("Ready for manual review"), true);
  assert.equal(markdown.includes("identifierNamesCache"), true);
  assert.equal(markdown.includes("SensitivePublicName"), false);
});

test("CLI --identifier-cache-review writes Markdown and supports JSON", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  const outputPath = path.join(root, "identifier-cache-review.md");
  fs.writeFileSync(configPath, JSON.stringify({
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    identifierNamesCachePath: ".cache-secret.json",
    identifiersDictionary: ["SensitivePublicName"],
    identifiersPrefix: "corp_",
    reservedNames: ["^KeepMe$"]
  }), "utf8");

  const written = await runCliInCwd(root, [
    "--config", configPath,
    "--identifier-cache-review",
    "--identifier-cache-review-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");
  assert.equal(written.stdout, "");
  assert.equal(written.stderr.includes("Identifier cache review report written:"), true);
  assert.equal(markdown.includes("# Identifier Cache Replacement Review"), true);
  assert.equal(markdown.includes("## Identifier Cache Review Assistant"), true);
  assert.equal(markdown.includes("Release metadata"), true);
  assert.equal(markdown.includes("identifierNamesCachePath"), true);
  assert.equal(markdown.includes(".cache-secret.json"), false);
  assert.equal(markdown.includes("SensitivePublicName"), false);
  assert.equal(markdown.includes("corp_"), false);
  assert.equal(markdown.includes("KeepMe"), false);

  const json = JSON.parse((await runCliInCwd(root, [
    "--config", configPath,
    "--identifier-cache-review",
    "--json"
  ], "")).stdout);
  const jsonText = JSON.stringify(json);
  assert.equal(json.format, "jso-protector-identifier-cache-review");
  assert.equal(json.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(json.reviewAssistant.sourceFree, true);
  assert.equal(json.reviewAssistant.questions.some((item) => item.topic === "Release metadata"), true);
  assert.equal(json.reviewAssistant.doNotInclude.includes("raw config files"), true);
  assert.equal(jsonText.includes(".cache-secret.json"), false);
  assert.equal(jsonText.includes("SensitivePublicName"), false);
  assert.equal(jsonText.includes("corp_"), false);
  assert.equal(jsonText.includes("KeepMe"), false);
});

test("buildRuntimeDefenseReviewReport summarizes runtime migration review without leaking values", () => {
  const report = cli.buildRuntimeDefenseReviewReport({
    selfDefending: true,
    debugProtection: true,
    debugProtectionInterval: 4000,
    domainLockRedirectUrl: "https://secret.example/blocked?tenant=acme",
    jsConfuserLockStartDate: "20260501",
    jsConfuserLockCountermeasures: "panic",
    options: {
      RuntimeDefenseBeaconUrl: "https://beacon.secret.example/runtime?tenant=acme",
      LockDomainList: "secret.example\napp.secret.example",
      LockDateValue: "20261231"
    },
    countermeasures: {
      onTamper: ["redirect"],
      redirectUrl: "https://secret.example/incident"
    },
    report: "dist-protected/jso-report.json",
    manifest: "dist-protected/jso-manifest.json"
  }, {
    config: "jso.config.json"
  });

  const json = JSON.stringify(report);
  assert.equal(report.format, "jso-protector-runtime-defense-review");
  assert.equal(report.ok, true);
  assert.equal(report.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(report.summary.runtimeReviewFields, 1);
  assert.equal(report.summary.runtimeBeaconConfigured, true);
  assert.equal(report.summary.countermeasurePolicyConfigured, true);
  assert.equal(report.summary.domainLockConfigured, true);
  assert.equal(report.summary.dateLockConfigured, true);
  assert.equal(report.requestedFields.some((field) => field.field === "jsConfuserLockCountermeasures" && field.valueType === "string"), true);
  assert.equal(report.reviewEvidence.some((item) => item.id === "runtime-monitoring-target" && item.status === "evidenced"), true);
  assert.equal(report.reviewEvidence.some((item) => item.id === "countermeasure-policy" && item.status === "evidenced"), true);
  assert.equal(report.reviewEvidence.some((item) => item.id === "compatibility-scan" && item.status === "needs-review" && item.followUpReadsSource === true), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.title, "Runtime Defense Review Assistant");
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("RuntimeDefenseBeaconUrl values"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw config files"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Runtime behavior scope"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Monitoring handoff"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Countermeasure policy"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Domain/date lock smoke"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Source-reading compatibility scan"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Protected-build smoke"), true);
  assert.equal(json.includes("secret.example"), false);
  assert.equal(json.includes("tenant=acme"), false);
  assert.equal(json.includes("20260501"), false);
  assert.equal(json.includes("20261231"), false);
  assert.equal(json.includes("panic"), false);
  assert.equal(json.includes("4000"), false);

  const markdown = cli.renderRuntimeDefenseReviewText(report);
  assert.equal(markdown.includes("# Runtime Defense Migration Review"), true);
  assert.equal(markdown.includes("## Runtime Defense Review Assistant"), true);
  assert.equal(markdown.includes("BYO AI key"), true);
  assert.equal(markdown.includes("Runtime behavior scope"), true);
  assert.equal(markdown.includes("Ready for manual review"), true);
  assert.equal(markdown.includes("jsConfuserLockCountermeasures"), true);
  assert.equal(markdown.includes("secret.example"), false);
  assert.equal(markdown.includes("panic"), false);
});

test("CLI --runtime-defense-review writes Markdown and supports JSON", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  const outputPath = path.join(root, "runtime-defense-review.md");
  fs.writeFileSync(configPath, JSON.stringify({
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    selfDefending: true,
    debugProtection: true,
    domainLockRedirectUrl: "https://secret.example/blocked?tenant=acme",
    jsConfuserLockCountermeasures: "panic",
    options: {
      RuntimeDefenseBeaconUrl: "https://beacon.secret.example/runtime?tenant=acme"
    }
  }), "utf8");

  const written = await runCliInCwd(root, [
    "--config", configPath,
    "--runtime-defense-review",
    "--runtime-defense-review-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");
  assert.equal(written.stdout, "");
  assert.equal(written.stderr.includes("Runtime defense review report written:"), true);
  assert.equal(markdown.includes("# Runtime Defense Migration Review"), true);
  assert.equal(markdown.includes("## Runtime Defense Review Assistant"), true);
  assert.equal(markdown.includes("Release metadata"), true);
  assert.equal(markdown.includes("selfDefending"), false);
  assert.equal(markdown.includes("jsConfuserLockCountermeasures"), true);
  assert.equal(markdown.includes("secret.example"), false);
  assert.equal(markdown.includes("tenant=acme"), false);
  assert.equal(markdown.includes("panic"), false);

  const json = JSON.parse((await runCliInCwd(root, [
    "--config", configPath,
    "--runtime-defense-review",
    "--json"
  ], "")).stdout);
  const jsonText = JSON.stringify(json);
  assert.equal(json.format, "jso-protector-runtime-defense-review");
  assert.equal(json.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(json.reviewAssistant.sourceFree, true);
  assert.equal(json.reviewAssistant.questions.some((item) => item.topic === "Release metadata"), true);
  assert.equal(json.reviewAssistant.doNotInclude.includes("raw config files"), true);
  assert.equal(jsonText.includes("secret.example"), false);
  assert.equal(jsonText.includes("tenant=acme"), false);
  assert.equal(jsonText.includes("panic"), false);
});

test("buildRuntimeIncidentEvidenceReport summarizes clean source-free dashboard exports", async () => {
  const root = makeTempDir();
  const exportPath = writeRuntimeIncidentExportJson(root, [
    {
      incidentId: "9001",
      status: "Resolved",
      severity: "High",
      reason: "reviewed",
      buildId: "checkout-clean",
      receivedUtc: "2026-06-08T11:00:00Z",
      actionPlan: {
        sourceFree: true,
        escalationLevel: "archive",
        nextOwner: "review coordinator",
        nextAction: "Keep this incident with release evidence.",
        evidence: "per-incident-evidence-json",
        responseTargetLabel: "No active incident",
        windowState: "closed",
        statusTransition: "No dashboard status change",
        requiresAcknowledgement: false,
        overdue: false
      }
    },
    {
      incidentId: "9002",
      status: "Ignored",
      severity: "Low",
      reason: "test release",
      buildId: "checkout-clean",
      receivedUtc: "2026-06-08T11:30:00Z",
      actionPlan: {
        sourceFree: true,
        escalationLevel: "archive",
        nextOwner: "review coordinator",
        nextAction: "Keep this ignored test release row with reviewer evidence.",
        evidence: "per-incident-evidence-json",
        responseTargetLabel: "No active incident",
        windowState: "closed",
        statusTransition: "No dashboard status change",
        requiresAcknowledgement: false,
        overdue: false
      }
    }
  ], {
    filters: { status: "All", buildId: "checkout-clean" },
    routing: {
      sourceFree: true,
      escalationLevel: "normal",
      recommendedQueue: "checkout-owner",
      preferredEvidence: "runtime-incident-json",
      responseTargetMinutes: 1440,
      responseTargetLabel: "next business day",
      routeConfirmedIncidentsTo: ["customer-owned SIEM"],
      alertRoutingPlaybook: [{
        id: "reviewer-packet",
        lane: "Reviewer packet",
        owner: "review coordinator",
        trigger: "Release review",
        target: "Before review",
        evidence: "Dashboard Monitoring JSON",
        action: "Attach source-free runtime incident packet.",
        boundary: "Do not include secrets."
      }]
    },
    dashboardActions: [{
      id: "mark-open-reviewing",
      label: "Move open in view to Reviewing",
      dashboardAction: "mark_filtered_reviewing",
      formFieldName: "runtime_action",
      formFieldValue: "mark_filtered_reviewing",
      enabled: false,
      matchingOpenIncidentCount: 0,
      statusFrom: "Open",
      statusTo: "Reviewing",
      scope: "current account and selected status, severity, and BuildID filters",
      safety: "Leaves resolved, ignored, and already-reviewing incidents unchanged."
    }, {
      id: "resolve-reviewing",
      label: "Resolve reviewing in view",
      dashboardAction: "mark_filtered_resolved",
      formFieldName: "runtime_action",
      formFieldValue: "mark_filtered_resolved",
      enabled: false,
      matchingReviewingIncidentCount: 0,
      statusFrom: "Reviewing",
      statusTo: "Resolved",
      scope: "current account and selected status, severity, and BuildID filters",
      safety: "Leaves open, ignored, and already-resolved incidents unchanged."
    }]
  });

  const report = cli.buildRuntimeIncidentEvidenceReport(exportPath, { generatedAt: "2026-06-08T12:05:00Z" });
  assert.equal(report.format, "jso-protector-runtime-incident-evidence");
  assert.equal(report.ok, true);
  assert.equal(report.reviewDecision.status, "ready");
  assert.equal(report.summary.incidents, 2);
  assert.equal(report.summary.unresolvedHighCritical, 0);
  assert.deepEqual(report.summary.buildIds, ["checkout-clean"]);
  assert.equal(report.correlation.repeatedFingerprintGroupCount, 1);
  assert.equal(report.correlation.topFingerprintGroups[0].key, "fp-runtime");
  assert.equal(report.correlation.topFingerprintGroups[0].count, 2);
  assert.equal(report.routing.alertRoutingPlaybook.length, 1);
  assert.equal(report.dashboardActions.length, 2);
  assert.equal(report.dashboardActions[0].enabled, false);
  assert.equal(report.dashboardActions[1].dashboardAction, "mark_filtered_resolved");
  assert.equal(report.incidentActionPlan.incidentsWithActionPlan, 2);
  assert.equal(report.incidentActionPlan.nextOwnerCounts["review coordinator"], 2);
  assert.equal(report.incidentActionPlan.topActions[0].nextOwner, "review coordinator");
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw incident payloads"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Repeated signal correlation"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Alert routing handoff"), true);
  assert.equal(JSON.stringify(report).includes("203.0.113.10"), false);

  const markdown = cli.renderRuntimeIncidentEvidenceText(report);
  assert.equal(markdown.includes("# Runtime Incident Evidence"), true);
  assert.equal(markdown.includes("## Repeated Signal Correlation"), true);
  assert.equal(markdown.includes("fp-runtime"), true);
  assert.equal(markdown.includes("## Dashboard Actions"), true);
  assert.equal(markdown.includes("## Incident Action Plan"), true);
  assert.equal(markdown.includes("review coordinator"), true);
  assert.equal(markdown.includes("Move open in view to Reviewing"), true);
  assert.equal(markdown.includes("Resolve reviewing in view"), true);
  assert.equal(markdown.includes("Reviewer packet"), true);
  assert.equal(markdown.includes("## Runtime Incident Review Assistant"), true);
  assert.equal(markdown.includes("raw incident payloads"), true);
  assert.equal(markdown.includes("not a managed SOC report"), true);

  const outputPath = path.join(root, "runtime-incident-evidence.md");
  const written = await runCli([
    "--runtime-incident-evidence", exportPath,
    "--runtime-incident-evidence-output", outputPath
  ], "");
  assert.equal(written.stderr.includes("Runtime incident evidence report written:"), true);
  assert.equal(fs.readFileSync(outputPath, "utf8").includes("Runtime Incident Evidence"), true);

  const json = JSON.parse((await runCli(["--runtime-incident-evidence", exportPath, "--json"], "")).stdout);
  assert.equal(json.format, "jso-protector-runtime-incident-evidence");
  assert.equal(json.ok, true);
  assert.equal(json.reviewAssistant.sourceFree, true);
});

test("CLI --runtime-incident-evidence writes urgent packets and fails active high-critical exports", async () => {
  const root = makeTempDir();
  const exportPath = writeRuntimeIncidentExportJson(root, [{
    incidentId: "9101",
    status: "Open",
    severity: "Critical",
    reason: "unknown script",
    buildId: "checkout-urgent",
    receivedUtc: "2026-06-08T12:10:00Z",
    actionPlan: {
      sourceFree: true,
      escalationLevel: "urgent",
      nextOwner: "security response owner",
      nextAction: "Acknowledge this incident and route confirmed events.",
      evidence: "per-incident-evidence-json",
      responseTargetLabel: "15 minutes",
      responseDueUtc: "2026-06-08T12:25:00Z",
      windowState: "within-target",
      statusTransition: "Open -> Reviewing",
      requiresAcknowledgement: true,
      overdue: false
    }
  }, {
    incidentId: "9102",
    status: "Reviewing",
    severity: "High",
    reason: "confirmed checkout owner review",
    buildId: "checkout-urgent",
    receivedUtc: "2026-06-08T12:11:00Z",
    actionPlan: {
      sourceFree: true,
      escalationLevel: "urgent",
      nextOwner: "security response owner",
      nextAction: "Complete the security review.",
      evidence: "per-incident-evidence-json",
      responseTargetLabel: "15 minutes",
      responseDueUtc: "2026-06-08T12:26:00Z",
      windowState: "within-target",
      statusTransition: "Reviewing -> Resolved/Ignored after confirmation",
      requiresAcknowledgement: false,
      overdue: false
    }
  }], {
    filters: { status: "Active", severity: "HighOrCritical", buildId: "checkout-urgent" },
    routing: {
      escalationLevel: "urgent",
      recommendedQueue: "security-incident-response",
      preferredEvidence: "active-high-critical-json",
      responseTargetMinutes: 15,
      responseTargetLabel: "15 minutes",
      statusAction: "Move matching Open incidents to Reviewing.",
      routeConfirmedIncidentsTo: ["Splunk HEC", "signed webhook"]
    },
    responseWindow: {
      sourceFree: true,
      basis: "oldest active high/critical receivedUtc",
      generatedUtc: "2026-06-08T12:15:00Z",
      targetMinutes: 15,
      targetLabel: "15 minutes",
      responseDueUtc: "2026-06-08T12:25:00Z",
      overdue: false,
      windowState: "within-target"
    },
    dashboardActions: [{
      id: "mark-open-reviewing",
      label: "Move open in view to Reviewing",
      dashboardAction: "mark_filtered_reviewing",
      formFieldName: "runtime_action",
      formFieldValue: "mark_filtered_reviewing",
      enabled: true,
      matchingOpenIncidentCount: 1,
      statusFrom: "Open",
      statusTo: "Reviewing",
      scope: "current account and selected status, severity, and BuildID filters",
      safety: "Leaves resolved, ignored, and already-reviewing incidents unchanged."
    }, {
      id: "resolve-reviewing",
      label: "Resolve reviewing in view",
      dashboardAction: "mark_filtered_resolved",
      formFieldName: "runtime_action",
      formFieldValue: "mark_filtered_resolved",
      enabled: true,
      matchingReviewingIncidentCount: 1,
      statusFrom: "Reviewing",
      statusTo: "Resolved",
      scope: "current account and selected status, severity, and BuildID filters",
      safety: "Leaves open, ignored, and already-resolved incidents unchanged."
    }]
  });

  const report = cli.buildRuntimeIncidentEvidenceReport(exportPath, { generatedAt: "2026-06-08T12:16:00Z" });
  assert.equal(report.ok, false);
  assert.equal(report.reviewDecision.status, "needs-urgent-response");
  assert.match(report.reviewDecision.nextAction, /Move matching Open incidents to Reviewing/);
  assert.equal(report.dashboardActions[0].enabled, true);
  assert.equal(report.correlation.topFingerprintGroups[0].highOrCriticalActiveCount, 2);
  assert.equal(report.incidentActionPlan.incidentsWithActionPlan, 2);
  assert.equal(report.incidentActionPlan.acknowledgementRequiredCount, 1);
  assert.equal(report.incidentActionPlan.nextOwnerCounts["security response owner"], 2);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Urgent response"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Incident owner assignment"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Repeated high-risk signal"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Dashboard status actions"), true);
  assert.match(report.recommendations[0], /Move open in view to Reviewing/);
  assert.match(report.recommendations[1], /Resolve reviewing in view/);
  assert.match(report.recommendations[2], /Review repeated fingerprint signal/);

  const outputPath = path.join(root, "runtime-incident-evidence.json");
  await assert.rejects(
    () => runCli([
      "--runtime-incident-evidence", exportPath,
      "--runtime-incident-evidence-output", outputPath,
      "--json"
    ], ""),
    /runtime incident evidence needs response/
  );
  const written = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  assert.equal(written.ok, false);
  assert.equal(written.summary.unresolvedHighCritical, 2);
  assert.equal(written.routing.recommendedQueue, "security-incident-response");
  assert.equal(written.correlation.repeatedFingerprintGroupCount, 1);
  assert.equal(written.incidentActionPlan.acknowledgementRequiredCount, 1);
  assert.equal(written.dashboardActions[0].dashboardAction, "mark_filtered_reviewing");
  assert.equal(written.dashboardActions[1].dashboardAction, "mark_filtered_resolved");
  assert.equal(written.reviewAssistant.questions.some((item) => item.topic === "Urgent response"), true);
});

test("verifyVmProofReport accepts saved API report evidence", () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, "\uFEFF" + JSON.stringify({
    Type: "Succeed",
    Report: {
      BuildID: "2026-06-06-main",
      EnabledOptions: ["EncryptStrings", "UseVMProtection"],
      VMProtectionApplied: true,
      VMProtectionVirtualizedCount: 2,
      VMProtectionWarnings: []
    }
  }, null, 2), "utf8");

  const report = cli.verifyVmProofReport(reportPath, { minVirtualizedFunctions: 2 });
  assert.equal(report.ok, true);
  assert.equal(report.buildId, "2026-06-06-main");
  assert.equal(report.summary.requested, true);
  assert.equal(report.summary.applied, true);
  assert.equal(report.summary.virtualizedCount, 2);
});

test("verifyVmProofReport rejects weak VM proof", () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    UseVMProtection: true,
    VMProtectionApplied: false,
    VMProtectionVirtualizedCount: 0,
    VMProtectionWarnings: ["@virtualize function 'validateLicense' was skipped: async"]
  }, null, 2), "utf8");

  const report = cli.verifyVmProofReport(reportPath);
  assert.equal(report.ok, false);
  assert.equal(report.summary.requested, true);
  assert.equal(report.summary.applied, false);
  assert.equal(report.summary.warnings, 1);
  assert.equal(report.checks.some((check) => check.name === "virtualized-count" && !check.ok), true);
});

test("CLI --verify-vm-proof emits JSON proof check", async () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    Report: {
      BuildId: "build-42",
      Options: { UseVMProtection: true },
      VMProtectionApplied: true,
      VirtualizedFunctionCount: "1",
      VMProtectionWarnings: ""
    }
  }, null, 2), "utf8");

  const result = await runCli(["--verify-vm-proof", reportPath, "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "jso-protector-vm-proof-check");
  assert.equal(report.ok, true);
  assert.equal(report.buildId, "build-42");
  assert.equal(report.summary.virtualizedCount, 1);
});

test("buildVmProofPack summarizes source-free VM reviewer evidence", () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    Type: "Succeed",
    Report: {
      BuildID: "build-vm-pack",
      ReleaseLabel: "checkout-release-42",
      PolymorphismFingerprint: "pf-vm-pack",
      EnabledOptions: ["EncryptStrings", "UseVMProtection"],
      VMProtectionApplied: true,
      VMProtectionVirtualizedCount: 2,
      VMProtectionWarnings: []
    }
  }, null, 2), "utf8");

  const pack = cli.buildVmProofPack(reportPath, { minVirtualizedFunctions: 2 });
  const markdown = cli.renderVmProofPackMarkdown(pack);

  assert.equal(pack.format, "jso-protector-vm-proof-pack");
  assert.equal(pack.ok, true);
  assert.equal(pack.sourceFree, true);
  assert.equal(pack.buildId, "build-vm-pack");
  assert.equal(pack.releaseLabel, "checkout-release-42");
  assert.equal(pack.polymorphismFingerprint, "pf-vm-pack");
  assert.equal(pack.proof.summary.virtualizedCount, 2);
  assert.equal(pack.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(pack.reviewDecision.manualReviewRequired, true);
  assert.match(pack.reviewDecision.nextAction, /cold sensitive path/);
  assert.equal(pack.reviewAssistant.sourceFree, true);
  assert.match(pack.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(pack.reviewAssistant.doNotInclude.includes("VM bytecode"), true);
  assert.equal(pack.reviewAssistant.questions.some((item) => item.topic === "VM scope confirmation"), true);
  assert.equal(pack.reviewAssistant.questions.some((item) => item.topic === "Hot-path risk"), true);
  assert.equal(pack.reviewAssistant.questions.some((item) => item.topic === "Protected-build smoke"), true);
  assert.equal(pack.checklist.some((item) => item.name === "build-id" && item.required && item.ok), true);
  assert.equal(pack.checklist.some((item) => item.name === "performance-scope" && item.required === false && item.ok === false), true);
  assert.equal(pack.compatibilityGuidance.some((item) => item.scope === "Skipped with warning" && /async functions/.test(item.examples)), true);
  assert.equal(pack.performanceGuidance.some((item) => item.scope === "Do not virtualize" && /Render loops/.test(item.examples)), true);
  assert.equal(pack.recommendations.some((item) => /Attach this proof pack/.test(item)), true);
  assert.equal(markdown.includes("# JSO VM Proof Pack"), true);
  assert.equal(markdown.includes("| Build ID | build-vm-pack |"), true);
  assert.equal(markdown.includes("## Compatibility Guidance"), true);
  assert.equal(markdown.includes("## Review Decision"), true);
  assert.equal(markdown.includes("Ready for manual review"), true);
  assert.equal(markdown.includes("checkout-provider callbacks"), true);
  assert.equal(markdown.includes("## Hot-Path Guidance"), true);
  assert.equal(markdown.includes("Render loops"), true);
  assert.equal(markdown.includes("## VM Proof Review Assistant"), true);
  assert.equal(markdown.includes("Protected-build smoke"), true);
  assert.equal(markdown.includes("VM bytecode"), true);
});

test("CLI --vm-proof-pack writes Markdown and supports JSON", async () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  const outputPath = path.join(root, "vm-proof-pack.md");
  fs.writeFileSync(reportPath, JSON.stringify({
    Report: {
      BuildId: "build-vm-cli",
      Label: "ci-123",
      Options: { UseVMProtection: true, EncryptStrings: true },
      VMProtectionApplied: true,
      VirtualizedFunctionCount: "1",
      VMProtectionWarnings: ""
    }
  }, null, 2), "utf8");

  const written = await runCli([
    "--vm-proof-pack", reportPath,
    "--vm-proof-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");
  assert.equal(written.stdout, "");
  assert.equal(written.stderr.includes("VM proof pack written:"), true);
  assert.equal(markdown.includes("# JSO VM Proof Pack"), true);
  assert.equal(markdown.includes("| Build ID | build-vm-cli |"), true);
  assert.equal(markdown.includes("Status: PASS"), true);
  assert.equal(markdown.includes("Review decision: Ready for manual review"), true);

  const json = JSON.parse((await runCli(["--vm-proof-pack", reportPath, "--json"], "")).stdout);
  assert.equal(json.format, "jso-protector-vm-proof-pack");
  assert.equal(json.ok, true);
  assert.equal(json.buildId, "build-vm-cli");
  assert.equal(json.evidence.requested, true);
  assert.equal(json.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(json.reviewAssistant.sourceFree, true);
  assert.equal(json.reviewAssistant.questions.some((item) => item.topic === "Hot-path risk"), true);
  assert.equal(json.compatibilityGuidance.some((item) => item.scope === "Supported function shape"), true);
  assert.equal(json.performanceGuidance.some((item) => item.scope === "Good VM candidates"), true);
});

test("buildAiResistanceEvidenceReport summarizes current AI-resistance evidence", () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    Type: "Succeed",
    Report: {
      BuildID: "build-ai-1",
      PolymorphismFingerprint: "fp-123",
      EnabledOptions: ["EncryptStrings", "FlatTransform", "UseVMProtection"],
      VMProtectionApplied: true,
      VMProtectionVirtualizedCount: 1,
      VMProtectionWarnings: [],
      CompatibilitySummary: { Risk: "Low" },
      RuntimeDefenseSummary: { Events: 0 },
      GlobalIdentifierMap: []
    }
  }, null, 2), "utf8");

  const report = cli.buildAiResistanceEvidenceReport(reportPath, { requireVmProof: true });
  assert.equal(report.format, "jso-protector-ai-resistance-evidence");
  assert.equal(report.ok, true);
  assert.equal(report.scoreStatus, "planned-methodology-not-production-score");
  assert.equal(report.buildId, "build-ai-1");
  assert.equal(report.evidence.vmProof.ok, true);
  assert.equal(report.reviewDecision.decision, "ready-for-manual-review");
  assert.equal(report.reviewDecision.manualReviewRequired, true);
  assert.equal(report.reviewDecision.missingReviewTracks.some((row) => row.id === "static-identifier-recovery"), true);
  assert.deepEqual(report.evidence.strongOptions, ["EncryptStrings", "FlatTransform", "UseVMProtection"]);
  assert.equal(report.checks.some((check) => check.name === "resistance-score-status" && check.ok), true);
  assert.equal(report.reviewMatrix.some((row) => row.id === "control-flow-reconstruction" && row.status === "evidenced"), true);
  assert.equal(report.reviewMatrix.some((row) => row.id === "runtime-instrumentation" && /tamper activity/.test(row.safeClaim)), true);
  assert.equal(report.reviewMatrix.some((row) => row.id === "source-free-review-handoff" && /raw source/.test(row.reviewerAction)), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw source code"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Manual review tracks"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Resistance Score boundary"), true);
  assert.equal(report.claimBoundaries.some((item) => item.claim === "AI resistance" && /static-analysis/.test(item.approvedWording)), true);
  assert.equal(report.claimBoundaries.some((item) => /AI-proof/.test(item.doNotSay)), true);
  assert.equal(report.recommendations.some((item) => /AI-proof/.test(item)), true);
});

test("buildAiResistanceEvidenceReport fails weak required evidence", () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    Report: {
      EnabledOptions: [],
      UseVMProtection: true,
      VMProtectionApplied: false,
      VMProtectionVirtualizedCount: 0,
      VMProtectionWarnings: ["@virtualize function 'validateLicense' was skipped"]
    }
  }, null, 2), "utf8");

  const report = cli.buildAiResistanceEvidenceReport(reportPath, { requireVmProof: true });
  assert.equal(report.ok, false);
  assert.equal(report.checks.some((check) => check.name === "build-id" && check.required && !check.ok), true);
  assert.equal(report.checks.some((check) => check.name === "strong-protection-options" && check.required && !check.ok), true);
  assert.equal(report.checks.some((check) => check.name === "vm-proof" && check.required && !check.ok), true);
  assert.equal(report.evidence.vmProof.warnings.length, 1);
  assert.equal(report.reviewDecision.decision, "blocked");
  assert.equal(report.reviewDecision.failedChecks.includes("build-id"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Required evidence failures"), true);
});

test("CLI --ai-resistance-evidence emits JSON evidence report", async () => {
  const root = makeTempDir();
  const reportPath = path.join(root, "jso-report.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    Report: {
      BuildId: "build-ai-cli",
      Options: { EncryptStrings: true, FlatTransform: true },
      PolymorphismFingerprint: "fp-cli",
      VMProtectionWarnings: []
    }
  }, null, 2), "utf8");

  const result = await runCli(["--ai-resistance-evidence", reportPath, "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "jso-protector-ai-resistance-evidence");
  assert.equal(report.ok, true);
  assert.equal(report.buildId, "build-ai-cli");
  assert.equal(report.scoreStatus, "planned-methodology-not-production-score");
  assert.equal(report.reviewDecision.decision, "ready-for-manual-review");
  assert.deepEqual(report.evidence.strongOptions, ["EncryptStrings", "FlatTransform"]);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("protected output"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Resistance Score boundary"), true);
  assert.equal(report.claimBoundaries.some((item) => item.claim === "Resistance Score" && item.status === "planned"), true);
  assert.equal(report.reviewMatrix.some((row) => row.id === "string-literal-recovery" && row.status === "evidenced"), true);

  const textResult = await runCli(["--ai-resistance-evidence", reportPath], "");
  assert.equal(textResult.stdout.includes("review decision: Ready for manual review"), true);
  assert.equal(textResult.stdout.includes("Review matrix:"), true);
  assert.equal(textResult.stdout.includes("Claim boundaries:"), true);
  assert.equal(textResult.stdout.includes("Review assistant packet:"), true);
  assert.equal(textResult.stdout.includes("Resistance Score boundary"), true);
  assert.equal(textResult.stdout.includes("Resistance Score is a planned methodology"), true);

  const jsonOutputPath = path.join(root, "ai-resistance-evidence.json");
  const jsonFileResult = await runCli(["--ai-resistance-evidence", reportPath, "--ai-resistance-evidence-output", jsonOutputPath, "--json"], "");
  assert.equal(jsonFileResult.stdout, "");
  assert.equal(jsonFileResult.stderr.includes("AI resistance evidence report written:"), true);
  const writtenJson = JSON.parse(fs.readFileSync(jsonOutputPath, "utf8"));
  assert.equal(writtenJson.format, "jso-protector-ai-resistance-evidence");
  assert.equal(writtenJson.buildId, "build-ai-cli");
  assert.equal(writtenJson.reviewDecision.decision, "ready-for-manual-review");

  const textOutputPath = path.join(root, "ai-resistance-evidence.md");
  const textFileResult = await runCli(["--ai-resistance-evidence", reportPath, "--ai-resistance-evidence-output", textOutputPath], "");
  assert.equal(textFileResult.stdout, "");
  assert.equal(textFileResult.stderr.includes("AI resistance evidence report written:"), true);
  const writtenText = fs.readFileSync(textOutputPath, "utf8");
  assert.equal(writtenText.includes("review decision: Ready for manual review"), true);
  assert.equal(writtenText.includes("Review matrix:"), true);
  assert.equal(writtenText.includes("Claim boundaries:"), true);
  assert.equal(writtenText.includes("Review assistant packet:"), true);
});

test("buildScriptInventoryFromSnapshot converts runtime inventory to a PCI starter", () => {
  const root = makeTempDir();
  const snapshotPath = path.join(root, "runtime-inventory.json");
  fs.writeFileSync(snapshotPath, JSON.stringify({
    v: 1,
    kind: "inventory",
    buildId: "checkout-build-1",
    pageHref: "https://shop.example/checkout",
    scripts: [
      {
        src: "https://js.stripe.com/v3/",
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        inline: false,
        injectedAfterLoad: false,
        allowlisted: true,
        checkoutSurface: "hosted-checkout",
        frameContext: "psp-iframe",
        frameOwner: "Payments",
        parentPageHref: "https://shop.example/checkout",
        frameHref: "https://checkout.stripe.example/frame",
        observedAt: "2026-06-07T00:00:00.000Z"
      },
      {
        src: "https://cdn.bad.example/skimmer.js",
        sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        inline: false,
        injectedAfterLoad: true,
        allowlisted: false,
        observedAt: "2026-06-07T00:01:00.000Z"
      },
      {
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        inline: true,
        allowlisted: true,
        observedAt: "2026-06-07T00:02:00.000Z"
      },
      {
        src: "/assets/checkout.js",
        sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        inline: false,
        allowlisted: true
      }
    ]
  }, null, 2), "utf8");

  const report = cli.buildScriptInventoryFromSnapshot(snapshotPath, {
    generatedUtc: "2026-06-07T00:03:00.000Z"
  });

  assert.equal(report.format, "jso-payment-script-inventory");
  assert.equal(report.sourceFree, true);
  assert.equal(report.reviewStatus, "starter-generated-review-required");
  assert.equal(report.generatedUtc, "2026-06-07T00:03:00.000Z");
  assert.deepEqual(report.buildIds, ["checkout-build-1"]);
  assert.deepEqual(report.pageHrefs, ["https://shop.example/checkout"]);
  assert.equal(report.scripts.length, 4);

  const stripe = report.scripts.find((item) => item.source === "https://js.stripe.com/v3/");
  const skimmer = report.scripts.find((item) => item.source === "https://cdn.bad.example/skimmer.js");
  const firstParty = report.scripts.find((item) => item.source === "/assets/checkout.js");
  const inline = report.scripts.find((item) => item.source.startsWith("inline:sha256-"));

  assert.equal(stripe.authorized, true);
  assert.equal(stripe.justification, "");
  assert.equal(stripe.category, "third-party");
  assert.equal(stripe.integrity, "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(stripe.checkoutSurface, "hosted-checkout");
  assert.equal(stripe.frameContext, "psp-iframe");
  assert.equal(stripe.frameOwner, "Payments");
  assert.equal(stripe.parentPageHref, "https://shop.example/checkout");
  assert.equal(stripe.frameHref, "https://checkout.stripe.example/frame");
  assert.equal(stripe.risk, "");
  assert.equal(stripe.dataAccess, "");
  assert.equal(stripe.approvalTicket, "");
  assert.equal(skimmer.authorized, false);
  assert.equal(skimmer.injectedAfterLoad, true);
  assert.equal(firstParty.category, "first-party");
  assert.equal(inline.category, "inline");
  assert.equal(inline.owner, "");
});

test("CLI --script-inventory-from-snapshot writes a review starter file", async () => {
  const root = makeTempDir();
  const snapshotPath = path.join(root, "runtime-inventory.json");
  const outputPath = path.join(root, "payment-script-inventory.json");
  fs.writeFileSync(snapshotPath, JSON.stringify({
    payload: JSON.stringify({
      v: 1,
      kind: "inventory",
      buildId: "checkout-build-2",
      pageHref: "https://shop.example/checkout",
      scripts: [{
        src: "https://www.paypal.com/sdk/js",
        sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        allowlisted: true
      }]
    })
  }, null, 2), "utf8");

  const result = await runCli([
    "--script-inventory-from-snapshot", snapshotPath,
    "--script-inventory-output", outputPath
  ], "");
  const report = JSON.parse(fs.readFileSync(outputPath, "utf8"));

  assert.equal(result.stdout, "");
  assert.equal(result.stderr.includes("script inventory written:"), true);
  assert.equal(report.format, "jso-payment-script-inventory");
  assert.equal(report.scripts.length, 1);
  assert.equal(report.scripts[0].source, "https://www.paypal.com/sdk/js");
  assert.equal(report.scripts[0].authorized, true);
  assert.equal(report.scripts[0].justification, "");
  assert.equal(report.scripts[0].risk, "");
  assert.equal(report.scripts[0].dataAccess, "");
  assert.equal(report.scripts[0].approvalTicket, "");
});

test("buildPaymentPageHeadersFromHar converts HAR page responses to a security-header snapshot", () => {
  const root = makeTempDir();
  const harPath = path.join(root, "checkout.har");
  fs.writeFileSync(harPath, JSON.stringify({
    log: {
      version: "1.2",
      creator: { name: "test", version: "1" },
      entries: [
        {
          startedDateTime: "2026-06-08T12:00:00.000Z",
          _resourceType: "document",
          request: { method: "GET", url: "https://shop.example/checkout" },
          response: {
            status: 200,
            headers: [
              { name: "Content-Type", value: "text/html; charset=utf-8" },
              { name: "Content-Security-Policy", value: "default-src 'self'; script-src 'self' https://js.stripe.com; frame-src https://js.stripe.com; report-uri https://csp.example.test/report" },
              { name: "Strict-Transport-Security", value: "max-age=31536000" },
              { name: "Set-Cookie", value: "session=secret" }
            ],
            content: { mimeType: "text/html" }
          }
        },
        {
          startedDateTime: "2026-06-08T12:00:01.000Z",
          _resourceType: "iframe",
          request: { method: "GET", url: "https://shop.example/checkout/card-frame" },
          response: {
            status: 200,
            headers: [
              { name: "Content-Type", value: "text/html" },
              { name: "Content-Security-Policy-Report-Only", value: "default-src 'none'; report-to csp-endpoint" },
              { name: "Reporting-Endpoints", value: "csp-endpoint=\"https://csp.example.test/report\"" },
              { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" }
            ],
            content: { mimeType: "text/html" }
          }
        },
        {
          startedDateTime: "2026-06-08T12:00:02.000Z",
          _resourceType: "script",
          request: { method: "GET", url: "https://shop.example/checkout.js" },
          response: {
            status: 200,
            headers: [
              { name: "Content-Type", value: "application/javascript" },
              { name: "Content-Security-Policy", value: "default-src 'none'" }
            ],
            content: { mimeType: "application/javascript" }
          }
        }
      ]
    }
  }, null, 2), "utf8");

  const initialReport = cli.buildPaymentPageHeadersFromHar(harPath, {
    urlPattern: "checkout"
  });
  const baselinePath = path.join(root, "payment-page-headers.baseline.json");
  fs.writeFileSync(baselinePath, JSON.stringify({
    format: "jso-payment-page-security-headers",
    pages: [
      initialReport.pages[0],
      {
        ...initialReport.pages[1],
        headerSha256: "b".repeat(64)
      }
    ]
  }, null, 2), "utf8");

  const report = cli.buildPaymentPageHeadersFromHar(harPath, {
    urlPattern: "checkout",
    baselinePath
  });

  assert.equal(report.format, "jso-payment-page-security-headers");
  assert.equal(report.sourceFree, true);
  assert.equal(report.generatedBy, "jso-protector --payment-page-headers-from-har");
  assert.equal(report.source.baselineFile, "payment-page-headers.baseline.json");
  assert.match(report.source.baselineSha256, /^[a-f0-9]{64}$/);
  assert.equal(report.baseline.baselinePages, 2);
  assert.equal(report.baseline.matchedPages, 1);
  assert.equal(report.baseline.mismatchedPages, 1);
  assert.equal(report.baseline.missingPages, 0);
  assert.equal(report.pages.length, 2);
  assert.equal(report.summary.pages, 2);
  assert.equal(report.summary.withCsp, 1);
  assert.equal(report.summary.withReportOnlyCsp, 1);
  assert.equal(report.summary.withScriptSrc, 2);
  assert.equal(report.summary.withFrameSrc, 1);
  assert.equal(report.summary.withHsts, 1);
  assert.equal(report.summary.withReportEndpoint, 2);
  assert.equal(report.summary.baselineMatches, 1);
  assert.equal(report.summary.baselineMismatches, 1);
  assert.equal(report.summary.baselineMissing, 0);
  assert.deepEqual(report.summary.domains, ["shop.example"]);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw response headers"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("cookies"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Baseline drift"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "CSP coverage"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Frame policy"), true);
  assert.equal(report.pages[0].headers["content-security-policy"].includes("script-src"), true);
  assert.equal(report.pages[0].headers["set-cookie"], undefined);
  assert.equal(report.pages[0].matchesBaseline, "match");
  assert.equal(report.pages[0].baselineSha256, report.pages[0].headerSha256);
  assert.equal(report.pages[1].frameContext, "iframe");
  assert.equal(report.pages[1].matchesBaseline, "mismatch");
  assert.equal(report.pages[1].headers["reporting-endpoints"].includes("csp-endpoint"), true);
  assert.match(report.pages[0].headerSha256, /^[a-f0-9]{64}$/);
});

test("CLI --payment-page-headers-from-har writes a security-header snapshot", async () => {
  const root = makeTempDir();
  const harPath = path.join(root, "checkout.har");
  const baselinePath = path.join(root, "payment-page-headers.baseline.json");
  const outputPath = path.join(root, "payment-page-headers.json");
  fs.writeFileSync(harPath, JSON.stringify({
    log: {
      version: "1.2",
      creator: { name: "test", version: "1" },
      entries: [{
        startedDateTime: "2026-06-08T12:00:00.000Z",
        _resourceType: "document",
        request: { method: "GET", url: "https://shop.example/checkout" },
        response: {
          status: 200,
          headers: [
            { name: "Content-Type", value: "text/html" },
            { name: "Content-Security-Policy", value: "default-src 'self'; script-src 'self'; frame-src https://pay.example.test" },
            { name: "X-Frame-Options", value: "DENY" }
          ],
          content: { mimeType: "text/html" }
        }
      }]
    }
  }, null, 2), "utf8");
  const baseline = cli.buildPaymentPageHeadersFromHar(harPath, {
    urlPattern: "checkout"
  });
  fs.writeFileSync(baselinePath, JSON.stringify({
    format: "jso-payment-page-security-headers",
    pages: baseline.pages
  }, null, 2), "utf8");

  const result = await runCli([
    "--payment-page-headers-from-har", harPath,
    "--payment-page-headers-baseline", baselinePath,
    "--payment-page-headers-output", outputPath,
    "--payment-page-url-pattern", "checkout"
  ], "");
  const report = JSON.parse(fs.readFileSync(outputPath, "utf8"));

  assert.equal(result.stdout, "");
  assert.equal(result.stderr.includes("payment-page security headers written:"), true);
  assert.equal(report.format, "jso-payment-page-security-headers");
  assert.equal(report.pages.length, 1);
  assert.equal(report.pages[0].headers["x-frame-options"], "DENY");
  assert.equal(report.pages[0].matchesBaseline, "match");
  assert.equal(report.summary.baselineMatches, 1);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw response headers"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "CSP reporting"), true);
});

test("buildScriptInventoryAudit reconciles approved inventory with runtime snapshot", () => {
  const root = makeTempDir();
  const inventoryPath = path.join(root, "payment-script-inventory.json");
  const snapshotPath = path.join(root, "runtime-inventory.json");
  const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const shaC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  const shaD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

  fs.writeFileSync(inventoryPath, JSON.stringify({
    format: "jso-payment-script-inventory",
    scripts: [
      {
        source: "https://js.stripe.com/v3/",
        authorized: true,
        justification: "Card tokenization provider.",
        owner: "Payments",
        integrity: "sha256-" + shaA,
        lastReviewedUtc: "2026-06-07T00:00:00.000Z",
        checkoutSurface: "hosted-checkout",
        frameContext: "psp-iframe",
        frameOwner: "Payments",
        frameHref: "https://checkout.stripe.example/frame"
      },
      {
        source: "https://cdn.bad.example/skimmer.js",
        authorized: false,
        justification: "Known blocked test script.",
        owner: "Security",
        integrity: "sha256-" + shaB,
        lastReviewedUtc: "2026-06-07T00:00:00.000Z"
      },
      {
        source: "https://static.example/checkout.js",
        authorized: true,
        justification: "First-party checkout orchestration.",
        owner: "Checkout",
        integrity: "sha256-" + shaC,
        lastReviewedUtc: "2026-06-07T00:00:00.000Z",
        risk: "low",
        dataAccess: "checkout-state",
        approvalTicket: "CHG-2003"
      }
    ]
  }, null, 2), "utf8");

  fs.writeFileSync(snapshotPath, JSON.stringify({
    v: 1,
    kind: "inventory",
    buildId: "checkout-build-audit",
    pageHref: "https://shop.example/checkout",
    scripts: [
      {
        src: "https://js.stripe.com/v3/",
        sha256: shaD,
        allowlisted: true,
        injectedAfterLoad: false,
        checkoutSurface: "hosted-checkout",
        frameContext: "psp-iframe",
        frameOwner: "Payments",
        frameHref: "https://checkout.stripe.example/frame",
        observedAt: "2026-06-07T00:01:00.000Z"
      },
      {
        src: "https://cdn.bad.example/skimmer.js",
        sha256: shaB,
        allowlisted: false,
        injectedAfterLoad: true,
        observedAt: "2026-06-07T00:02:00.000Z"
      },
      {
        src: "https://tag.example/new.js",
        sha256: shaA,
        allowlisted: false,
        observedAt: "2026-06-07T00:03:00.000Z"
      }
    ],
    violations: [
      {
        reason: "content-changed-vs-previous-deploy",
        src: "https://js.stripe.com/v3/",
        sha256: shaD
      },
      {
        reason: "unknown-origin",
        src: "https://tag.example/new.js",
        sha256: shaA
      }
    ]
  }, null, 2), "utf8");

  const report = cli.buildScriptInventoryAudit(inventoryPath, snapshotPath, {
    generatedAt: "2026-06-07T00:04:00.000Z"
  });

  assert.equal(report.format, "jso-payment-script-inventory-audit");
  assert.equal(report.sourceFree, true);
  assert.equal(report.ok, false);
  assert.equal(report.generatedAt, "2026-06-07T00:04:00.000Z");
  assert.equal(report.summary.approvedScripts, 3);
  assert.equal(report.summary.observedScripts, 3);
  assert.equal(report.summary.unknownObserved, 1);
  assert.equal(report.summary.unauthorizedObserved, 1);
  assert.equal(report.summary.integrityMismatches, 1);
  assert.equal(report.summary.missingApproved, 1);
  assert.equal(report.summary.injectedAfterLoad, 1);
  assert.equal(report.summary.runtimeViolations, 2);
  assert.equal(report.summary.authorizedApprovedScripts, 2);
  assert.equal(report.summary.withRiskRating, 1);
  assert.equal(report.summary.withDataAccess, 1);
  assert.equal(report.summary.withApprovalTicket, 1);
  assert.equal(report.summary.missingRiskRating, 1);
  assert.equal(report.summary.missingDataAccess, 1);
  assert.equal(report.summary.missingApprovalTicket, 1);
  assert.equal(report.summary.reviewMetadataGaps, 1);
  assert.deepEqual(report.summary.approvedCheckoutSurfaces, { "hosted-checkout": 1 });
  assert.deepEqual(report.summary.observedCheckoutSurfaces, { "hosted-checkout": 1 });
  assert.deepEqual(report.summary.approvedFrameContexts, { "psp-iframe": 1 });
  assert.deepEqual(report.summary.observedFrameContexts, { "psp-iframe": 1 });
  assert.equal(report.summary.approvedIframeScopedScripts, 1);
  assert.equal(report.summary.observedIframeScopedScripts, 1);
  assert.equal(report.findings.integrityMismatches[0].source, "https://js.stripe.com/v3/");
  assert.deepEqual(report.findings.integrityMismatches[0].frameContexts, ["psp-iframe"]);
  assert.equal(report.findings.unknownObserved[0].source, "https://tag.example/new.js");
  assert.equal(report.findings.missingApproved[0].source, "https://static.example/checkout.js");
  assert.equal(report.findings.missingApproved[0].risk, "low");
  assert.equal(report.findings.missingApproved[0].dataAccess, "checkout-state");
  assert.equal(report.findings.missingApproved[0].approvalTicket, "CHG-2003");
  assert.equal(report.findings.reviewMetadataGaps[0].source, "https://js.stripe.com/v3/");
  assert.deepEqual(report.findings.reviewMetadataGaps[0].missing, ["risk", "dataAccess", "approvalTicket"]);
  assert.equal(report.checklist.some((item) => item.name === "review-context" && item.required === false && item.ok === false), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw source code"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Unknown observed scripts"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => /QSA assessment/.test(report.reviewAssistant.reviewerPrompt)), true);
  assert.equal(report.recommendations.some((item) => item.includes("optional review context")), true);
  const markdown = cli.renderScriptInventoryAuditMarkdown(report);
  assert.equal(markdown.includes("Payment-Page Script Inventory Audit"), true);
  assert.equal(markdown.includes("| Review metadata gaps | 1 |"), true);
  assert.equal(markdown.includes("| Frame contexts | psp-iframe: 1 approved / psp-iframe: 1 observed |"), true);
  assert.equal(markdown.includes("frameContext=psp-iframe"), true);
  assert.equal(markdown.includes("risk=low; dataAccess=checkout-state; approvalTicket=CHG-2003"), true);
  assert.equal(markdown.includes("## Review Assistant Packet"), true);
  assert.equal(markdown.includes("Use with a BYO AI key or internal reviewer"), true);
  assert.equal(markdown.includes("raw source code"), true);
});

test("CLI --script-inventory-audit writes a clean Markdown proof packet", async () => {
  const root = makeTempDir();
  const inventoryPath = path.join(root, "payment-script-inventory.json");
  const snapshotPath = path.join(root, "runtime-inventory.json");
  const outputPath = path.join(root, "payment-script-inventory-audit.md");
  const sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

  fs.writeFileSync(inventoryPath, JSON.stringify({
    scripts: [{
      source: "https://js.stripe.com/v3/",
      authorized: true,
      justification: "Card tokenization provider.",
      owner: "Payments",
      integrity: "sha256-" + sha,
      lastReviewedUtc: "2026-06-07T00:00:00.000Z",
      risk: "medium",
      dataAccess: "payment-tokenization",
      approvalTicket: "CHG-2401"
    }]
  }, null, 2), "utf8");

  fs.writeFileSync(snapshotPath, JSON.stringify({
    v: 1,
    kind: "inventory",
    buildId: "checkout-build-clean",
    pageHref: "https://shop.example/checkout",
    scripts: [{
      src: "https://js.stripe.com/v3/",
      sha256: sha,
      allowlisted: true,
      injectedAfterLoad: false,
      observedAt: "2026-06-07T00:01:00.000Z"
    }],
    violations: []
  }, null, 2), "utf8");

  const result = await runCli([
    "--script-inventory-audit", inventoryPath,
    "--runtime-inventory-snapshot", snapshotPath,
    "--script-inventory-audit-output", outputPath
  ], "");
  const markdown = fs.readFileSync(outputPath, "utf8");

  assert.equal(result.stdout, "");
  assert.equal(result.stderr.includes("script inventory audit written:"), true);
  assert.equal(markdown.includes("# Payment-Page Script Inventory Audit"), true);
  assert.equal(markdown.includes("Status: PASS"), true);
  assert.equal(markdown.includes("## Review Assistant Packet"), true);
  assert.equal(markdown.includes("Clean review"), true);
});

test("checkSizeBudgets reports output byte and growth failures", () => {
  const manifest = {
    files: [{
      fileName: "app.js",
      sourceBytes: 10,
      outputBytes: 50
    }]
  };
  const failures = cli.checkSizeBudgets(manifest, {
    maxOutputBytes: 40,
    maxGrowthRatio: 4
  });

  assert.deepEqual(failures.map((failure) => failure.type), ["max-output-bytes", "max-growth-ratio"]);
  assert.throws(() => cli.assertSizeBudgets(manifest, { maxGrowthRatio: 4 }), /Size budget failed/);
});

test("CLI prints preset and option references as JSON", async () => {
  const presets = await runCli(["--list-presets", "--json"], "");
  const options = await runCli(["--list-options", "--json"], "");
  const migrationMap = await runCli(["--list-migration-map", "--json"], "");

  assert.equal(JSON.parse(presets.stdout).presets.length, 4);
  assert.equal(JSON.parse(options.stdout).options.some((option) => option.name === "VariableExclusion"), true);
  const parsedMigrationMap = JSON.parse(migrationMap.stdout);
  assert.equal(parsedMigrationMap.summary.totalKnown, parsedMigrationMap.mappings.length + parsedMigrationMap.review.length);
  assert.equal(parsedMigrationMap.mappings.some((item) => item.source === "controlFlowFlattening"), true);
  assert.equal(presets.stderr, "");
  assert.equal(options.stderr, "");
  assert.equal(migrationMap.stderr, "");
});

test("CLI prints migration coverage summary for humans", async () => {
  const result = await runCli(["--list-migration-map"], "");

  assert.equal(result.stdout.includes("Mapped:"), true);
  assert.equal(result.stdout.includes("Review-only:"), true);
  assert.equal(result.stdout.includes("optionsPreset -> preset"), true);
  assert.equal(result.stderr, "");
});

test("CLI help includes script inventory generator flags", async () => {
  const result = await runCli(["--help"], "");

  assert.equal(result.stdout.includes("--script-inventory-from-snapshot <file>"), true);
  assert.equal(result.stdout.includes("--script-inventory-output <file>"), true);
  assert.equal(result.stdout.includes("--payment-page-headers-from-har <file>"), true);
  assert.equal(result.stdout.includes("--payment-page-headers-baseline <file>"), true);
  assert.equal(result.stdout.includes("--payment-page-headers-output <file>"), true);
  assert.equal(result.stdout.includes("--payment-page-url-pattern <regex>"), true);
  assert.equal(result.stdout.includes("--script-inventory-audit <file>"), true);
  assert.equal(result.stdout.includes("--runtime-inventory-snapshot <file>"), true);
  assert.equal(result.stdout.includes("--script-inventory-audit-output <file>"), true);
  assert.equal(result.stdout.includes("--source-map-evidence <file>"), true);
  assert.equal(result.stdout.includes("--source-map-evidence-output <file>"), true);
  assert.equal(result.stdout.includes("--deployment-hygiene-evidence <file>"), true);
  assert.equal(result.stdout.includes("--deployment-hygiene-output <file>"), true);
  assert.equal(result.stdout.includes("--runtime-incident-evidence <file>"), true);
  assert.equal(result.stdout.includes("--runtime-incident-evidence-output <file>"), true);
  assert.equal(result.stdout.includes("--migration-review"), true);
  assert.equal(result.stdout.includes("--migration-review-output <file>"), true);
  assert.equal(result.stdout.includes("--identifier-cache-review"), true);
  assert.equal(result.stdout.includes("--identifier-cache-review-output <file>"), true);
  assert.equal(result.stdout.includes("--runtime-defense-review"), true);
  assert.equal(result.stdout.includes("--runtime-defense-review-output <file>"), true);
  assert.equal(result.stdout.includes("--vm-proof-pack <file>"), true);
  assert.equal(result.stdout.includes("--vm-proof-output <file>"), true);
  assert.equal(result.stdout.includes("--ai-resistance-evidence-output <file>"), true);
  assert.equal(result.stderr, "");
});

test("CLI explains compatibility options and local-only guidance", async () => {
  const mapped = JSON.parse((await runCli(["--explain-compat", "parse-html", "--json"], "")).stdout);
  assert.equal(mapped.status, "mapped");
  assert.equal(mapped.target.includes("parseHtml"), true);

  const domainLock = JSON.parse((await runCli(["--explain-compat", "domain-lock", "--json"], "")).stdout);
  assert.equal(domainLock.status, "mapped");
  assert.equal(domainLock.target.includes("LockDomainList"), true);

  const review = JSON.parse((await runCli(["--explain-compat", "self-defending", "--json"], "")).stdout);
  assert.equal(review.status, "mapped");
  assert.equal(review.target.includes("SelfDefending"), true);

  const ignoreImports = JSON.parse((await runCli(["--explain-compat", "ignore-imports", "--json"], "")).stdout);
  assert.equal(ignoreImports.status, "mapped");
  assert.equal(ignoreImports.target.includes("ignoreImports"), true);

  const indexTypes = JSON.parse((await runCli(["--explain-compat", "string-array-indexes-type", "--json"], "")).stdout);
  assert.equal(indexTypes.status, "mapped");
  assert.equal(indexTypes.target.includes("StringArrayIndexesType"), true);

  const strictMode = JSON.parse((await runCli(["--explain-compat", "strict-mode", "--json"], "")).stdout);
  assert.equal(strictMode.status, "review-only");
  assert.equal(strictMode.option, "strictMode");

  const identifiersPrefix = JSON.parse((await runCli(["--explain-compat", "identifiers-prefix", "--json"], "")).stdout);
  assert.equal(identifiersPrefix.status, "review-only");
  assert.equal(identifiersPrefix.option, "identifiersPrefix");

  const local = JSON.parse((await runCli(["--local-only", "--json"], "")).stdout);
  // These assertions used to pin the pre-publication story: not on npm, source
  // can never stay local. Both became false - the package is published and
  // --local protects on-device - and the guidance kept printing them to users.
  assert.equal(local.npmPublished, true);
  assert.equal(local.packageDistribution, "npm");
  assert.equal(local.sourceLeavesMachineByDefault, true);
  assert.equal(local.sourceCanStayLocal, true);
  assert.equal(local.localProtectionFlag, "--local");
  assert.equal(local.installCommands.some((command) => command === "npm install --save-dev jso-protector"), true);
  assert.equal(local.localProtectionCommands.some((command) => command.includes("--local")), true);
  assert.equal(local.message.includes("VM bytecode protection remains a hosted step"), true);
  assert.equal(local.offlinePreflightCommands.some((command) => command.includes("--competitor-gap-report --json")), true);
  assert.equal(local.offlinePreflightCommands.some((command) => command.includes("--source-map-evidence")), true);
  assert.equal(local.offlinePreflightCommands.some((command) => command.includes("--runtime-incident-evidence")), true);
  assert.equal(local.message.includes("keeps source on-device"), true);
  assert.equal(local.message.includes("online entitlement check"), true);
});

test("CLI explains JS-Confuser compatibility options", async () => {
  const mapped = JSON.parse((await runCli(["--explain-js-confuser-compat", "lock.endDate", "--json"], "")).stdout);
  assert.equal(mapped.status, "mapped");
  assert.equal(mapped.target.includes("LockDateValue"), true);

  const integrity = JSON.parse((await runCli(["--explain-js-confuser-compat", "lock.integrity", "--json"], "")).stdout);
  assert.equal(integrity.status, "mapped");
  assert.equal(integrity.target.includes("SelfDefending"), true);
});

test("CLI prints resolved config with credentials redacted", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    apiKey: "secret-key",
    apiPassword: "secret-password",
    input: "dist",
    output: "protected",
    parseHtml: true,
    honorConditionalComments: true,
    ignoreImports: true,
    options: { LockDomain: true }
  }, null, 2));

  const result = await runCli(["--config", configPath, "--print-config", "--json"], "");
  const printed = JSON.parse(result.stdout);
  assert.equal(printed.apiKey, "[set]");
  assert.equal(printed.apiPassword, "[set]");
  assert.equal(result.stdout.includes("secret"), false);
  assert.equal(printed.parseHtml, true);
  assert.equal(printed.honorConditionalComments, true);
  assert.equal(printed.ignoreImports, true);
  assert.equal(printed.options.LockDomain, true);
});

test("CLI text print-config includes safety toggles", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    input: "dist",
    output: "protected",
    parseHtml: true,
    honorConditionalComments: true,
    protectMarkedComments: true,
    ignoreImports: true
  }, null, 2));

  const oldKey = process.env.JSO_API_KEY;
  const oldPassword = process.env.JSO_API_PASSWORD;
  process.env.JSO_API_KEY = "env-key";
  process.env.JSO_API_PASSWORD = "env-password";

  try {
    const result = await runCli(["--config", configPath, "--print-config"], "");
    assert.equal(result.stdout.includes("parseHtml: true"), true);
    assert.equal(result.stdout.includes("honorConditionalComments: true"), true);
    assert.equal(result.stdout.includes("protectMarkedComments: true"), true);
    assert.equal(result.stdout.includes("ignoreImports: true"), true);
  } finally {
    restoreEnv("JSO_API_KEY", oldKey);
    restoreEnv("JSO_API_PASSWORD", oldPassword);
  }
});

test("runDoctor checks config without calling the API by default", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('doctor');");
  fs.writeFileSync(path.join(input, "index.html"), "<script src=\"app.js\"></script>");

  const config = cli.mergeConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    extensions: [".js"],
    copyAssets: true
  }, {});

  const report = await cli.runDoctor(config, {});
  assert.equal(report.ok, true);
  assert.deepEqual(report.files, ["app.js"]);
  assert.deepEqual(report.assets, ["index.html"]);
  assert.equal(report.checks.find((check) => check.name === "api").message.includes("skipped"), true);
});

test("runReleaseCheck combines validation plan and doctor without calling the API", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release');");
  fs.writeFileSync(path.join(input, "style.css"), "body{}");

  const report = await cli.runReleaseCheck({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    copyAssets: true,
    manifest: "protected/jso-manifest.json",
    maxGrowthRatio: 8
  }, {});

  assert.equal(report.format, "jso-protector-release-check");
  assert.equal(report.ok, true);
  assert.equal(report.checkApi, false);
  assert.equal(report.validation.ok, true);
  assert.deepEqual(report.plan.files, ["app.js"]);
  assert.deepEqual(report.plan.assets, ["style.css"]);
  assert.equal(report.plan.maxGrowthRatio, 8);
  assert.equal(report.doctor.ok, true);
  assert.equal(report.doctor.checks.find((check) => check.name === "api").message.includes("skipped"), true);
});

test("CLI release-check prints redacted JSON preflight report", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const configPath = path.join(root, "jso.config.json");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release-check');");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "secret-key",
    apiPassword: "secret-password",
    input: "dist",
    output: "protected",
    sourceMap: true,
    identifierNamesCachePath: ".cache.json"
  }, null, 2));

  const result = await runCli(["--config", configPath, "--release-check", "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.plan.files.includes("app.js"), true);
  assert.equal(report.doctor.ok, true);
  assert.equal(report.validation.limitations.some((item) => item.id === "source-maps"), true);
  assert.equal(report.validation.limitations.some((item) => item.id === "identifier-name-cache"), true);
  assert.equal(report.doctor.limitations.some((item) => item.id === "source-maps"), true);
  assert.equal(result.stdout.includes("secret"), false);
});

test("CLI dry-run JSON includes transformed API item summary", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const configPath = path.join(root, "jso.config.json");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "index.html"), "<script data-javascript-obfuscator>console.log('secret');</script>");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "password",
    input: "dist",
    output: "protected",
    parseHtml: true
  }, null, 2));

  const result = await runCli(["--config", configPath, "--dry-run", "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.files, ["index.html"]);
  assert.equal(report.processing.apiItems, 1);
  assert.equal(report.processing.transformedFiles[0].fileName, "index.html");
});

test("release-check reports protected-region parser errors before API use", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), [
    "console.log('release-check');",
    "// javascript-obfuscator:disable",
    "console.log('plain');"
  ].join("\n"));

  const report = await cli.runReleaseCheck({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "password",
    input: "dist",
    output: "protected",
    honorConditionalComments: true
  }, {});

  assert.equal(report.ok, false);
  assert.equal(report.plan.ok, false);
  assert.equal(report.plan.error.includes("app.js:2:1"), true);
  assert.equal(report.doctor.ok, false);
  assert.equal(report.doctor.checks.some((check) => check.message.includes("app.js:2:1")), true);
});

test("release-check reports invalid marked HTML scripts before API use", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "index.html"), "<script data-javascript-obfuscator src=\"app.js\"></script>");

  const report = await cli.runReleaseCheck({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "password",
    input: "dist",
    output: "protected",
    parseHtml: true
  }, {});

  assert.equal(report.ok, false);
  assert.equal(report.plan.ok, false);
  assert.equal(report.plan.error.includes("index.html:1:1"), true);
  assert.equal(report.plan.error.includes("external script"), true);
});

test("CLI release-check strict mode fails validation warnings", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const configPath = path.join(root, "jso.config.json");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('strict');");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "password",
    input: "dist",
    output: "protected",
    stringArrayThreshold: 0,
    deadCodeInjectionThreshold: 0,
    options: {
      EncodeStrings: true,
      TypoOption: true
    }
  }, null, 2));

  await assert.rejects(
    () => runCli(["--config", configPath, "--release-check", "--strict", "--json"], ""),
    /release check failed/
  );
});

test("validateProtectionConfig reports malformed fields and unknown options", () => {
  const root = makeTempDir();
  const valid = cli.validateProtectionConfig({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    options: {
      EncodeStrings: true,
      TypoOption: true
    }
  }, {});

  assert.equal(valid.ok, true);
  assert.equal(valid.checks.some((check) => check.level === "warning" && check.message.includes("TypoOption")), true);
  assert.equal(valid.checks.some((check) => check.name === "credentialStorage" && check.level === "warning" && check.message.includes("$JSO_API_KEY")), true);

  const strict = cli.validateProtectionConfig({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    options: {
      EncodeStrings: true,
      TypoOption: true
    }
  }, { strict: true });

  assert.equal(strict.ok, false);
  assert.equal(strict.strict, true);
  assert.equal(strict.warnings, 3);

  const envCredentials = cli.validateProtectionConfig({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    input: "dist",
    output: "protected",
    options: {
      EncodeStrings: true
    }
  }, {});

  assert.equal(envCredentials.checks.some((check) => check.name === "credentialStorage" && check.level === "ok"), true);

  const invalid = cli.validateProtectionConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    include: "app.js"
  }, {});

  assert.equal(invalid.ok, false);
  assert.equal(invalid.checks[0].level, "error");
  assert.match(invalid.checks[0].message, /include must be an array/);
});

test("validateProtectionConfig rejects active-scheme runtime redirects", () => {
  const root = makeTempDir();
  const base = {
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: ".",
    output: "protected",
    options: { RuntimeDefenseAction: "redirect", RuntimeDefenseRedirectUrl: "javascript:alert(1)" }
  };
  const bad = cli.validateProtectionConfig(base, {});
  assert.equal(bad.ok, false);
  assert.equal(bad.checks.some((check) => check.name === "runtimeDefenseRedirect" && check.level === "error"), true);
  const good = cli.validateProtectionConfig({ ...base, options: { ...base.options, RuntimeDefenseRedirectUrl: "/blocked" } }, {});
  assert.equal(good.checks.some((check) => check.name === "runtimeDefenseRedirect" && check.level === "ok"), true);
  const badDomain = cli.validateProtectionConfig({ ...base, options: {}, domainLockRedirectUrl: "data:text/html,bad" }, {});
  assert.equal(badDomain.ok, false);
  assert.equal(badDomain.checks.some((check) => check.name === "config" && check.level === "error" && /HTTP\(S\)/.test(check.message)), true);
});

test("CLI validates config as JSON without calling the API", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    options: {
      EncodeStrings: true,
      TypoOption: true
    }
  }, null, 2));

  const result = await runCli(["--config", configPath, "--validate-config", "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.checks.some((check) => check.level === "warning" && check.message.includes("TypoOption")), true);
});

test("CLI validates config-level javascript-obfuscator compatibility fields", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    input: "dist",
    output: "protected",
    optionsPreset: "medium-obfuscation",
    domainLock: ["example.com", "app.example.com"],
    stringArray: true,
    stringArrayEncoding: ["rc4"],
    controlFlowFlattening: true,
    identifierNamesGenerator: "hexadecimal",
    parseHtml: true
  }, null, 2));

  const oldKey = process.env.JSO_API_KEY;
  const oldPassword = process.env.JSO_API_PASSWORD;
  process.env.JSO_API_KEY = "env-key";
  process.env.JSO_API_PASSWORD = "env-password";

  try {
    const result = await runCli(["--config", configPath, "--print-config", "--json"], "");
    const report = JSON.parse(result.stdout);
    assert.equal(report.preset, "balanced");
    assert.equal(report.parseHtml, true);
    assert.equal(report.options.LockDomain, true);
    assert.equal(report.options.LockDomainList, "example.com\napp.example.com");
    assert.equal(report.options.MoveStrings, true);
    assert.equal(report.options.EncryptStrings, true);
    assert.equal(report.options.DeepObfuscate, true);
    assert.equal(report.options.FlatTransform, true);
    assert.equal(report.options.IdentityStyle, "v1hex");
  } finally {
    restoreEnv("JSO_API_KEY", oldKey);
    restoreEnv("JSO_API_PASSWORD", oldPassword);
  }
});

test("scanCompatibilityRisks finds common reflection hazards", () => {
  const report = cli.scanTextCompatibilityRisks("app.js", [
    "if (widget.constructor.name === 'Widget') console.log('x');",
    "console.log(Function.prototype.toString.call(run));",
    "console.log(run.name);"
  ].join("\n"));

  assert.equal(report.length, 3);
  assert.deepEqual(report.map((entry) => entry.ruleId), [
    "function-source-reflection",
    "constructor-name-reflection",
    "name-reflection"
  ]);
  assert.deepEqual(report.map((entry) => entry.line), [2, 1, 3]);
});

test("scanCompatibilityRisks identifies browser globals that global renaming must preserve", () => {
  const report = cli.scanTextCompatibilityRisks("vendor.js", [
    "/*! pinned vendor build */",
    "var luxon = (function () { return {}; }());",
    "window.PublicSDK = luxon;"
  ].join("\n"));

  assert.deepEqual(report.map((entry) => entry.ruleId), [
    "classic-script-public-global",
    "assigned-public-global"
  ]);
  assert.deepEqual(report.map((entry) => entry.publicGlobalName), ["luxon", "PublicSDK"]);
  assert.deepEqual(report.map((entry) => entry.suggestedVariableExclusion), ["^luxon$", "^PublicSDK$"]);
  assert.deepEqual(report.map((entry) => entry.line), [2, 3]);
});

test("CLI compat-scan reports findings as JSON", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log(handler.name);", "utf8");
  fs.writeFileSync(path.join(input, "safe.js"), "console.log('safe');", "utf8");

  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "$JSO_API_KEY",
    apiPassword: "$JSO_API_PASSWORD",
    input,
    output: path.join(root, "protected")
  }, null, 2));

  const oldKey = process.env.JSO_API_KEY;
  const oldPassword = process.env.JSO_API_PASSWORD;
  process.env.JSO_API_KEY = "env-key";
  process.env.JSO_API_PASSWORD = "env-password";

  try {
    const result = await runCli(["--config", configPath, "--compat-scan", "--json"], "");
    const report = JSON.parse(result.stdout);
    assert.equal(report.format, "jso-protector-compatibility-scan");
    assert.equal(report.summary.files, 2);
    assert.equal(report.summary.findings, 1);
    assert.equal(report.findings[0].fileName, "app.js");
    assert.equal(report.findings[0].line, 1);
  } finally {
    restoreEnv("JSO_API_KEY", oldKey);
    restoreEnv("JSO_API_PASSWORD", oldPassword);
  }
});

test("doctor includes compatibility scan guidance", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log(component.constructor.name);", "utf8");

  const report = await cli.runDoctor({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input,
    output: path.join(root, "protected"),
    preset: "balanced",
    extensions: [".js"],
    markupExtensions: [".html"],
    exclude: ["**/*.map"],
    include: [],
    assetExclude: ["**/*.map"],
    copyAssets: true,
    options: { EncodeStrings: true }
  }, {});

  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("Run --compat-scan --json for details")), true);
});

test("CLI maps runtime-defense fields while warning on remaining review-only fields", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    identifiersDictionary: ["alpha", "beta"],
    identifiersPrefix: "release_",
    selfDefending: true,
    reservedStrings: ["^LICENSE$"],
    seed: 42,
    sourceMap: false,
    strictMode: null,
    splitStrings: true,
    splitStringsChunkLength: 8,
    stringArrayIndexShift: true
  }, null, 2));

  const result = await runCli(["--config", configPath, "--validate-config", "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("selfDefending")), false);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("identifiersDictionary")), true);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("identifiersPrefix")), true);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("reservedStrings")), false);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("strictMode")), true);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("stringArrayIndexShift")), false);
});

test("validateProtectionConfig rejects invalid review-only compatibility field types", () => {
  const root = makeTempDir();
  const report = cli.validateProtectionConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    identifiersDictionary: "alpha",
    reservedStrings: "LICENSE",
    strictMode: "auto",
    stringArrayIndexShift: true,
    jsConfuserLockIntegrity: -1
  }, {});

  assert.equal(report.ok, false);
  assert.equal(report.checks[0].level, "error");
  assert.match(report.checks[0].message, /identifiersDictionary must be an array/);

  const indexShiftReport = cli.validateProtectionConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    stringArrayIndexShift: "true"
  }, {});

  assert.equal(indexShiftReport.ok, false);
  assert.equal(indexShiftReport.checks[0].level, "error");
  assert.match(indexShiftReport.checks[0].message, /stringArrayIndexShift must be a boolean/);
});

test("migrateJavascriptObfuscatorConfig maps common source options", () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "javascript-obfuscator.json");
  fs.writeFileSync(sourcePath, JSON.stringify({
    compact: true,
    controlFlowFlattening: true,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.7,
    domainLock: ["example.com", "app.example.com"],
    identifiersDictionary: ["alpha", "beta"],
    identifiersPrefix: "release_",
    identifierNamesGenerator: "hexadecimal",
    identifierNamesCache: {},
	seed: "release-42",
	reservedStrings: ["^PUBLIC_", "LICENSE$"],
	forceTransformStrings: ["^FORCED_"],
    numbersToExpressions: true,
    optionsPreset: "high-obfuscation",
    renameGlobals: true,
    reservedNames: ["^PublicApi$"],
    selfDefending: true,
    strictMode: true,
    stringArray: true,
    stringArrayEncoding: ["rc4"],
    stringArrayIndexShift: true,
    stringArrayShuffle: true,
    stringArrayRotate: true,
    stringArrayIndexesType: ["hexadecimal-number", "hexadecimal-numeric-string"],
    stringArrayThreshold: 0.5,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.75,
    stringArrayWrappersCount: 3,
    stringArrayWrappersChainedCalls: false,
    stringArrayWrappersParametersMaxCount: 5,
    stringArrayWrappersType: "function",
    transformObjectKeys: true,
    target: "browser",
    unknownSetting: true
  }, null, 2));

  const report = cli.migrateJavascriptObfuscatorConfig(sourcePath, {
    input: "build",
    output: "protected"
  });

  assert.equal(report.format, "jso-protector-migration");
  assert.equal(report.config.input, "build");
  assert.equal(report.config.output, "protected");
  assert.equal(report.config.preset, "maximum");
  assert.equal(report.summary.sourceOptions, 34);
  assert.equal(report.summary.mappedOptions, 29);
  assert.equal(report.summary.reviewOnly, 4);
  assert.equal(report.summary.unmapped, 1);
  assert.equal(report.summary.automaticCoverage, 0.8529);
  assert.equal(report.config.options.MoveStrings, true);
  assert.equal(report.config.options.StringArrayIndexShift, true);
  assert.equal(report.config.options.StringArrayShuffle, true);
  assert.equal(report.config.options.StringArrayRotate, true);
  assert.equal(report.config.options.StringArrayIndexesType, "hexadecimal-number\nhexadecimal-numeric-string");
  assert.equal(report.config.options.StringArrayThreshold, 0.5);
  assert.equal(report.config.options.StringArrayCallsTransform, true);
  assert.equal(report.config.options.StringArrayCallsTransformThreshold, 0.75);
  assert.equal(report.config.options.StringArrayWrappersCount, 3);
  assert.equal(report.config.options.StringArrayWrappersChainedCalls, false);
  assert.equal(report.config.options.StringArrayWrappersParametersMaxCount, 5);
  assert.equal(report.config.options.StringArrayWrappersType, "function");
  assert.equal(report.config.options.TransformObjectKeys, true);
  assert.equal(report.config.options.EncryptStrings, true);
  assert.equal(report.config.options.Seed, "release-42");
	assert.equal(report.config.options.ReservedStrings, "^PUBLIC_\nLICENSE$");
	assert.equal(report.config.options.ForceTransformStrings, "^FORCED_");
	assert.equal(report.config.options.EncodeNumbers, true);
	assert.equal(report.review.some((item) => item.option === "seed"), false);
  assert.equal(report.config.options.FlatTransform, true);
  assert.equal(report.config.options.DeepObfuscate, true);
  assert.equal(report.config.options.AddDeadCode, true);
  assert.equal(report.config.options.DeadcodeLevel, "High");
  assert.equal(report.config.options.IdentityStyle, "v1hex");
  assert.equal(report.config.options.LockDomain, true);
  assert.equal(report.config.options.LockDomainList, "example.com\napp.example.com");
  assert.equal(report.config.options.SelfDefending, true);
  assert.deepEqual(report.config.reservedNames, ["^PublicApi$"]);
  assert.equal(report.mapped.some((item) => item.from === "optionsPreset" && item.to === "preset"), true);
  assert.equal(report.mapped.some((item) => item.from === "domainLock" && item.to === "LockDomainList"), true);
  assert.equal(report.mapped.some((item) => item.from === "selfDefending" && item.to === "SelfDefending"), true);
  assert.equal(report.review.some((item) => item.option === "selfDefending"), false);
  assert.equal(report.review.some((item) => item.option === "identifiersDictionary"), true);
  assert.equal(report.review.some((item) => item.option === "identifiersPrefix"), true);
  assert.equal(report.review.some((item) => item.option === "identifierNamesCache"), true);
  assert.equal(report.review.some((item) => item.option === "strictMode"), true);
  assert.equal(report.review.some((item) => item.option === "stringArrayIndexShift"), false);
  assert.equal(report.review.some((item) => item.option === "stringArrayShuffle"), false);
  assert.equal(report.review.some((item) => item.option === "stringArrayRotate"), false);
  assert.equal(report.review.some((item) => item.option === "stringArrayIndexesType"), false);
  assert.deepEqual(report.unmapped, ["unknownSetting"]);
  assert.equal(report.nextCommands.some((item) => item.label === "validate" && item.command.includes("--validate-config --json")), true);
  assert.equal(report.nextCommands.some((item) => item.label === "release-check" && item.command.includes("--release-check --json")), true);
  assert.equal(report.nextCommands.some((item) => item.label === "competitor-gap" && item.command.includes("--competitor-gap-report --json")), true);
  assert.equal(report.nextCommands.some((item) => item.label === "migration-review" && item.command.includes("--migration-review-output reports/migration-review.md")), true);
  assert.equal(report.nextCommands.some((item) => item.label === "identifier-cache-review" && item.command.includes("--identifier-cache-review-output reports/identifier-cache-review.md")), true);
  assert.equal(report.nextCommands.some((item) => item.label === "runtime-defense-review"), false);
  assert.equal(report.nextCommands.some((item) => item.label === "protect" && item.command.includes("--manifest dist-protected/jso-manifest.json")), true);
});

test("migrateJavascriptObfuscatorConfig loads trusted CommonJS source configs", () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "javascript-obfuscator.config.cjs");
  const oldPreset = process.env.JSO_COMPAT_PRESET;
  process.env.JSO_COMPAT_PRESET = "medium-obfuscation";
  fs.writeFileSync(sourcePath, `
module.exports = ({ env }) => ({
  optionsPreset: env.JSO_COMPAT_PRESET,
  stringArray: true,
  stringArrayEncoding: ["rc4"],
  reservedNames: ["^KeepMe$"],
  sourceMap: false
});
`, "utf8");

  try {
    const report = cli.migrateJavascriptObfuscatorConfig(sourcePath, {});
    assert.equal(report.config.preset, "balanced");
    assert.equal(report.config.options.MoveStrings, true);
    assert.equal(report.config.options.EncryptStrings, true);
    assert.deepEqual(report.config.reservedNames, ["^KeepMe$"]);
    assert.equal(report.summary.sourceOptions, 5);
    assert.equal(report.summary.mappedOptions, 4);
    assert.equal(report.summary.reviewOnly, 1);
    assert.equal(report.nextCommands.some((item) => item.label === "migration-review" && item.command.includes("--migration-review-output reports/migration-review.md")), true);
    assert.equal(report.nextCommands.some((item) => item.label === "identifier-cache-review"), false);
    assert.equal(report.nextCommands.some((item) => item.label === "runtime-defense-review"), false);
    assert.equal(report.nextCommands.some((item) => item.label === "source-map-evidence" && item.command.includes("--source-map-evidence-output reports/source-map-evidence.md")), true);
  } finally {
    restoreEnv("JSO_COMPAT_PRESET", oldPreset);
  }
});

test("migrateJavascriptObfuscatorConfig maps VM preset aliases", () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "javascript-obfuscator.json");
  fs.writeFileSync(sourcePath, JSON.stringify({
    optionsPreset: "vm-anti-llm",
    stringArray: true
  }, null, 2));

  const report = cli.migrateJavascriptObfuscatorConfig(sourcePath, {});
  assert.equal(report.config.preset, "maximum");
  assert.equal(report.config.options.MoveStrings, true);
  assert.equal(report.summary.mappedOptions, 2);
});

test("migrateJsConfuserConfig maps common source options", () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "js-confuser.config.json");
  fs.writeFileSync(sourcePath, JSON.stringify({
    preset: "high",
    target: "node",
    renameVariables: true,
    renameGlobals: true,
    stringEncoding: true,
    stringConcealing: true,
    duplicateLiteralsRemoval: true,
    stringSplitting: 0.5,
    stringCompression: true,
    controlFlowFlattening: true,
    deadCode: true,
    identifierGenerator: "hexadecimal",
    hexadecimalNumbers: true,
    lock: {
      domainLock: ["example.com", "app.example.com"],
      endDate: "2026-05-31",
      integrity: true,
      startDate: "2026-05-01"
    },
    shuffle: true,
    unknownSetting: true
  }, null, 2));

  const report = cli.migrateJsConfuserConfig(sourcePath, {
    input: "build",
    output: "protected"
  });

  assert.equal(report.format, "jso-protector-migration");
  assert.equal(report.config.input, "build");
  assert.equal(report.config.output, "protected");
  assert.equal(report.config.preset, "maximum");
  assert.equal(report.summary.sourceOptions, 19);
  assert.equal(report.summary.mappedOptions, 17);
  assert.equal(report.summary.reviewOnly, 1);
  assert.equal(report.summary.unmapped, 1);
  assert.equal(report.summary.automaticCoverage, 0.8947);
  assert.equal(report.config.options.OptimizationMode, "NodeJS");
  assert.equal(report.config.options.ReplaceNames, true);
  assert.equal(report.config.options.RenameGlobals, true);
  assert.equal(report.config.options.EncodeStrings, true);
  assert.equal(report.config.options.EncryptStrings, true);
  assert.equal(report.config.options.MoveStrings, true);
  assert.equal(report.config.options.SplitStrings, true);
  assert.equal(report.config.options.SelfCompression, true);
  assert.equal(report.config.options.FlatTransform, true);
  assert.equal(report.config.options.DeepObfuscate, true);
  assert.equal(report.config.options.AddDeadCode, true);
  assert.equal(report.config.options.IdentityStyle, "v1hex");
  assert.equal(report.config.options.EncodeNumbers, true);
  assert.equal(report.config.options.LockDomain, true);
  assert.equal(report.config.options.LockDomainList, "example.com\napp.example.com");
  assert.equal(report.config.options.LockDate, true);
  assert.equal(report.config.options.LockDateValue, "20260531");
  assert.equal(report.config.options.LockStartDate, true);
  assert.equal(report.config.options.LockStartDateValue, "20260501");
  assert.equal(report.config.options.SelfDefending, true);
  assert.equal(report.review.some((item) => item.option === "lock.integrity"), false);
  assert.equal(report.review.some((item) => item.option === "lock.startDate"), false);
  assert.equal(report.review.some((item) => item.option === "shuffle"), true);
  assert.equal(report.nextCommands.some((item) => item.label === "migration-review" && item.command.includes("--migration-review-output reports/migration-review.md")), true);
  assert.equal(report.nextCommands.some((item) => item.label === "runtime-defense-review"), false);
  assert.deepEqual(report.unmapped, ["unknownSetting"]);
});

test("CLI maps legacy JS-Confuser runtime fields without review warnings", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    jsConfuserLockIntegrity: true,
    jsConfuserLockStartDate: "20260501",
    jsConfuserLockTamperProtection: 1
  }, null, 2));

  const result = await runCli(["--config", configPath, "--validate-config", "--json"], "");
  const report = JSON.parse(result.stdout);
	const merged = cli.mergeConfig(JSON.parse(fs.readFileSync(configPath, "utf8")), {});
  assert.equal(report.ok, true);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("jsConfuserLockIntegrity")), false);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("jsConfuserLockTamperProtection")), false);
  assert.equal(merged.options.SelfDefending, true);
  assert.equal(merged.options.LockStartDateValue, "20260501");
  assert.equal(merged.options.AntiMonkeyPatching, true);
});

test("CLI migrates JS-Confuser config as JSON", async () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "js-confuser.config.json");
  fs.writeFileSync(sourcePath, JSON.stringify({
    renameVariables: true,
    lock: {
      endDate: "2026-05-31",
      countermeasures: "panic"
    }
  }, null, 2));

  const result = await runCli(["--migrate-js-confuser", sourcePath, "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "jso-protector-migration");
  assert.equal(report.summary.sourceOptions, 3);
  assert.equal(report.summary.mappedOptions, 2);
  assert.equal(report.config.options.ReplaceNames, true);
  assert.equal(report.config.options.LockDateValue, "20260531");
  assert.equal(report.config.jsConfuserLockCountermeasures, "panic");
});

test("CLI migrates javascript-obfuscator config as JSON", async () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "javascript-obfuscator.json");
  fs.writeFileSync(sourcePath, JSON.stringify({
    stringArray: true,
    reservedNames: ["^KeepMe$"]
  }, null, 2));

  const result = await runCli(["--migrate-javascript-obfuscator", sourcePath, "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "jso-protector-migration");
  assert.equal(report.summary.sourceOptions, 2);
  assert.equal(report.summary.mappedOptions, 2);
  assert.equal(report.summary.unmapped, 0);
  assert.equal(report.config.options.MoveStrings, true);
  assert.deepEqual(report.config.reservedNames, ["^KeepMe$"]);
  assert.equal(report.nextCommands[0].command, "jso-protector --config jso.config.json --validate-config --json");
  assert.equal(report.nextCommands.some((item) => item.label === "competitor-gap"), true);
});

test("CLI migration report prints summary for humans", async () => {
  const root = makeTempDir();
  const sourcePath = path.join(root, "javascript-obfuscator.json");
  const outputPath = path.join(root, "jso.config.json");
  fs.writeFileSync(sourcePath, JSON.stringify({
    stringArray: true,
    selfDefending: true,
    unknownSetting: true
  }, null, 2));

  const result = await runCli(["--migrate-javascript-obfuscator", sourcePath, "--output", outputPath], "");

  assert.equal(fs.existsSync(outputPath), true);
  assert.equal(result.stderr.includes("Migration summary:"), true);
  assert.equal(result.stderr.includes("1 unmapped"), true);
  assert.equal(result.stderr.includes("Next commands:"), true);
  assert.equal(result.stderr.includes("--validate-config --json"), true);
  assert.equal(result.stderr.includes("--dry-run --json"), true);
});

test("runDoctor reports missing input as failure", async () => {
  const root = makeTempDir();
  const config = cli.mergeConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "missing",
    output: "protected"
  }, {});

  const report = await cli.runDoctor(config, {});
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((check) => check.name === "input").ok, false);
});

test("validateProtectionConfig groups competitor migration limitations", () => {
  const root = makeTempDir();
  const report = cli.validateProtectionConfig({
    __configDir: root,
    endpoint: "https://example.test/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    sourceMap: true,
    identifierNamesCache: {},
    identifiersPrefix: "release_",
    selfDefending: true
  }, {});

  assert.equal(report.limitations.some((item) => item.id === "source-maps"), true);
  assert.equal(report.limitations.some((item) => item.id === "identifier-name-cache"), true);
  assert.equal(report.limitations.some((item) => item.id === "custom-identifier-dictionary"), true);
  assert.equal(report.limitations.some((item) => item.id === "runtime-self-defending"), false);
});

test("buildCompetitorGapReport summarizes covered and gap capabilities", () => {
  const report = cli.buildCompetitorGapReport({
    sourceMap: true,
    identifierNamesCachePath: ".jso-cache.json",
    debugProtection: true,
    selfDefending: true
  }, {});

  assert.equal(report.summary.capabilities >= 6, true);
  assert.equal(report.summary.covered > 0, true);
  assert.equal(report.summary.gaps > 0, true);
  const runtimeDefense = report.capabilities.find((item) => item.id === "runtime-defense");
  assert.equal(runtimeDefense.status, "partial");
  assert.match(runtimeDefense.jsoSupport, /hosted dashboard intake/);
  assert.equal(runtimeDefense.evidence.includes("RuntimeDefenseBeaconUrl"), true);
  assert.equal(runtimeDefense.evidence.includes("dashboard-monitoring"), true);
  assert.equal(report.sourceSnapshot.reviewedOn, "2026-08-02");
  assert.equal(report.sourceSnapshot.sources.some((source) => source.competitor === "Obfuscator.io" && /pricing/.test(source.url)), true);
  assert.equal(report.sourceSnapshot.sources.some((source) => source.competitor === "javascript-obfuscator"), true);
  assert.equal(report.sourceSnapshot.sources.some((source) => source.competitor === "AfterPack"), true);
  assert.equal(report.capabilities.some((item) => item.id === "vm-bytecode" && item.status === "partial" && item.evidence.includes("vm-proof-pack-report")), true);
  assert.equal(report.capabilities.some((item) => item.id === "vm-runtime-hardening" && /stateful-opcode/.test(item.jsoSupport)), true);
  assert.match(report.sourceSnapshot.claimBoundary, /Re-check current vendor pages/);
  assert.equal(report.limitations.some((item) => item.id === "source-maps"), true);
  assert.equal(report.limitations.some((item) => item.id === "runtime-self-defending"), false);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "migration-review" && item.command.includes("--migration-review") && item.sourceFree === true), true);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "source-map-evidence" && item.command.includes("--source-map-evidence")), true);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "identifier-cache-replacement-review" && item.command.includes("--identifier-cache-review") && item.sourceFree === true), true);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "runtime-defense-review"), false);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "runtime-compatibility-scan"), false);
  assert.equal(report.sourceBoundary.sourceFree, true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.match(report.reviewAssistant.intendedUse, /BYO AI key/);
  assert.equal(report.reviewAssistant.doNotInclude.includes("API keys or passwords"), true);
  assert.equal(report.reviewAssistant.doNotInclude.includes("raw compatibility scan source snippets"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Gap prioritization"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Partial parity validation"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Triggered migration limitations"), true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Source-reading scan boundary"), false);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Vendor claim freshness"), true);
  assert.equal(report.capabilities.find((item) => item.id === "runtime-defense").jsoSupport.includes("map directly"), true);
  assert.equal(report.recommendedPlan.some((item) => /reserved-name reviews/.test(item)), true);
});

test("CLI --competitor-gap-report emits JSON parity report", async () => {
  const root = makeTempDir();
  const configPath = path.join(root, "jso.config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    sourceMap: true,
    lock: undefined,
    selfDefending: true
  }), "utf8");

  const result = await runCliInCwd(root, ["--config", configPath, "--competitor-gap-report", "--json"], "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "jso-protector-competitor-gap-report");
  assert.equal(report.version, 1);
  assert.equal(report.competitors.includes("Obfuscator.io"), true);
  assert.equal(report.competitors.includes("Jscrambler"), true);
  assert.equal(report.sourceSnapshot.reviewedOn, "2026-08-02");
  assert.equal(report.sourceSnapshot.sources.some((source) => source.competitor === "Jscrambler"), true);
  assert.equal(report.capabilities.some((item) => item.id === "runtime-defense"), true);
  assert.equal(report.limitations.some((item) => item.id === "runtime-self-defending"), false);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "migration-review"), true);
  assert.equal(report.reviewArtifacts.some((item) => item.id === "source-map-evidence"), true);
  assert.equal(report.reviewAssistant.sourceFree, true);
  assert.equal(report.reviewAssistant.questions.some((item) => item.topic === "Vendor claim freshness"), true);

  const textResult = await runCliInCwd(root, ["--config", configPath, "--competitor-gap-report"], "");
  assert.equal(textResult.stdout.includes("sources reviewed: 2026-08-02"), true);
  assert.equal(textResult.stdout.includes("Re-check current vendor pages"), true);
  assert.equal(textResult.stdout.includes("Review artifacts:"), true);
  assert.equal(textResult.stdout.includes("Review assistant:"), true);
  assert.equal(textResult.stdout.includes("BYO AI key"), true);
  assert.equal(textResult.stdout.includes("Vendor claim freshness"), true);
  assert.equal(textResult.stdout.includes("--migration-review"), true);
  assert.equal(textResult.stdout.includes("--source-map-evidence"), true);
});

test("example config and schema stay aligned", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "jso.config.schema.json"), "utf8"));
  const example = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "jso.config.example.json"), "utf8"));
  const generated = cli.createExampleConfig();

  assert.equal(schema.properties.preset.enum.includes("balanced"), true);
  assert.equal(example.$schema, "./jso.config.schema.json");
  assert.equal(generated.$schema, "./node_modules/jso-protector/jso.config.schema.json");

  const allowed = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(example)) {
    assert.equal(allowed.has(key), true, `${key} is missing from schema`);
  }
  for (const key of Object.keys(generated)) {
    assert.equal(allowed.has(key), true, `${key} is missing from schema`);
  }
});

test("json files do not contain duplicate keys", () => {
  const root = path.join(__dirname, "..");
  const queue = [root];
  const jsonFiles = [];

  while (queue.length) {
    const current = queue.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules") queue.push(fullPath);
        continue;
      }
      if (/\.json$/i.test(entry.name)) jsonFiles.push(fullPath);
    }
  }

  for (const filePath of jsonFiles) {
    const duplicates = findDuplicateJsonKeys(fs.readFileSync(filePath, "utf8"), filePath);
    assert.deepEqual(duplicates, [], `${filePath} contains duplicate key(s): ${duplicates.join(", ")}`);
  }
});

test("createExampleConfig supports init templates and overrides", () => {
  const nodeTemplate = cli.createExampleConfig({
    template: "node-app",
    input: "build",
    output: "release",
    parseHtml: false,
    options: ["LockDate=true"],
    reservedNames: ["^CliName$"]
  });

  assert.equal(nodeTemplate.projectName, "node-release");
  assert.deepEqual(nodeTemplate.extensions, [".js", ".cjs", ".mjs"]);
  assert.equal(nodeTemplate.copyAssets, false);
  assert.equal(nodeTemplate.ignoreImports, true);
  assert.equal(nodeTemplate.input, "build");
  assert.equal(nodeTemplate.output, "release");
  assert.equal(nodeTemplate.options.OptimizationMode, "NodeJS");
  assert.equal(nodeTemplate.options.LockDate, true);
  assert.deepEqual(nodeTemplate.reservedNames, ["^CliName$"]);
});

test("createExampleConfig supports the electron template", () => {
  const electronTemplate = cli.createExampleConfig({
    template: "electron",
    manifest: "dist-protected/jso-manifest.json"
  });

  assert.equal(electronTemplate.projectName, "electron-release");
  assert.deepEqual(electronTemplate.extensions, [".js", ".cjs", ".mjs"]);
  assert.equal(electronTemplate.copyAssets, true);
  assert.equal(electronTemplate.ignoreImports, true);
  assert.equal(electronTemplate.mixedServer, true);
  assert.equal(electronTemplate.options.OptimizationMode, "NodeJS");
  assert.equal(electronTemplate.manifest, "dist-protected/jso-manifest.json");
});

test("createExampleConfig supports framework init templates", () => {
  const nextTemplate = cli.createExampleConfig({
    template: "nextjs"
  });
  const viteTemplate = cli.createExampleConfig({
    template: "vite"
  });
  const parcelTemplate = cli.createExampleConfig({
    template: "parcel"
  });
  const bunTemplate = cli.createExampleConfig({
    template: "bun"
  });
  const browserifyTemplate = cli.createExampleConfig({
    template: "browserify"
  });
  const webpackTemplate = cli.createExampleConfig({
    template: "webpack"
  });
  const rspackTemplate = cli.createExampleConfig({
    template: "rspack"
  });
  const turbopackTemplate = cli.createExampleConfig({
    template: "turbopack"
  });
  const reactNativeTemplate = cli.createExampleConfig({
    template: "expo"
  });

  assert.equal(nextTemplate.projectName, "nextjs-release");
  assert.equal(nextTemplate.input, ".next/static");
  assert.equal(nextTemplate.output, ".next/static-protected");
  assert.deepEqual(nextTemplate.extensions, [".js"]);
  assert.equal(nextTemplate.copyAssets, true);
  assert.equal(nextTemplate.options.OptimizationMode, "Web");
  assert.equal(nextTemplate.exclude.includes("**/webpack-*.js"), true);

  assert.equal(viteTemplate.projectName, "vite-release");
  assert.equal(viteTemplate.copyAssets, true);
  assert.equal(viteTemplate.options.OptimizationMode, "Web");
  assert.equal(viteTemplate.reservedNames.includes("^import_meta_env$"), true);

  assert.equal(parcelTemplate.projectName, "parcel-release");
  assert.equal(parcelTemplate.copyAssets, true);
  assert.equal(parcelTemplate.options.OptimizationMode, "Web");
  assert.equal(parcelTemplate.reservedNames.includes("^parcelRequire.*$"), true);

  assert.equal(bunTemplate.projectName, "bun-release");
  assert.equal(bunTemplate.copyAssets, true);
  assert.equal(bunTemplate.options.OptimizationMode, "Web");
  assert.deepEqual(bunTemplate.extensions, [".js", ".mjs"]);

  assert.equal(browserifyTemplate.projectName, "browserify-release");
  assert.equal(browserifyTemplate.copyAssets, true);
  assert.equal(browserifyTemplate.options.OptimizationMode, "Web");
  assert.equal(browserifyTemplate.reservedNames.includes("^require$"), true);

  assert.equal(webpackTemplate.projectName, "webpack-release");
  assert.equal(webpackTemplate.copyAssets, true);
  assert.equal(webpackTemplate.options.OptimizationMode, "Web");
  assert.equal(webpackTemplate.reservedNames.includes("^webpackChunk.*$"), true);

  assert.equal(rspackTemplate.projectName, "rspack-release");
  assert.equal(rspackTemplate.copyAssets, true);
  assert.equal(rspackTemplate.options.OptimizationMode, "Web");
  assert.equal(rspackTemplate.reservedNames.includes("^webpackChunk.*$"), true);

  assert.equal(turbopackTemplate.projectName, "turbopack-release");
  assert.equal(turbopackTemplate.input, ".next/static");
  assert.equal(turbopackTemplate.output, ".next/static-protected");
  assert.deepEqual(turbopackTemplate.include, ["chunks/*.js", "chunks/**/*.js"]);
  assert.equal(turbopackTemplate.exclude.includes("**/polyfills-*.js"), true);

  assert.equal(reactNativeTemplate.projectName, "react-native-release");
  assert.equal(reactNativeTemplate.copyAssets, false);
  assert.equal(reactNativeTemplate.ignoreImports, false);
  assert.equal(reactNativeTemplate.options.OptimizationMode, "Mobile");
  assert.deepEqual(reactNativeTemplate.extensions, [".js"]);
});

test("post-build helper planners honor helper-specific defaults and overrides", () => {
  const root = makeTempDir();
  const distRoot = path.join(root, "dist");
  fs.mkdirSync(path.join(distRoot, "vendor"), { recursive: true });
  fs.writeFileSync(path.join(distRoot, "app.js"), "console.log('app');");
  fs.writeFileSync(path.join(distRoot, "vendor", "lib.js"), "console.log('vendor');");

  const parcelPlan = protectParcelBuild.planParcelBuild({
    apiKey: "key",
    apiPassword: "pwd",
    input: distRoot,
    output: path.join(root, "dist-protected")
  });
  const bunPlan = protectBunBuild.planBunBuild({
    apiKey: "key",
    apiPassword: "pwd",
    input: distRoot,
    output: path.join(root, "dist-bun-protected")
  });

  assert.deepEqual(parcelPlan.summary.files, ["app.js"]);
  assert.equal(parcelPlan.summary.assets.includes("vendor/lib.js"), true);
  assert.equal(bunPlan.config.maxOutputBytes, 250000);
  assert.equal(bunPlan.summary.files.includes("app.js"), true);
});

test("CLI init writes config and next steps", async () => {
  const root = makeTempDir();
  const result = await runCliInCwd(root, ["--init"], "");
  const configPath = path.join(root, "jso.config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));

  assert.equal(config.$schema, "./node_modules/jso-protector/jso.config.schema.json");
  assert.equal(config.apiKey, "$JSO_API_KEY");
  assert.equal(result.stdout.includes("npm install --save-dev jso-protector"), true);
  assert.equal(result.stdout.includes("--release-check --json"), true);
});

test("CLI init supports templates and scaffold overrides", async () => {
  const root = makeTempDir();
  await runCliInCwd(root, [
    "--init",
    "--init-template", "node",
    "--input", "build",
    "--output", "build-protected",
    "--manifest", "build-protected/jso-manifest.json",
    "--reserved-name", "^ServerApi$",
    "--option", "LockDate=true"
  ], "");
  const config = JSON.parse(fs.readFileSync(path.join(root, "jso.config.json"), "utf8"));

  assert.equal(config.projectName, "node-release");
  assert.deepEqual(config.extensions, [".js", ".cjs", ".mjs"]);
  assert.equal(config.input, "build");
  assert.equal(config.output, "build-protected");
  assert.equal(config.ignoreImports, true);
  assert.equal(config.copyAssets, false);
  assert.equal(config.manifest, "build-protected/jso-manifest.json");
  assert.deepEqual(config.reservedNames, ["^ServerApi$"]);
  assert.equal(config.options.OptimizationMode, "NodeJS");
  assert.equal(config.options.LockDate, true);
});

test("CLI init supports the electron template alias", async () => {
  const root = makeTempDir();
  await runCliInCwd(root, [
    "--init",
    "--init-template", "electron",
    "--input", "out",
    "--output", "out-protected"
  ], "");
  const config = JSON.parse(fs.readFileSync(path.join(root, "jso.config.json"), "utf8"));

  assert.equal(config.projectName, "electron-release");
  assert.equal(config.input, "out");
  assert.equal(config.output, "out-protected");
  assert.equal(config.copyAssets, true);
  assert.equal(config.ignoreImports, true);
  assert.equal(config.mixedServer, true);
  assert.equal(config.options.OptimizationMode, "NodeJS");
});

test("CLI init supports framework template aliases", async () => {
  const nextRoot = makeTempDir();
  await runCliInCwd(nextRoot, [
    "--init",
    "--init-template", "next"
  ], "");
  const nextConfig = JSON.parse(fs.readFileSync(path.join(nextRoot, "jso.config.json"), "utf8"));

  assert.equal(nextConfig.projectName, "nextjs-release");
  assert.equal(nextConfig.input, ".next/static");
  assert.equal(nextConfig.output, ".next/static-protected");
  assert.equal(nextConfig.copyAssets, true);
  assert.equal(nextConfig.options.OptimizationMode, "Web");

  const reactNativeRoot = makeTempDir();
  await runCliInCwd(reactNativeRoot, [
    "--init",
    "--init-template", "expo"
  ], "");
  const reactNativeConfig = JSON.parse(fs.readFileSync(path.join(reactNativeRoot, "jso.config.json"), "utf8"));

  assert.equal(reactNativeConfig.projectName, "react-native-release");
  assert.equal(reactNativeConfig.copyAssets, false);
  assert.equal(reactNativeConfig.ignoreImports, false);
  assert.equal(reactNativeConfig.options.OptimizationMode, "Mobile");

  const viteRoot = makeTempDir();
  await runCliInCwd(viteRoot, [
    "--init",
    "--init-template", "vite"
  ], "");
  const viteConfig = JSON.parse(fs.readFileSync(path.join(viteRoot, "jso.config.json"), "utf8"));

  assert.equal(viteConfig.projectName, "vite-release");
  assert.equal(viteConfig.copyAssets, true);
  assert.equal(viteConfig.options.OptimizationMode, "Web");

  const parcelRoot = makeTempDir();
  await runCliInCwd(parcelRoot, [
    "--init",
    "--init-template", "parcel"
  ], "");
  const parcelConfig = JSON.parse(fs.readFileSync(path.join(parcelRoot, "jso.config.json"), "utf8"));

  assert.equal(parcelConfig.projectName, "parcel-release");
  assert.equal(parcelConfig.copyAssets, true);
  assert.equal(parcelConfig.options.OptimizationMode, "Web");
  assert.equal(parcelConfig.reservedNames.includes("^parcelRequire.*$"), true);

  const bunRoot = makeTempDir();
  await runCliInCwd(bunRoot, [
    "--init",
    "--init-template", "bun"
  ], "");
  const bunConfig = JSON.parse(fs.readFileSync(path.join(bunRoot, "jso.config.json"), "utf8"));

  assert.equal(bunConfig.projectName, "bun-release");
  assert.equal(bunConfig.copyAssets, true);
  assert.equal(bunConfig.options.OptimizationMode, "Web");
  assert.deepEqual(bunConfig.extensions, [".js", ".mjs"]);

  const browserifyRoot = makeTempDir();
  await runCliInCwd(browserifyRoot, [
    "--init",
    "--init-template", "browserify"
  ], "");
  const browserifyConfig = JSON.parse(fs.readFileSync(path.join(browserifyRoot, "jso.config.json"), "utf8"));

  assert.equal(browserifyConfig.projectName, "browserify-release");
  assert.equal(browserifyConfig.copyAssets, true);
  assert.equal(browserifyConfig.options.OptimizationMode, "Web");
  assert.equal(browserifyConfig.reservedNames.includes("^require$"), true);

  const webpackRoot = makeTempDir();
  await runCliInCwd(webpackRoot, [
    "--init",
    "--init-template", "webpack"
  ], "");
  const webpackConfig = JSON.parse(fs.readFileSync(path.join(webpackRoot, "jso.config.json"), "utf8"));

  assert.equal(webpackConfig.projectName, "webpack-release");
  assert.equal(webpackConfig.copyAssets, true);
  assert.equal(webpackConfig.options.OptimizationMode, "Web");

  const rspackRoot = makeTempDir();
  await runCliInCwd(rspackRoot, [
    "--init",
    "--init-template", "rspack"
  ], "");
  const rspackConfig = JSON.parse(fs.readFileSync(path.join(rspackRoot, "jso.config.json"), "utf8"));

  assert.equal(rspackConfig.projectName, "rspack-release");
  assert.equal(rspackConfig.copyAssets, true);
  assert.equal(rspackConfig.options.OptimizationMode, "Web");

  const turbopackRoot = makeTempDir();
  await runCliInCwd(turbopackRoot, [
    "--init",
    "--init-template", "turbopack"
  ], "");
  const turbopackConfig = JSON.parse(fs.readFileSync(path.join(turbopackRoot, "jso.config.json"), "utf8"));

  assert.equal(turbopackConfig.projectName, "turbopack-release");
  assert.equal(turbopackConfig.input, ".next/static");
  assert.equal(turbopackConfig.output, ".next/static-protected");
  assert.deepEqual(turbopackConfig.include, ["chunks/*.js", "chunks/**/*.js"]);
});

test("mergeConfig can import online web presets", () => {
  const root = makeTempDir();
  const webPresetPath = path.join(root, "online-preset.json");
  fs.writeFileSync(webPresetPath, JSON.stringify({
    format: "javascript-obfuscator-web-preset",
    version: 1,
    preset: "standard",
    standardOptions: {
      keepLinefeeds: true,
      keepIndentations: true,
      encodeStrings: true,
      moveStrings: true,
      replaceNames: true
    },
    advancedFeatures: ["Short Local Name", "Compressor", "Deep Obfuscation", "Flat Transform"],
    variableExclusionList: "^PublicApi$"
  }, null, 2));

  const merged = cli.mergeConfig({
    __configDir: root,
    webPreset: "online-preset.json",
    input: "dist",
    output: "protected"
  }, {});

  assert.equal(merged.options.WriteFormats, true);
  assert.equal(merged.options.WriteFormats_KeepIndent, true);
  assert.equal(merged.options.IdentityStyle, "v2abcd");
  assert.equal(merged.options.SelfCompression, true);
  assert.equal(merged.options.DeepObfuscate, true);
  assert.equal(merged.options.FlatTransform, true);
  assert.equal(merged.options.VariableExclusion, "^PublicApi$");
});

test("collectFiles respects extensions and exclude patterns", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(path.join(input, "vendor"), { recursive: true });
  fs.mkdirSync(path.join(input, "nested"), { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('app');");
  fs.writeFileSync(path.join(input, "app.js.map"), "{}");
  fs.writeFileSync(path.join(input, "vendor", "lib.js"), "console.log('lib');");
  fs.writeFileSync(path.join(input, "nested", "view.jsx"), "export default null;");
  fs.writeFileSync(path.join(input, "style.css"), "body{}");

  const files = cli.collectFiles(
    input,
    path.join(root, "protected"),
    [".js", ".jsx"],
    ["**/*.map", "**/vendor/**"]
  );

  assert.deepEqual(files.map((file) => file.relative).sort(), ["app.js", "nested/view.jsx"]);
});

test("collectFiles skips nested output folders and already obfuscated files", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(input, "protected");
  fs.mkdirSync(path.join(input, "nested"), { recursive: true });
  fs.mkdirSync(output, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('app');");
  fs.writeFileSync(path.join(input, "app-obfuscated.js"), "console.log('old');");
  fs.writeFileSync(path.join(input, "nested", "view.js"), "console.log('view');");
  fs.writeFileSync(path.join(output, "app.js"), "console.log('protected');");

  const files = cli.collectFiles(
    input,
    output,
    [".js"],
    ["**/*.map", "**/node_modules/**", "**/*-obfuscated.js"]
  );

  assert.deepEqual(files.map((file) => file.relative).sort(), ["app.js", "nested/view.js"]);
});

test("collectFiles honors include patterns", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  fs.mkdirSync(path.join(input, "assets"), { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('app');");
  fs.writeFileSync(path.join(input, "assets", "widget.js"), "console.log('widget');");
  fs.writeFileSync(path.join(input, "assets", "widget.jsx"), "export default null;");

  const files = cli.collectFiles(
    input,
    path.join(root, "protected"),
    [".js", ".jsx"],
    [],
    ["assets/*.js"]
  );

  assert.deepEqual(files.map((file) => file.relative), ["assets/widget.js"]);
});

test("collectFiles ignores unsupported direct file extensions", () => {
  const root = makeTempDir();
  const input = path.join(root, "README.md");
  fs.writeFileSync(input, "# no");

  const files = cli.collectFiles(input, path.join(root, "out.js"), [".js"], []);
  assert.deepEqual(files, []);
});

test("collectAssets copies non-protected files and excluded JavaScript but omits source maps", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(path.join(input, "vendor"), { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('app');");
  fs.writeFileSync(path.join(input, "index.html"), "<script src=\"app.js\"></script>");
  fs.writeFileSync(path.join(input, "style.css"), "body{}");
  fs.writeFileSync(path.join(input, "app.js.map"), "{}");
  fs.writeFileSync(path.join(input, "vendor", "lib.js"), "console.log('lib');");

  const protectedFiles = cli.collectFiles(input, output, [".js"], ["**/*.map", "**/vendor/**"]);
  const assets = cli.collectAssets(input, output, protectedFiles, ["**/*.map"]);

  assert.deepEqual(assets.map((file) => file.relative).sort(), [
    "index.html",
    "style.css",
    "vendor/lib.js"
  ]);
});

test("collectAssets skips nested output folders on reruns", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(input, "protected");
  fs.mkdirSync(path.join(output, "assets"), { recursive: true });
  fs.writeFileSync(path.join(input, "index.html"), "<script src=\"app.js\"></script>");
  fs.writeFileSync(path.join(output, "index.html"), "<script src=\"app.js\"></script>");
  fs.writeFileSync(path.join(output, "assets", "old.css"), "body{}");

  const assets = cli.collectAssets(input, output, [], ["**/*.map"]);

  assert.deepEqual(assets.map((file) => file.relative), ["index.html"]);
});

test("buildRequest maps config and files to HttpApi payload", () => {
  const root = makeTempDir();
  const source = path.join(root, "app.js");
  fs.writeFileSync(source, "function hello(){}");

  const request = cli.buildRequest({
    apiKey: "key",
    apiPassword: "pwd",
    projectName: "release",
    mixedServer: true,
    options: {
      EncodeStrings: true,
      ReplaceNames: false,
      CompressionRatio: "Best"
    }
  }, [{
    source,
    relative: "app.js",
    target: path.join(root, "out", "app.js")
  }]);

  assert.equal(request.APIKey, "key");
  assert.equal(request.APIPwd, "pwd");
  assert.equal(request.Name, "release");
  assert.equal(request.MixedServer, true);
  assert.equal(request.EncodeStrings, true);
  assert.equal(request.ReplaceNames, undefined);
  assert.equal(request.CompressionRatio, "Best");
  assert.deepEqual(request.Items, [{ FileName: "app.js", FileCode: "function hello(){}" }]);
});

test("conditional comments fail by default and preserve disabled regions when enabled", () => {
  const root = makeTempDir();
  const source = path.join(root, "app.js");
  fs.writeFileSync(source, [
    "console.log('protect-a');",
    "// javascript-obfuscator:disable",
    "console.log('plain');",
    "// javascript-obfuscator:enable",
    "console.log('protect-b');"
  ].join("\n"));

  const file = { source, relative: "app.js", target: path.join(root, "out", "app.js") };
  assert.throws(() => cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: false,
    options: {}
  }, [file]), /conditional comments/);

  const prepared = cli.buildProtectionItems({
    honorConditionalComments: true,
    parseHtml: false,
    options: {}
  }, [file]);
  assert.equal(prepared.items.length, 2);
  assert.equal(prepared.items[0].FileCode.includes("protect-a"), true);
  assert.equal(prepared.items[1].FileCode.includes("protect-b"), true);

  cli.writeResults([file], {
    Items: prepared.items.map((item) => ({
      FileName: item.FileName,
      FileCode: item.FileCode.replace(/protect-/g, "done-")
    }))
  }, prepared.transforms);

  const output = fs.readFileSync(file.target, "utf8");
  assert.equal(output.includes("done-a"), true);
  assert.equal(output.includes("console.log('plain');"), true);
  assert.equal(output.includes("done-b"), true);
});

test("conditional comments require balanced disable and enable markers", () => {
  assert.throws(() => cli.buildCodeProtectionPlan({
    honorConditionalComments: true,
    parseHtml: false,
    options: {}
  }, "app.js", [
    "console.log('protect');",
    "// javascript-obfuscator:disable",
    "console.log('plain');"
  ].join("\n")), /app\.js:2:1.*without a matching javascript-obfuscator:enable/);

  assert.throws(() => cli.buildCodeProtectionPlan({
    honorConditionalComments: true,
    parseHtml: false,
    options: {}
  }, "app.js", [
    "console.log('protect');",
    "// javascript-obfuscator:enable"
  ].join("\n")), /app\.js:2:1.*enable without a matching/);
});

test("protect-marked comments fail by default and protect only marked regions when enabled", () => {
  const root = makeTempDir();
  const source = path.join(root, "app.js");
  fs.writeFileSync(source, [
    "console.log('plain-a');",
    "// javascript-obfuscator:protect-begin",
    "console.log('protect-me');",
    "// javascript-obfuscator:protect-end",
    "console.log('plain-b');"
  ].join("\n"));

  const file = { source, relative: "app.js", target: path.join(root, "out", "app.js") };
  assert.throws(() => cli.buildProtectionItems({
    honorConditionalComments: false,
    protectMarkedComments: false,
    parseHtml: false,
    options: {}
  }, [file]), /protect markers/);

  const prepared = cli.buildProtectionItems({
    honorConditionalComments: false,
    protectMarkedComments: true,
    parseHtml: false,
    options: {}
  }, [file]);

  assert.equal(prepared.items.length, 1);
  assert.equal(prepared.items[0].FileCode.includes("protect-me"), true);

  cli.writeResults([file], {
    Items: prepared.items.map((item) => ({
      FileName: item.FileName,
      FileCode: item.FileCode.replace("protect-me", "protected")
    }))
  }, prepared.transforms);

  const output = fs.readFileSync(file.target, "utf8");
  assert.equal(output.includes("console.log('plain-a');"), true);
  assert.equal(output.includes("console.log('protected');"), true);
  assert.equal(output.includes("console.log('plain-b');"), true);
});

test("protect-marked comments require balanced markers and cannot mix with conditional comments", () => {
  assert.throws(() => cli.buildCodeProtectionPlan({
    protectMarkedComments: true,
    honorConditionalComments: false,
    parseHtml: false,
    options: {}
  }, "app.js", [
    "console.log('plain');",
    "// javascript-obfuscator:protect-begin",
    "console.log('protect');"
  ].join("\n")), /app\.js:2:1.*without a matching javascript-obfuscator:protect-end/);

  assert.throws(() => cli.buildCodeProtectionPlan({
    protectMarkedComments: true,
    honorConditionalComments: true,
    parseHtml: false,
    options: {}
  }, "app.js", [
    "console.log('protect');",
    "// javascript-obfuscator:disable",
    "// javascript-obfuscator:protect-begin",
    "console.log('plain');",
    "// javascript-obfuscator:protect-end",
    "// javascript-obfuscator:enable"
  ].join("\n")), /Use one marker style per file/);
});

test("ignoreImports preserves import statements and static require calls", () => {
  const plan = cli.buildCodeProtectionPlan({
    honorConditionalComments: false,
    ignoreImports: true,
    parseHtml: false,
    options: {}
  }, "app.js", [
    "import { feature } from './feature.js';",
    "const helper = require('./helper.js');",
    "const value = feature + helper;",
    "await import('./chunk.js');"
  ].join("\n"));

  assert.equal(plan.items.length, 1);
  assert.equal(plan.items[0].FileCode.trim(), "const value = feature + helper;");

  const output = cli.composeProtectionOutput(plan.transform, new Map(plan.items.map((item) => [
    item.FileName,
    { FileName: item.FileName, FileCode: item.FileCode.replace("value", "protectedValue") }
  ])));

  assert.equal(output.includes("import { feature } from './feature.js';"), true);
  assert.equal(output.includes("const helper = require('./helper.js');"), true);
  assert.equal(output.includes("await import('./chunk.js');"), true);
  assert.equal(output.includes("protectedValue = feature + helper"), true);
});

test("ignoreImports propagates through mergeConfig and does not trigger review-only warnings", () => {
  const root = makeTempDir();
  const report = cli.validateProtectionConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    ignoreImports: true
  }, {});

  assert.equal(report.ok, true);
  assert.equal(report.checks.some((check) => check.name === "compatibility" && check.message.includes("ignoreImports")), false);

  const merged = cli.mergeConfig({
    __configDir: root,
    apiKey: "key",
    apiPassword: "pwd",
    input: "dist",
    output: "protected",
    ignoreImports: true
  }, {});
  assert.equal(merged.ignoreImports, true);
});

test("parseHtml protects marked inline scripts and preserves unmarked HTML", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  const htmlPath = path.join(input, "index.html");
  fs.writeFileSync(htmlPath, [
    "<html><body>",
    "<script>console.log('plain');</script>",
    "<script data-javascript-obfuscator>console.log('secret');</script>",
    "</body></html>"
  ].join(""));

  const files = cli.collectFiles(input, output, [".js", ".html"], [], [], true);
  assert.deepEqual(files.map((file) => file.relative), ["index.html"]);

  const prepared = cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: true,
    options: {}
  }, files);
  assert.equal(prepared.items.length, 1);
  assert.equal(prepared.items[0].FileCode, "console.log('secret');");

  cli.writeResults(files, {
    Items: [{ FileName: prepared.items[0].FileName, FileCode: "console.log('protected');" }]
  }, prepared.transforms);

  const protectedHtml = fs.readFileSync(path.join(output, "index.html"), "utf8");
  assert.equal(protectedHtml.includes("console.log('plain');"), true);
  assert.equal(protectedHtml.includes("console.log('protected');"), true);
  assert.equal(protectedHtml.includes("console.log('secret');"), false);
});

test("parseHtml protects marked inline scripts in ASPX template files", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  const templatePath = path.join(input, "Default.aspx");
  fs.writeFileSync(templatePath, [
    "<%@ Page Language=\"C#\" %>",
    "<script>console.log('plain');</script>",
    "<script data-javascript-obfuscator>console.log('secret');</script>"
  ].join("\n"));

  const files = cli.collectFiles(input, output, [".js", ".aspx"], [], [], [".aspx"]);
  assert.deepEqual(files.map((file) => file.relative), ["Default.aspx"]);

  const prepared = cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: true,
    markupExtensions: [".aspx"],
    options: {}
  }, files);
  assert.equal(prepared.items.length, 1);
  assert.equal(prepared.items[0].FileCode, "console.log('secret');");

  cli.writeResults(files, {
    Items: [{ FileName: prepared.items[0].FileName, FileCode: "console.log('protected');" }]
  }, prepared.transforms);

  const protectedTemplate = fs.readFileSync(path.join(output, "Default.aspx"), "utf8");
  assert.equal(protectedTemplate.includes("console.log('plain');"), true);
  assert.equal(protectedTemplate.includes("console.log('protected');"), true);
  assert.equal(protectedTemplate.includes("console.log('secret');"), false);
});

test("buildProtectionManifest records transformed output before files are written", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  const htmlPath = path.join(input, "index.html");
  fs.writeFileSync(htmlPath, [
    "<main>release</main>",
    "<script data-javascript-obfuscator>console.log('secret');</script>"
  ].join(""));

  const files = cli.collectFiles(input, output, [".html"], [], []);
  const prepared = cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: true,
    options: {},
    endpoint: "https://example.test/HttpApi.ashx",
    projectName: "manifest-test",
    preset: "balanced"
  }, files);
  const protectedCode = "console.log('protected');";
  const manifest = cli.buildProtectionManifest({
    endpoint: "https://example.test/HttpApi.ashx",
    projectName: "manifest-test",
    preset: "balanced",
    options: {}
  }, files, [], {
    Items: [{ FileName: prepared.items[0].FileName, FileCode: protectedCode }]
  }, prepared.transforms);

  assert.equal(fs.existsSync(path.join(output, "index.html")), false);
  assert.equal(manifest.files[0].fileName, "index.html");
  assert.equal(manifest.files[0].outputBytes, Buffer.byteLength(`<main>release</main><script data-javascript-obfuscator>${protectedCode}</script>`));
  assert.equal(manifest.processing.apiItems, 1);
  assert.equal(manifest.processing.transformedFiles[0].fileName, "index.html");
});

test("buildProtectionManifest carries grouped migration limitations", () => {
  const root = makeTempDir();
  const source = path.join(root, "app.js");
  const target = path.join(root, "dist", "app.js");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(source, "console.log('release');", "utf8");

  const manifest = cli.buildProtectionManifest({
    endpoint: "https://example.test/HttpApi.ashx",
    projectName: "limitations-manifest",
    preset: "balanced",
    options: {},
    sourceMap: true,
    identifierNamesCachePath: "cache.json",
    jsConfuserLockSelfDefending: true
  }, [{ source, relative: "app.js", target }], [], {
    Items: [{ FileName: "app.js", FileCode: "console.log('protected');" }]
  });

  assert.equal(manifest.limitations.some((item) => item.id === "source-maps"), true);
  assert.equal(manifest.limitations.some((item) => item.id === "identifier-name-cache"), true);
  assert.equal(manifest.limitations.some((item) => item.id === "runtime-self-defending"), false);
});

test("HTML files require parseHtml before protection", () => {
  const root = makeTempDir();
  const source = path.join(root, "index.html");
  fs.writeFileSync(source, "<script data-javascript-obfuscator>console.log('secret');</script>");
  const file = { source, relative: "index.html", target: path.join(root, "out", "index.html") };

  assert.throws(() => cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: false,
    options: {}
  }, [file]), /Pass --parse-html/);
});

test("parseHtml fails clearly for marked external and module scripts", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "external.html"), "<script data-javascript-obfuscator src=\"app.js\"></script>");
  fs.writeFileSync(path.join(input, "module.html"), "<script data-javascript-obfuscator type=\"module\">console.log('module');</script>");

  const files = cli.collectFiles(input, output, [".html"], [], []);
  assert.deepEqual(files.map((file) => file.relative).sort(), ["external.html", "module.html"]);

  assert.throws(() => cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: true,
    options: {}
  }, [files.find((file) => file.relative === "external.html")]), /external\.html:1:1.*external script/);

  assert.throws(() => cli.buildProtectionItems({
    honorConditionalComments: false,
    parseHtml: true,
    options: {}
  }, [files.find((file) => file.relative === "module.html")]), /module\.html:1:1.*module script/);
});

test("planProtection and protectFiles expose transformed API items", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "index.html"), [
    "<main>release</main>",
    "<script data-javascript-obfuscator>console.log('secret');</script>"
  ].join(""));

  const plan = api.planProtection({
    input,
    output,
    apiKey: "key",
    apiPassword: "pwd",
    parseHtml: true
  });
  assert.deepEqual(plan.summary.files, ["index.html"]);
  assert.equal(plan.summary.processing.apiItems, 1);
  assert.equal(plan.summary.processing.transformedFiles[0].fileName, "index.html");

  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("secret", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const result = await api.protectFiles({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      input,
      output,
      apiKey: "key",
      apiPassword: "pwd",
      parseHtml: true
    });
    const protectedHtml = fs.readFileSync(path.join(output, "index.html"), "utf8");
    assert.equal(result.processing.apiItems, 1);
    assert.equal(protectedHtml.includes("<main>release</main>"), true);
    assert.equal(protectedHtml.includes("console.log('protected');"), true);
    assert.equal(protectedHtml.includes("console.log('secret');"), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("mergeConfig carries namedSets through and validates them", () => {
  const root = makeTempDir();
  const merged = cli.mergeConfig({
    __configDir: root,
    input: "dist",
    output: "protected",
    namedSets: { checkout: { match: ["checkout/**"], preset: "maximum" } }
  }, {});
  assert.equal(cli.hasNamedSets(merged), true);
  assert.deepEqual(merged.namedSets.checkout.match, ["checkout/**"]);

  assert.throws(() => cli.mergeConfig({
    __configDir: root, input: "dist", output: "protected",
    namedSets: { bad: { match: ["x/**"], preset: "ultra" } }
  }, {}), /preset "ultra" is unknown/);
  assert.throws(() => cli.mergeConfig({
    __configDir: root, input: "dist", output: "protected",
    namedSets: { bad: { preset: "maximum" } }
  }, {}), /match must be a non-empty array/);
  assert.throws(() => cli.mergeConfig({
    __configDir: root, input: "dist", output: "protected",
    namedSets: { bad: { match: ["x/**"], optoins: {} } }
  }, {}), /unknown key "optoins"/);
});

test("groupFilesByNamedSets partitions files and applyNamedSetToConfig composes options", () => {
  const config = {
    preset: "standard",
    options: { ReplaceNames: true, EncodeStrings: true },
    namedSets: {
      checkout: { match: ["checkout/**"], preset: "maximum", options: { DeadcodeLevel: "High" } },
      widget: { match: ["**/*.widget.js"], options: { RenameGlobals: false } }
    }
  };
  const files = [
    { relative: "app.js" },
    { relative: "checkout/pay.js" },
    { relative: "embed/x.widget.js" }
  ];
  const groups = cli.groupFilesByNamedSets(config, files);
  assert.equal(groups.length, 3);
  const byName = new Map(groups.map((group) => [group.setName, group]));
  assert.deepEqual(byName.get(null).files.map((file) => file.relative), ["app.js"]);
  assert.deepEqual(byName.get("checkout").files.map((file) => file.relative), ["checkout/pay.js"]);
  assert.deepEqual(byName.get("widget").files.map((file) => file.relative), ["embed/x.widget.js"]);

  const checkoutConfig = cli.applyNamedSetToConfig(config, "checkout");
  assert.equal(checkoutConfig.preset, "maximum");
  assert.equal(checkoutConfig.options.ReplaceNames, true, "baseline options survive");
  assert.equal(checkoutConfig.options.FlatTransform, true, "set preset contributes its option block");
  assert.equal(checkoutConfig.options.DeadcodeLevel, "High", "set options win over the set preset");

  const widgetConfig = cli.applyNamedSetToConfig(config, "widget");
  assert.equal(widgetConfig.preset, "standard", "a set without a preset keeps the baseline preset");
  assert.equal(widgetConfig.options.RenameGlobals, false);

  assert.equal(cli.applyNamedSetToConfig(config, null), config, "unmatched files keep the base config object");
});

test("namedSets split protection into one API round per set", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(path.join(input, "checkout"), { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('app');");
  fs.writeFileSync(path.join(input, "checkout", "pay.js"), "console.log('pay');");

  const payloads = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const payload = JSON.parse(body);
      payloads.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: "/*p*/" + item.FileCode
        }))
      }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const result = await api.protectFiles({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      input,
      output,
      apiKey: "key",
      apiPassword: "pwd",
      preset: "standard",
      namedSets: {
        checkout: { match: ["checkout/**"], preset: "maximum", options: { DeadcodeLevel: "High" } }
      }
    });

    assert.equal(payloads.length, 2, "one API round per named-set group");
    const checkoutPayload = payloads.find((payload) => payload.Items.some((item) => item.FileName.startsWith("checkout/")));
    const basePayload = payloads.find((payload) => !payload.Items.some((item) => item.FileName.startsWith("checkout/")));
    assert.ok(checkoutPayload && basePayload, "both groups reached the API");
    assert.equal(checkoutPayload.FlatTransform, true, "checkout round carries the maximum-preset options");
    assert.equal(checkoutPayload.DeadcodeLevel, "High", "checkout round carries the set's own options");
    assert.equal(basePayload.FlatTransform, undefined, "base round does not inherit the set's options");

    assert.equal(fs.readFileSync(path.join(output, "app.js"), "utf8"), "/*p*/console.log('app');");
    assert.equal(fs.readFileSync(path.join(output, "checkout", "pay.js"), "utf8"), "/*p*/console.log('pay');");
    assert.equal(result.type, "Succeed");
    assert.equal(result.manifest.files.length, 2, "manifest spans both groups");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("writeResults writes API response items to matching targets", () => {
  const root = makeTempDir();
  const target = path.join(root, "protected", "app.js");

  cli.writeResults([{
    relative: "app.js",
    target
  }], {
    Items: [{ FileName: "app.js", FileCode: "var a=1;" }]
  });

  assert.equal(fs.readFileSync(target, "utf8"), "var a=1;");
});

test("copyAssets copies static files to output targets", () => {
  const root = makeTempDir();
  const source = path.join(root, "dist", "style.css");
  const target = path.join(root, "protected", "style.css");
  fs.mkdirSync(path.dirname(source), { recursive: true });
  fs.writeFileSync(source, "body{}");

  cli.copyAssets([{ source, target, relative: "style.css" }]);

  assert.equal(fs.readFileSync(target, "utf8"), "body{}");
});

test("postJson sends HttpApi-compatible request and parses response", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    assert.equal(request.method, "POST");
    assert.equal(request.headers["content-type"], "application/json");

    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: `/* protected */\n${item.FileCode}`
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const result = await cli.postJson(`http://127.0.0.1:${address.port}/HttpApi.ashx`, {
      APIKey: "key",
      APIPwd: "pwd",
      Name: "test",
      Items: [{ FileName: "app.js", FileCode: "console.log(1);" }]
    });

    assert.equal(result.Type, "Succeed");
    assert.equal(result.Items[0].FileCode, "/* protected */\nconsole.log(1);");
    assert.equal(received.length, 1);
    assert.equal(received[0].APIKey, "key");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("postJson explains paid API account failures without leaking credentials", async () => {
  const server = http.createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      response.writeHead(403, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Message: "Subscription expired for API key secret-key and password secret-password"
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    await assert.rejects(
      () => cli.postJson(`http://127.0.0.1:${address.port}/HttpApi.ashx`, {
        APIKey: "secret-key",
        APIPwd: "secret-password",
        Items: []
      }),
      (error) => {
        assert.equal(error.message.includes("secret-key"), false);
        assert.equal(error.message.includes("secret-password"), false);
        assert.equal(error.message.includes("[redacted]"), true);
        assert.equal(error.message.includes("account status"), true);
        return true;
      }
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("protectItems explains hosted API plan and credit failures", async () => {
  const server = http.createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Failed",
        FileName: "app.js",
        Message: "Plan credit limit exceeded for password secret-password"
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    await assert.rejects(
      () => cli.protectItems({
        endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
        apiKey: "secret-key",
        apiPassword: "secret-password",
        projectName: "test",
        mixedServer: false,
        options: {}
      }, [{ FileName: "app.js", FileCode: "console.log(1);" }]),
      (error) => {
        assert.equal(error.message.includes("secret-password"), false);
        assert.equal(error.message.includes("Failed in app.js"), true);
        assert.equal(error.message.includes("plan limits"), true);
        return true;
      }
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("protectCode exposes a Node API for single-file integrations", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("debug", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const code = await api.protectCode({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      preset: "standard"
    }, "console.log('debug');", "app.js");

    assert.equal(code, "console.log('protected');");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("protectCode strips stale sourceMappingURL comments by default and can preserve them", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("release", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const source = "console.log('release');\n//# sourceMappingURL=app.js.map\n";
    const stripped = await api.protectCode({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd"
    }, source, "app.js");
    const preserved = await api.protectCode({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      removeSourceMaps: false
    }, source, "app.js");

    assert.equal(stripped.includes("sourceMappingURL"), false);
    assert.equal(preserved.includes("sourceMappingURL"), true);
    assert.match(stripped, /console\.log\('protected'\);/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("obfuscate exposes a javascript-obfuscator-style async Node API", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("debug", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const result = await api.obfuscate("console.log('debug');", {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      controlFlowFlattening: true,
      identifierNamesGenerator: "hexadecimal",
      reservedNames: ["^PublicApi$"],
      stringArrayEncoding: ["rc4"],
      target: "node"
    }, "app.js");

    assert.equal(result.getObfuscatedCode(), "console.log('protected');");
    assert.equal(result.toString(), "console.log('protected');");
    assert.equal(result.code, "console.log('protected');");
    assert.equal(result.fileName, "app.js");
    assert.equal(result.result.Type, "Succeed");
    assert.deepEqual(result.result.Items.map((item) => item.FileName), ["app.js"]);
    assert.equal(result.getSourceMap(), null);
    assert.equal(result.getIdentifierNamesCache(), null);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.js"]);
    assert.equal(received[0].DeepObfuscate, true);
    assert.equal(received[0].FlatTransform, true);
    assert.equal(received[0].EncryptStrings, true);
    assert.equal(received[0].IdentityStyle, "v1hex");
    assert.equal(received[0].OptimizationMode, "NodeJS");
    assert.equal(received[0].VariableExclusion, "^PublicApi$");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("translateJavascriptObfuscatorOptions maps familiar source options to API options", () => {
  const translated = api.translateJavascriptObfuscatorOptions({
    compact: true,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.7,
    domainLock: ["example.com", "app.example.com"],
    renameGlobals: true,
    renameProperties: true,
    parseHtml: true,
    strictMode: false,
    selfDefending: true,
    debugProtection: false,
    debugProtectionInterval: 750,
    disableConsoleOutput: true,
    domainLockRedirectUrl: "/domain-blocked",
    seed: 42,
	reservedStrings: ["^PUBLIC_", "LICENSE$"],
	forceTransformStrings: ["^FORCED_"],
    numbersToExpressions: true,
    stringArray: true,
    stringArrayIndexShift: true,
    stringArrayShuffle: true,
    stringArrayRotate: true,
    stringArrayIndexesType: ["hexadecimal-number", "hexadecimal-numeric-string"],
    stringArrayThreshold: 0.5,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.75,
    stringArrayWrappersCount: 3,
    stringArrayWrappersChainedCalls: false,
    stringArrayWrappersParametersMaxCount: 5,
    stringArrayWrappersType: "function",
    transformObjectKeys: true,
    splitStrings: true,
    splitStringsChunkLength: 5,
    unicodeEscapeSequence: true
  }, {
    preset: "maximum",
    options: {
      LockDomain: true
    }
  });

  assert.equal(translated.preset, "maximum");
  assert.equal(translated.options.MoveStrings, true);
  assert.equal(translated.options.StringArrayIndexShift, true);
  assert.equal(translated.options.StringArrayShuffle, true);
  assert.equal(translated.options.StringArrayRotate, true);
  assert.equal(translated.options.StringArrayIndexesType, "hexadecimal-number\nhexadecimal-numeric-string");
  assert.equal(translated.options.StringArrayThreshold, 0.5);
  assert.equal(translated.options.StringArrayCallsTransform, true);
  assert.equal(translated.options.StringArrayCallsTransformThreshold, 0.75);
  assert.equal(translated.options.StringArrayWrappersCount, 3);
  assert.equal(translated.options.StringArrayWrappersChainedCalls, false);
  assert.equal(translated.options.StringArrayWrappersParametersMaxCount, 5);
  assert.equal(translated.options.StringArrayWrappersType, "function");
  assert.equal(translated.options.TransformObjectKeys, true);
  assert.equal(translated.options.SplitStrings, true);
  assert.equal(translated.options.SplitStringsChunkLength, 5);
  assert.equal(translated.options.EncodeStrings, true);
  assert.equal(translated.options.AddDeadCode, true);
  assert.equal(translated.options.DeadcodeLevel, "High");
  assert.equal(translated.options.RenameGlobals, true);
  assert.equal(translated.options.RenameMembers, true);
  assert.equal(translated.options.SelfCompression, true);
  assert.equal(translated.options.SelfDefending, true);
  assert.equal(translated.options.DebugProtection, false);
  assert.equal(translated.options.DebugProtectionIntervalMilliseconds, 750);
  assert.equal(translated.options.DisableConsoleOutput, true);
  assert.equal(translated.options.LockDomainRedirectUrl, "/domain-blocked");
  assert.equal(translated.options.Seed, "42");
  assert.equal(translated.options.ReservedStrings, "^PUBLIC_\nLICENSE$");
  assert.equal(translated.options.ForceTransformStrings, "^FORCED_");
  assert.equal(translated.options.EncodeNumbers, true);
  assert.equal(translated.options.CompressionRatio, "Best");
  assert.equal(translated.options.LockDomain, true);
  assert.equal(translated.options.LockDomainList, "example.com\napp.example.com");
  assert.equal(translated.parseHtml, true);
  assert.equal(translated.strictMode, false);
});

test("translateJavascriptObfuscatorOptions maps optionsPreset when no override is provided", () => {
  const translated = api.translateJavascriptObfuscatorOptions({
    optionsPreset: "low-obfuscation"
  });

  assert.equal(translated.preset, "standard");
});

test("translateJavascriptObfuscatorOptions accepts VM preset aliases", () => {
  const translated = api.translateJavascriptObfuscatorOptions({
    optionsPreset: "vm-medium-obfuscation"
  });

  assert.equal(translated.preset, "balanced");
});

test("obfuscateMultiple protects an object map in one API request", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: `/* protected ${item.FileName} */\n${item.FileCode}`
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const results = await api.obfuscateMultiple({
      "foo.js": "var foo = 1;",
      "bar.js": "var bar = 2;"
    }, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      stringArray: true
    });

    assert.deepEqual(Object.keys(results), ["foo.js", "bar.js"]);
    assert.equal(results["foo.js"].getObfuscatedCode(), "/* protected foo.js */\nvar foo = 1;");
    assert.equal(results["foo.js"].toString(), "/* protected foo.js */\nvar foo = 1;");
    assert.equal(results["bar.js"].getObfuscatedCode(), "/* protected bar.js */\nvar bar = 2;");
    assert.equal(received.length, 1);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["foo.js", "bar.js"]);
    assert.equal(received[0].MoveStrings, true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("obfuscateMultiple honors marked HTML and conditional comments", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace(/secret|protect/g, "done")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const results = await api.obfuscateMultiple({
      "index.html": "<script>console.log('plain');</script><script data-javascript-obfuscator>console.log('secret');</script>",
      "app.js": [
        "console.log('protect');",
        "// javascript-obfuscator:disable",
        "console.log('plain');",
        "// javascript-obfuscator:enable"
      ].join("\n")
    }, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      parseHtml: true,
      honorConditionalComments: true
    });

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["index.html.script1.js", "app.jso-part-1.js"]);
    assert.equal(results["index.html"].getObfuscatedCode().includes("console.log('plain');"), true);
    assert.equal(results["index.html"].getObfuscatedCode().includes("console.log('done');"), true);
    assert.equal(results["app.js"].getObfuscatedCode().includes("console.log('done');"), true);
    assert.equal(results["app.js"].getObfuscatedCode().includes("console.log('plain');"), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("getOptionsByPreset returns a copy of preset options", () => {
  const first = api.getOptionsByPreset("balanced");
  const second = api.getOptionsByPreset("balanced");
  first.DeepObfuscate = false;

  assert.equal(second.DeepObfuscate, true);
  assert.throws(() => api.getOptionsByPreset("unknown"), /Unknown preset/);
});

test("planProtection exposes directory inputs without calling the API", () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(path.join(input, "assets"), { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release');");
  fs.writeFileSync(path.join(input, "assets", "style.css"), "body{}");
  fs.writeFileSync(path.join(input, "app.js.map"), "{}");

  const plan = api.planProtection({
    input,
    output,
    preset: "balanced",
    exclude: ["**/*.map"],
    assetExclude: ["**/*.map"]
  });

  assert.equal(plan.config.preset, "balanced");
  assert.deepEqual(plan.files.map((file) => file.relative), ["app.js"]);
  assert.deepEqual(plan.assets.map((file) => file.relative), ["assets/style.css"]);
  assert.deepEqual(plan.summary.files, ["app.js"]);
});

test("protectFiles writes protected files, copied assets, and manifest through the Node API", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("release", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, "dist");
    const output = path.join(root, "protected");
    const manifestPath = path.join(root, "manifest.json");
    fs.mkdirSync(input, { recursive: true });
    fs.writeFileSync(path.join(input, "app.js"), "console.log('release');");
    fs.writeFileSync(path.join(input, "index.html"), "<script src=\"app.js\"></script>");

    const result = await api.protectFiles({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output,
      preset: "balanced",
      manifest: manifestPath
    });

    assert.equal(fs.readFileSync(path.join(output, "app.js"), "utf8"), "console.log('protected');");
    assert.equal(fs.readFileSync(path.join(output, "index.html"), "utf8"), "<script src=\"app.js\"></script>");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.js"]);
    assert.deepEqual(result.written, [path.join(output, "app.js")]);
    assert.deepEqual(result.copied, [path.join(output, "index.html")]);
    assert.equal(result.manifestPath, manifestPath);
    assert.equal(result.manifest.files[0].fileName, "app.js");
    assert.equal(JSON.parse(fs.readFileSync(manifestPath, "utf8")).assets[0].fileName, "index.html");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("protectFile writes one source file to an explicit target", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("debug", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const source = path.join(root, "entry.js");
    const target = path.join(root, "entry.protected.js");
    fs.writeFileSync(source, "console.log('debug');");

    const result = await api.protectFile({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd"
    }, source, target);

    assert.equal(fs.readFileSync(target, "utf8"), "console.log('protected');");
    assert.deepEqual(result.written, [target]);
    assert.deepEqual(result.copied, []);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("CLI can protect stdin to stdout", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("pipe", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const output = await runCli([
      "--stdin",
      "--stdout",
      "--file-name", "pipe.js",
      "--endpoint", `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      "--api-key", "key",
      "--api-password", "pwd"
    ], "console.log('pipe');");

    assert.equal(output.stderr, "");
    assert.equal(output.stdout, "console.log('protected');");
    assert.deepEqual(received[0].Items, [{ FileName: "pipe.js", FileCode: "console.log('pipe');" }]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("CLI stdin manifest records conditional-comment processing", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("protect", "done")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "jso-manifest.json");
    const result = await runCli([
      "--stdin",
      "--file-name", "pipe.js",
      "--output", path.join(root, "protected"),
      "--manifest", manifestPath,
      "--honor-conditional-comments",
      "--endpoint", `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      "--api-key", "key",
      "--api-password", "pwd",
      "--json"
    ], [
      "console.log('protect');",
      "// javascript-obfuscator:disable",
      "console.log('plain');",
      "// javascript-obfuscator:enable"
    ].join("\n"));

    const report = JSON.parse(result.stdout);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["pipe.jso-part-1.js"]);
    assert.equal(report.processing.apiItems, 1);
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "pipe.js");
    assert.equal(fs.readFileSync(path.join(root, "protected", "pipe.js"), "utf8").includes("console.log('plain');"), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("CLI fails when stdin output exceeds growth budget", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: `${item.FileCode}\n${"x".repeat(100)}`
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    await assert.rejects(() => runCli([
      "--stdin",
      "--stdout",
      "--file-name", "budget.js",
      "--endpoint", `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      "--api-key", "key",
      "--api-password", "pwd",
      "--max-growth-ratio", "1.1"
    ], "console.log('budget');"), /Size budget failed/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Vite plugin protects generated chunks and removes stale source maps", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: `/* protected ${item.FileName} */`
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const manifestPath = path.join(makeTempDir(), "vite-manifest.json");
    const plugin = viteProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      preset: "balanced",
      exclude: ["**/vendor/**"],
      manifest: manifestPath
    });
    plugin.configResolved({ build: { outDir: "dist" } });

    const bundle = {
      "assets/app.js": { type: "chunk", fileName: "assets/app.js", code: "console.log('app');", map: {} },
      "assets/app.js.map": { type: "asset", fileName: "assets/app.js.map", source: "{}" },
      "assets/vendor/lib.js": { type: "chunk", fileName: "assets/vendor/lib.js", code: "console.log('vendor');", map: {} },
      "assets/vendor/lib.js.map": { type: "asset", fileName: "assets/vendor/lib.js.map", source: "{}" },
      "assets/style.css": { type: "asset", fileName: "assets/style.css", source: "body{}" }
    };

    await plugin.generateBundle({}, bundle);
    assert.equal(bundle["assets/app.js"].code, "/* protected assets/app.js */");
    assert.equal(bundle["assets/app.js"].map, null);
    assert.equal(bundle["assets/app.js.map"], undefined);
    assert.equal(bundle["assets/vendor/lib.js"].code, "console.log('vendor');");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["assets/app.js"]);
    assert.equal(bundle["assets/style.css"].source, "body{}");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.format, "jso-protector-manifest");
    assert.equal(manifest.files[0].fileName, "assets/app.js");
    assert.equal(manifest.files[0].outputBytes, Buffer.byteLength("/* protected assets/app.js */"));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Turbopack helper protects matching emitted chunks with default filters", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: `/* protected ${item.FileName} */`
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, ".next", "static");
    const output = path.join(root, ".next", "static-protected");

    fs.mkdirSync(path.join(input, "chunks"), { recursive: true });
    fs.writeFileSync(path.join(input, "chunks", "app.js"), "console.log('app');");
    fs.writeFileSync(path.join(input, "webpack-123.js"), "console.log('runtime');");

    const result = await protectTurbopackBuild({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output
    });

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["chunks/app.js"]);
    assert.equal(fs.readFileSync(path.join(output, "chunks", "app.js"), "utf8"), "/* protected chunks/app.js */");
    assert.equal(fs.readFileSync(path.join(output, "webpack-123.js"), "utf8"), "console.log('runtime');");
    assert.equal(result.manifest.files[0].fileName, "chunks/app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Vite plugin honors conditional comments in generated chunks", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('protect');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const manifestPath = path.join(makeTempDir(), "vite-conditional-manifest.json");
    const plugin = viteProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      honorConditionalComments: true,
      manifest: manifestPath
    });
    plugin.configResolved({ build: { outDir: "dist" } });

    const bundle = {
      "assets/app.js": {
        type: "chunk",
        fileName: "assets/app.js",
        code: [
          "console.log('protect');",
          "// javascript-obfuscator:disable",
          "console.log('plain');",
          "// javascript-obfuscator:enable"
        ].join("\n"),
        map: {}
      }
    };

    await plugin.generateBundle({}, bundle);

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["assets/app.jso-part-1.js"]);
    assert.match(bundle["assets/app.js"].code, /console\.log\('protected'\);/);
    assert.match(bundle["assets/app.js"].code, /console\.log\('plain'\);/);
    assert.equal(bundle["assets/app.js"].map, null);

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "assets/app.js");
    assert.equal(manifest.files[0].fileName, "assets/app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Vite plugin fails clearly on conditional comments unless enabled", async () => {
  const plugin = viteProtector({
    endpoint: "http://127.0.0.1:1/HttpApi.ashx",
    apiKey: "key",
    apiPassword: "pwd"
  });
  plugin.configResolved({ build: { outDir: "dist" } });

  const bundle = {
    "assets/app.js": {
      type: "chunk",
      fileName: "assets/app.js",
      code: [
        "console.log('protect');",
        "// javascript-obfuscator:disable",
        "console.log('plain');",
        "// javascript-obfuscator:enable"
      ].join("\n"),
      map: {}
    }
  };

  await assert.rejects(
    () => plugin.generateBundle({}, bundle),
    /assets\/app\.js:2:1.*honor-conditional-comments/
  );
  assert.match(bundle["assets/app.js"].code, /console\.log\('protect'\);/);
  assert.match(bundle["assets/app.js"].code, /console\.log\('plain'\);/);
});

test("Vite plugin fails before mutating output when size budgets fail", async () => {
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: `${item.FileCode}\n${"x".repeat(100)}`
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const manifestPath = path.join(makeTempDir(), "vite-budget-manifest.json");
    const plugin = viteProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      preset: "balanced",
      manifest: manifestPath,
      maxGrowthRatio: 1.1
    });
    plugin.configResolved({ build: { outDir: "dist" } });

    const bundle = {
      "assets/app.js": { type: "chunk", fileName: "assets/app.js", code: "console.log('app');", map: {} },
      "assets/app.js.map": { type: "asset", fileName: "assets/app.js.map", source: "{}" }
    };

    await assert.rejects(() => plugin.generateBundle({}, bundle), /Size budget failed/);
    assert.equal(bundle["assets/app.js"].code, "console.log('app');");
    assert.notEqual(bundle["assets/app.js.map"], undefined);
    assert.equal(fs.existsSync(manifestPath), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("esbuild plugin protects in-memory output files", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("esbuild", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const plugin = esbuildProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      include: ["app.js"]
    });
    const build = {
      initialOptions: { outdir: root },
      onEnd(callback) {
        build.onEndCallback = callback;
      }
    };
    plugin.setup(build);

    const outputFiles = [
      { path: path.join(root, "app.js"), contents: Buffer.from("console.log('esbuild');") },
      { path: path.join(root, "app.js.map"), contents: Buffer.from("{}") },
      { path: path.join(root, "vendor.js"), contents: Buffer.from("console.log('vendor');") }
    ];

    await build.onEndCallback({ outputFiles });
    assert.equal(Buffer.from(outputFiles[0].contents).toString("utf8"), "console.log('protected');");
    assert.equal(Buffer.from(outputFiles[1].contents).toString("utf8"), "console.log('vendor');");
    assert.equal(outputFiles.length, 2);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.js"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("esbuild plugin respects configured module extensions in in-memory output files", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("module", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const plugin = esbuildProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      extensions: [".mjs"],
      include: ["entry.mjs"]
    });
    const build = {
      initialOptions: { outdir: root },
      onEnd(callback) {
        build.onEndCallback = callback;
      }
    };
    plugin.setup(build);

    const outputFiles = [
      { path: path.join(root, "entry.mjs"), contents: Buffer.from("console.log('module');") },
      { path: path.join(root, "entry.mjs.map"), contents: Buffer.from("{}") },
      { path: path.join(root, "skip.js"), contents: Buffer.from("console.log('skip');") }
    ];

    await build.onEndCallback({ outputFiles });
    assert.equal(Buffer.from(outputFiles[0].contents).toString("utf8"), "console.log('protected');");
    assert.equal(Buffer.from(outputFiles[1].contents).toString("utf8"), "console.log('skip');");
    assert.equal(outputFiles.length, 2);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["entry.mjs"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("esbuild plugin honors conditional comments in in-memory output files", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('esbuild');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "esbuild-conditional-manifest.json");
    const plugin = esbuildProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      honorConditionalComments: true,
      include: ["app.js"],
      manifest: manifestPath
    });
    const build = {
      initialOptions: { outdir: root },
      onEnd(callback) {
        build.onEndCallback = callback;
      }
    };
    plugin.setup(build);

    const outputFiles = [
      {
        path: path.join(root, "app.js"),
        contents: Buffer.from([
          "console.log('esbuild');",
          "// javascript-obfuscator:disable",
          "console.log('plain');",
          "// javascript-obfuscator:enable"
        ].join("\n"))
      },
      { path: path.join(root, "app.js.map"), contents: Buffer.from("{}") }
    ];

    await build.onEndCallback({ outputFiles });

    const output = Buffer.from(outputFiles[0].contents).toString("utf8");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.jso-part-1.js"]);
    assert.match(output, /console\.log\('protected'\);/);
    assert.match(output, /console\.log\('plain'\);/);
    assert.equal(outputFiles.length, 1);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("esbuild plugin respects configured module extensions for written output files", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("written", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const outfile = path.join(root, "bundle.cjs");
    fs.writeFileSync(outfile, "console.log('written');", "utf8");
    fs.writeFileSync(`${outfile}.map`, "{}", "utf8");

    const plugin = esbuildProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      extensions: [".cjs"]
    });
    const build = {
      initialOptions: { outfile },
      onEnd(callback) {
        build.onEndCallback = callback;
      }
    };
    plugin.setup(build);

    await build.onEndCallback({});

    assert.equal(fs.readFileSync(outfile, "utf8"), "console.log('protected');");
    assert.equal(fs.existsSync(`${outfile}.map`), false);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["bundle.cjs"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Browserify transform protects selected modules", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("browserify", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, "src");
    const manifestPath = path.join(root, "browserify-manifest.json");
    fs.mkdirSync(input, { recursive: true });
    const file = path.join(input, "app.js");
    const output = await runTextStream(browserifyProtector(file, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      preset: "balanced",
      include: ["app.js"],
      manifest: manifestPath
    }), "console.log('browserify');");

    assert.equal(output, "console.log('protected');");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.js"]);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.files[0].fileName, "app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Browserify transform honors conditional comments", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('browserify');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, "src");
    const manifestPath = path.join(root, "browserify-conditional-manifest.json");
    fs.mkdirSync(input, { recursive: true });
    const file = path.join(input, "app.js");
    const output = await runTextStream(browserifyProtector(file, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      honorConditionalComments: true,
      include: ["app.js"],
      manifest: manifestPath
    }), [
      "console.log('browserify');",
      "// javascript-obfuscator:disable",
      "console.log('plain');",
      "// javascript-obfuscator:enable"
    ].join("\n"));

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.jso-part-1.js"]);
    assert.match(output, /console\.log\('protected'\);/);
    assert.match(output, /console\.log\('plain'\);/);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Browserify transform respects configured module extensions", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("browserify", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, "src");
    fs.mkdirSync(input, { recursive: true });
    const file = path.join(input, "entry.mjs");
    const output = await runTextStream(browserifyProtector(file, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      extensions: [".mjs"],
      include: ["entry.mjs"]
    }), "console.log('browserify');");

    assert.equal(output, "console.log('protected');");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["entry.mjs"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Browserify transform passes excluded files through without credentials", async () => {
  const root = makeTempDir();
  const file = path.join(root, "vendor.js");
  const output = await runTextStream(browserifyProtector(file, {
    include: ["src/*.js"]
  }), "console.log('vendor');");

  assert.equal(output, "console.log('vendor');");
});

test("Gulp plugin batches Vinyl files and removes stale source maps", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("gulp", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "gulp-manifest.json");
    const files = [
      {
        path: path.join(root, "assets", "app.js"),
        base: root,
        relative: "assets/app.js",
        contents: Buffer.from("console.log('gulp');"),
        isNull() { return false; },
        isStream() { return false; }
      },
      {
        path: path.join(root, "assets", "app.js.map"),
        base: root,
        relative: "assets/app.js.map",
        contents: Buffer.from("{}"),
        isNull() { return false; },
        isStream() { return false; }
      },
      {
        path: path.join(root, "assets", "style.css"),
        base: root,
        relative: "assets/style.css",
        contents: Buffer.from("body{}"),
        isNull() { return false; },
        isStream() { return false; }
      }
    ];

    const output = await runObjectStream(gulpProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      preset: "balanced",
      include: ["assets/*.js"],
      manifest: manifestPath
    }), files);

    assert.deepEqual(output.map((file) => file.relative), ["assets/app.js", "assets/style.css"]);
    assert.equal(output[0].contents.toString("utf8"), "console.log('protected');");
    assert.equal(output[1].contents.toString("utf8"), "body{}");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["assets/app.js"]);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.files[0].fileName, "assets/app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Gulp plugin honors conditional comments in Vinyl files", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('gulp');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "gulp-conditional-manifest.json");
    const files = [{
      path: path.join(root, "assets", "app.js"),
      base: root,
      relative: "assets/app.js",
      contents: Buffer.from([
        "console.log('gulp');",
        "// javascript-obfuscator:disable",
        "console.log('plain');",
        "// javascript-obfuscator:enable"
      ].join("\n")),
      isNull() { return false; },
      isStream() { return false; }
    }];

    const output = await runObjectStream(gulpProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      honorConditionalComments: true,
      include: ["assets/*.js"],
      manifest: manifestPath
    }), files);

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["assets/app.jso-part-1.js"]);
    assert.match(output[0].contents.toString("utf8"), /console\.log\('protected'\);/);
    assert.match(output[0].contents.toString("utf8"), /console\.log\('plain'\);/);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "assets/app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Grunt task protects configured file mappings", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("grunt", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, "dist");
    const output = path.join(root, "protected");
    const manifestPath = path.join(root, "manifest.json");
    fs.mkdirSync(input, { recursive: true });
    fs.writeFileSync(path.join(input, "app.js"), "console.log('grunt');");
    fs.writeFileSync(path.join(input, "style.css"), "body{}");

    await runRegisteredGruntTask(registerGruntProtector, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output,
      preset: "balanced",
      include: ["app.js"],
      manifest: manifestPath
    }, [{
      src: [path.join(input, "app.js"), path.join(input, "style.css")],
      dest: `${output}${path.sep}`
    }]);

    assert.equal(fs.readFileSync(path.join(output, "app.js"), "utf8"), "console.log('protected');");
    assert.equal(fs.existsSync(path.join(output, "style.css")), false);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.js"]);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.files[0].fileName, "app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Grunt task honors conditional comments in configured file mappings", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('grunt');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const input = path.join(root, "dist");
    const output = path.join(root, "protected");
    const manifestPath = path.join(root, "grunt-conditional-manifest.json");
    fs.mkdirSync(input, { recursive: true });
    fs.writeFileSync(path.join(input, "app.js"), [
      "console.log('grunt');",
      "// javascript-obfuscator:disable",
      "console.log('plain');",
      "// javascript-obfuscator:enable"
    ].join("\n"));

    await runRegisteredGruntTask(registerGruntProtector, {
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output,
      honorConditionalComments: true,
      include: ["app.js"],
      manifest: manifestPath
    }, [{
      src: [path.join(input, "app.js")],
      dest: `${output}${path.sep}`
    }]);

    const protectedCode = fs.readFileSync(path.join(output, "app.js"), "utf8");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["app.jso-part-1.js"]);
    assert.match(protectedCode, /console\.log\('protected'\);/);
    assert.match(protectedCode, /console\.log\('plain'\);/);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Rollup plugin protects generated chunks", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("rollup", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const plugin = rollupProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      include: ["bundle.js"]
    });
    const bundle = {
      "bundle.js": { type: "chunk", fileName: "bundle.js", code: "console.log('rollup');", map: {} },
      "bundle.js.map": { type: "asset", fileName: "bundle.js.map", source: "{}" },
      "vendor.js": { type: "chunk", fileName: "vendor.js", code: "console.log('vendor');", map: {} }
    };

    await plugin.generateBundle({ dir: "dist" }, bundle);
    assert.equal(bundle["bundle.js"].code, "console.log('protected');");
    assert.equal(bundle["vendor.js"].code, "console.log('vendor');");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["bundle.js"]);
    assert.equal(bundle["bundle.js"].map, null);
    assert.equal(bundle["bundle.js.map"], undefined);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Rollup plugin honors conditional comments in generated chunks", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('rollup');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "rollup-conditional-manifest.json");
    const plugin = rollupProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      honorConditionalComments: true,
      include: ["bundle.js"],
      manifest: manifestPath
    });
    const bundle = {
      "bundle.js": {
        type: "chunk",
        fileName: "bundle.js",
        code: [
          "console.log('rollup');",
          "// javascript-obfuscator:disable",
          "console.log('plain');",
          "// javascript-obfuscator:enable"
        ].join("\n"),
        map: {}
      },
      "bundle.js.map": { type: "asset", fileName: "bundle.js.map", source: "{}" }
    };

    await plugin.generateBundle({ dir: "dist" }, bundle);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["bundle.jso-part-1.js"]);
    assert.match(bundle["bundle.js"].code, /console\.log\('protected'\);/);
    assert.match(bundle["bundle.js"].code, /console\.log\('plain'\);/);
    assert.equal(bundle["bundle.js"].map, null);
    assert.equal(bundle["bundle.js.map"], undefined);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "bundle.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Metro serializer protects bundle code returned as an object and removes stale source maps", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("metro", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const serializer = createMetroSerializer({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      include: ["index.android.release.bundle.js"],
      serializer: async () => ({
        code: "console.log('metro');",
        map: { version: 3 },
        assets: ["asset"]
      })
    });

    const result = await serializer("index.js", [], {}, {
      dev: false,
      platform: "android",
      projectRoot: makeTempDir()
    });

    assert.equal(result.code, "console.log('protected');");
    assert.equal(result.map, undefined);
    assert.deepEqual(result.assets, ["asset"]);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["index.android.release.bundle.js"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Metro serializer skips excluded bundle output", async () => {
  let called = false;
  const serializer = createMetroSerializer({
    include: ["index.ios.release.bundle.js"],
    serializer() {
      return { code: "console.log('metro');", map: { version: 3 } };
    },
    async protectItems() {
      called = true;
      throw new Error("protectItems should not run");
    }
  });

  const result = await serializer("index.js", [], {}, {
    dev: false,
    platform: "android",
    projectRoot: makeTempDir()
  });

  assert.equal(result.code, "console.log('metro');");
  assert.deepEqual(result.map, { version: 3 });
  assert.equal(called, false);
});

test("Webpack plugin protects JavaScript assets", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("release", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const hooks = {
      thisCompilation: {
        tap(_name, callback) {
          hooks.thisCompilation.callback = callback;
        }
      }
    };
    class RawSource {
      constructor(value) {
        this.value = value;
      }
      source() {
        return this.value;
      }
    }
    const compiler = {
      webpack: {
        sources: { RawSource },
        Compilation: { PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE: 300 }
      },
      options: { output: { path: "dist" } },
      hooks
    };
    const plugin = new WebpackProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      exclude: ["vendor.js"]
    });
    plugin.apply(compiler);

    const assets = {
      "main.js": new RawSource("console.log('release');"),
      "main.js.map": new RawSource("{}"),
      "vendor.js": new RawSource("console.log('vendor');"),
      "style.css": new RawSource("body{}")
    };
    const deleted = [];
    const compilation = {
      hooks: {
        processAssets: {
          tapPromise(_options, callback) {
            compilation.processAssetsCallback = callback;
          }
        }
      },
      getAsset(name) {
        return { source: assets[name] };
      },
      updateAsset(name, source) {
        assets[name] = source;
      },
      deleteAsset(name) {
        deleted.push(name);
        delete assets[name];
      }
    };

    hooks.thisCompilation.callback(compilation);
    await compilation.processAssetsCallback(assets);

    assert.equal(assets["main.js"].source(), "console.log('protected');");
    assert.equal(assets["vendor.js"].source(), "console.log('vendor');");
    assert.equal(assets["style.css"].source(), "body{}");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["main.js"]);
    assert.deepEqual(deleted, ["main.js.map"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Webpack plugin falls back to the webpack 4 emit hook surface", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("legacy", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const hooks = {
      emit: {
        tapPromise(_name, callback) {
          hooks.emit.callback = callback;
        }
      }
    };
    const compiler = {
      options: { output: { path: "dist" } },
      hooks
    };
    const plugin = new WebpackProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      exclude: ["vendor.js"]
    });
    plugin.apply(compiler);

    const compilation = {
      assets: {
        "main.js": createLegacyAsset("console.log('legacy');"),
        "main.js.map": createLegacyAsset("{}"),
        "vendor.js": createLegacyAsset("console.log('vendor');"),
        "style.css": createLegacyAsset("body{}")
      }
    };

    await hooks.emit.callback(compilation);

    assert.equal(compilation.assets["main.js"].source(), "console.log('protected');");
    assert.equal(compilation.assets["vendor.js"].source(), "console.log('vendor');");
    assert.equal(compilation.assets["style.css"].source(), "body{}");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["main.js"]);
    assert.equal(Object.prototype.hasOwnProperty.call(compilation.assets, "main.js.map"), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Webpack plugin respects configured emitted module extensions", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("module", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const hooks = {
      thisCompilation: {
        tap(_name, callback) {
          hooks.thisCompilation.callback = callback;
        }
      }
    };
    class RawSource {
      constructor(value) {
        this.value = value;
      }
      source() {
        return this.value;
      }
    }
    const compiler = {
      webpack: {
        sources: { RawSource },
        Compilation: { PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE: 300 }
      },
      options: { output: { path: "dist" } },
      hooks
    };
    const plugin = new WebpackProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      extensions: [".mjs"],
      include: ["main.mjs"]
    });
    plugin.apply(compiler);

    const assets = {
      "main.mjs": new RawSource("console.log('module');"),
      "main.mjs.map": new RawSource("{}"),
      "main.js": new RawSource("console.log('skip');")
    };
    const deleted = [];
    const compilation = {
      hooks: {
        processAssets: {
          tapPromise(_options, callback) {
            compilation.processAssetsCallback = callback;
          }
        }
      },
      getAsset(name) {
        return { source: assets[name] };
      },
      updateAsset(name, source) {
        assets[name] = source;
      },
      deleteAsset(name) {
        deleted.push(name);
        delete assets[name];
      }
    };

    hooks.thisCompilation.callback(compilation);
    await compilation.processAssetsCallback(assets);

    assert.equal(assets["main.mjs"].source(), "console.log('protected');");
    assert.equal(assets["main.js"].source(), "console.log('skip');");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["main.mjs"]);
    assert.deepEqual(deleted, ["main.mjs.map"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Rspack plugin protects JavaScript assets through the webpack-compatible hook surface", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("release", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const hooks = {
      thisCompilation: {
        tap(_name, callback) {
          hooks.thisCompilation.callback = callback;
        }
      }
    };
    class RawSource {
      constructor(value) {
        this.value = value;
      }
      source() {
        return this.value;
      }
    }
    const compiler = {
      webpack: {
        sources: { RawSource },
        Compilation: { PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE: 300 }
      },
      options: { output: { path: "dist" } },
      hooks
    };
    const plugin = new RspackProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      exclude: ["vendor.js"]
    });
    plugin.apply(compiler);

    const assets = {
      "main.js": new RawSource("console.log('release');"),
      "main.js.map": new RawSource("{}"),
      "vendor.js": new RawSource("console.log('vendor');")
    };
    const deleted = [];
    const compilation = {
      hooks: {
        processAssets: {
          tapPromise(_options, callback) {
            compilation.processAssetsCallback = callback;
          }
        }
      },
      getAsset(name) {
        return { source: assets[name] };
      },
      updateAsset(name, source) {
        assets[name] = source;
      },
      deleteAsset(name) {
        deleted.push(name);
        delete assets[name];
      }
    };

    hooks.thisCompilation.callback(compilation);
    await compilation.processAssetsCallback(assets);

    assert.equal(assets["main.js"].source(), "console.log('protected');");
    assert.equal(assets["vendor.js"].source(), "console.log('vendor');");
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["main.js"]);
    assert.deepEqual(deleted, ["main.js.map"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Webpack plugin honors conditional comments in JavaScript assets", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('release');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "webpack-conditional-manifest.json");
    const hooks = {
      thisCompilation: {
        tap(_name, callback) {
          hooks.thisCompilation.callback = callback;
        }
      }
    };
    class RawSource {
      constructor(value) {
        this.value = value;
      }
      source() {
        return this.value;
      }
    }
    const compiler = {
      webpack: {
        sources: { RawSource },
        Compilation: { PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE: 300 }
      },
      options: { output: { path: root } },
      hooks
    };
    const plugin = new WebpackProtector({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      honorConditionalComments: true,
      manifest: manifestPath
    });
    plugin.apply(compiler);

    const assets = {
      "main.js": new RawSource([
        "console.log('release');",
        "// javascript-obfuscator:disable",
        "console.log('plain');",
        "// javascript-obfuscator:enable"
      ].join("\n")),
      "main.js.map": new RawSource("{}")
    };
    const deleted = [];
    const compilation = {
      hooks: {
        processAssets: {
          tapPromise(_options, callback) {
            compilation.processAssetsCallback = callback;
          }
        }
      },
      getAsset(name) {
        return { source: assets[name] };
      },
      updateAsset(name, source) {
        assets[name] = source;
      },
      deleteAsset(name) {
        deleted.push(name);
        delete assets[name];
      }
    };

    hooks.thisCompilation.callback(compilation);
    await compilation.processAssetsCallback(assets);

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["main.jso-part-1.js"]);
    assert.match(assets["main.js"].source(), /console\.log\('protected'\);/);
    assert.match(assets["main.js"].source(), /console\.log\('plain'\);/);
    assert.deepEqual(deleted, ["main.js.map"]);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "main.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

function createLegacyAsset(value) {
  return {
    source() {
      return value;
    },
    size() {
      return Buffer.byteLength(value, "utf8");
    }
  };
}

test("Webpack loader protects a module and drops stale source maps", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("loader", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    let cacheableValue = null;
    const result = await runWebpackLoader(webpackLoader, {
      rootContext: root,
      resourcePath: path.join(root, "src", "app.js"),
      cacheable(value) {
        cacheableValue = value;
      },
      getOptions() {
        return {
          endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
          apiKey: "key",
          apiPassword: "pwd",
          preset: "balanced",
          include: ["src/*.js"]
        };
      }
    }, "console.log('loader');", { version: 3 }, { ast: true });

    assert.equal(result.code, "console.log('protected');");
    assert.equal(result.map, null);
    assert.deepEqual(result.meta, { ast: true });
    assert.equal(cacheableValue, false);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["src/app.js"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Webpack loader respects configured module extensions", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("loader", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const result = await runWebpackLoader(webpackLoader, {
      rootContext: root,
      resourcePath: path.join(root, "src", "entry.mjs"),
      cacheable() {},
      getOptions() {
        return {
          endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
          apiKey: "key",
          apiPassword: "pwd",
          extensions: [".mjs"],
          include: ["src/*.mjs"]
        };
      }
    }, "console.log('loader');", { version: 3 }, { ast: true });

    assert.equal(result.code, "console.log('protected');");
    assert.equal(result.map, null);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["src/entry.mjs"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Rspack loader aliases the webpack loader behavior", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("loader", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    let cacheableValue = null;
    const result = await runWebpackLoader(rspackLoader, {
      rootContext: root,
      resourcePath: path.join(root, "src", "app.js"),
      cacheable(value) {
        cacheableValue = value;
      },
      getOptions() {
        return {
          endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
          apiKey: "key",
          apiPassword: "pwd",
          preset: "balanced",
          include: ["src/*.js"]
        };
      }
    }, "console.log('loader');", { version: 3 }, { ast: true });

    assert.equal(result.code, "console.log('protected');");
    assert.equal(result.map, null);
    assert.deepEqual(result.meta, { ast: true });
    assert.equal(cacheableValue, false);
    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["src/app.js"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Webpack loader honors conditional comments in modules", async () => {
  const received = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      received.push(payload);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("console.log('loader');", "console.log('protected');")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = makeTempDir();
    const manifestPath = path.join(root, "loader-conditional-manifest.json");
    const result = await runWebpackLoader(webpackLoader, {
      rootContext: root,
      resourcePath: path.join(root, "src", "app.js"),
      cacheable() {},
      getOptions() {
        return {
          endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
          apiKey: "key",
          apiPassword: "pwd",
          honorConditionalComments: true,
          include: ["src/*.js"],
          manifest: manifestPath
        };
      }
    }, [
      "console.log('loader');",
      "// javascript-obfuscator:disable",
      "console.log('plain');",
      "// javascript-obfuscator:enable"
    ].join("\n"), { version: 3 }, { ast: true });

    assert.deepEqual(received[0].Items.map((item) => item.FileName), ["src/app.jso-part-1.js"]);
    assert.match(result.code, /console\.log\('protected'\);/);
    assert.match(result.code, /console\.log\('plain'\);/);
    assert.equal(result.map, null);
    assert.deepEqual(result.meta, { ast: true });
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.processing.apiItems, 1);
    assert.equal(manifest.processing.transformedFiles[0].fileName, "src/app.js");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Webpack loader skips excluded modules without credentials", async () => {
  const root = makeTempDir();
  let cacheableValue = null;
  const sourceMap = { version: 3 };
  const meta = { ast: true };
  const result = await runWebpackLoader(webpackLoader, {
    rootContext: root,
    resourcePath: path.join(root, "vendor", "lib.js"),
    cacheable(value) {
      cacheableValue = value;
    },
    getOptions() {
      return {
        apiKey: "key",
        apiPassword: "pwd",
        include: ["src/*.js"]
      };
    }
  }, "console.log('vendor');", sourceMap, meta);

  assert.equal(result.code, "console.log('vendor');");
  assert.equal(result.map, sourceMap);
  assert.equal(result.meta, meta);
  assert.equal(cacheableValue, false);
});

test("main can protect files through a mock HttpApi endpoint", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release');");
  fs.writeFileSync(path.join(input, "index.html"), "<script src=\"app.js\"></script>");
  fs.writeFileSync(path.join(input, "app.js.map"), "{}");

  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body);
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("release", "protected")
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const configPath = path.join(root, "jso.config.json");
    const manifestPath = path.join(root, "manifest.json");
    fs.writeFileSync(configPath, JSON.stringify({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output,
      extensions: [".js"],
      copyAssets: true,
      assetExclude: ["**/*.map"],
      options: { EncodeStrings: true }
    }, null, 2));

    await cli.main(["--config", configPath, "--manifest", manifestPath]);
    assert.equal(fs.readFileSync(path.join(output, "app.js"), "utf8"), "console.log('protected');");
    assert.equal(fs.readFileSync(path.join(output, "index.html"), "utf8"), "<script src=\"app.js\"></script>");
    assert.equal(fs.existsSync(path.join(output, "app.js.map")), false);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.format, "jso-protector-manifest");
    assert.equal(manifest.files[0].fileName, "app.js");
    assert.equal(manifest.files[0].sourceBytes, Buffer.byteLength("console.log('release');"));
    assert.equal(manifest.files[0].outputBytes, Buffer.byteLength("console.log('protected');"));
    assert.equal(manifest.assets[0].fileName, "index.html");
    assert.equal(typeof manifest.files[0].outputSha256, "string");
    assert.equal(manifest.limitations, undefined);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("main propagates --label as ReleaseLabel and writes --report JSON", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release');");

  let observedLabel = null;
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const payload = JSON.parse(body);
      observedLabel = payload.ReleaseLabel || null;
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: item.FileCode.replace("release", "protected")
        })),
        // Mock the new server-side BuildId + PolymorphismFingerprint surface
        // so the CLI's --json output can be asserted against it.
        Report: {
          BuildId: "rel-abcdef123",
          PolymorphismFingerprint: "1234567890abcdef",
          EnabledOptions: ["EncodeStrings"]
        }
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const configPath = path.join(root, "jso.config.json");
    const reportPath = path.join(root, "report.json");
    fs.writeFileSync(configPath, JSON.stringify({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output,
      extensions: [".js"],
      options: { EncodeStrings: true }
    }, null, 2));

    await cli.main([
      "--config", configPath,
      "--label", "ci-build-7f3a",
      "--report", reportPath
    ]);

    // ReleaseLabel must have ridden along on the API request body.
    assert.equal(observedLabel, "ci-build-7f3a", "ReleaseLabel should be forwarded to the API");

    // --report must produce a file with the expected top-level shape.
    assert.equal(fs.existsSync(reportPath), true, "report file should be written");
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(report.Type, "Succeed");
    assert.equal(report.Label, "ci-build-7f3a");
    assert.equal(report.Report.BuildId, "rel-abcdef123");
    assert.equal(report.Report.PolymorphismFingerprint, "1234567890abcdef");
    assert.deepEqual(report.FileNames, ["app.js"]);
    assert.equal(typeof report.GeneratedUtc, "string");

    // The protected source must NOT be duplicated into the report — the heavy
    // payload is intentionally stripped to keep the report small.
    assert.equal(report.Items, undefined, "report should strip heavy Items payload");
    assert.equal(report.FileCode, undefined);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("--label can also be supplied via JSO_LABEL env var", async () => {
  const root = makeTempDir();
  const input = path.join(root, "dist");
  const output = path.join(root, "protected");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release');");

  let observedLabel = null;
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const payload = JSON.parse(body);
      observedLabel = payload.ReleaseLabel || null;
      response.writeHead(200, { "Content-Type": "text/json" });
      response.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName, FileCode: item.FileCode
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const previous = process.env.JSO_LABEL;
  process.env.JSO_LABEL = "env-tag-deadbeef";
  try {
    const address = server.address();
    const configPath = path.join(root, "jso.config.json");
    fs.writeFileSync(configPath, JSON.stringify({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key", apiPassword: "pwd",
      input, output,
      extensions: [".js"],
      options: { EncodeStrings: true }
    }, null, 2));

    await cli.main(["--config", configPath]);
    assert.equal(observedLabel, "env-tag-deadbeef");
  } finally {
    if (previous === undefined) delete process.env.JSO_LABEL;
    else process.env.JSO_LABEL = previous;
    await new Promise((resolve) => server.close(resolve));
  }
});

test("main writes migration limitations into manifest artifacts", async () => {
  const root = makeTempDir();
  const input = path.join(root, "input");
  const output = path.join(root, "output");
  fs.mkdirSync(input, { recursive: true });
  fs.writeFileSync(path.join(input, "app.js"), "console.log('release');", "utf8");

  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const payload = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        Type: "Succeed",
        Items: payload.Items.map((item) => ({
          FileName: item.FileName,
          FileCode: "console.log('protected');"
        }))
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const configPath = path.join(root, "jso.config.json");
    const manifestPath = path.join(root, "manifest.json");
    fs.writeFileSync(configPath, JSON.stringify({
      endpoint: `http://127.0.0.1:${address.port}/HttpApi.ashx`,
      apiKey: "key",
      apiPassword: "pwd",
      input,
      output,
      extensions: [".js"],
      options: { EncodeStrings: true },
      sourceMap: true,
      identifierNamesCachePath: ".cache.json"
    }, null, 2));

    await cli.main(["--config", configPath, "--manifest", manifestPath]);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.limitations.some((item) => item.id === "source-maps"), true);
    assert.equal(manifest.limitations.some((item) => item.id === "identifier-name-cache"), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("main verifies a manifest from an alternate artifact root", async () => {
  const root = makeTempDir();
  const verifyRoot = path.join(root, "artifact");
  fs.mkdirSync(path.join(verifyRoot, "assets"), { recursive: true });
  fs.writeFileSync(path.join(verifyRoot, "assets", "app.js"), "console.log('protected');", "utf8");

  const manifestPath = path.join(root, "jso-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({
    format: "jso-protector-manifest",
    version: 1,
    generatedAt: new Date().toISOString(),
    endpoint: cli.DEFAULT_ENDPOINT,
    projectName: "verify-cli",
    preset: "balanced",
    options: [],
    files: [{
      fileName: "assets/app.js",
      sourcePath: path.join(root, "dist", "assets", "app.js"),
      outputPath: path.join(root, "old-output", "assets", "app.js"),
      sourceBytes: 23,
      outputBytes: Buffer.byteLength("console.log('protected');"),
      sourceSha256: cli.sha256("console.log('release');"),
      outputSha256: cli.sha256("console.log('protected');")
    }],
    assets: []
  }, null, 2), "utf8");

  const result = await runCli(["--verify-manifest", manifestPath, "--verify-root", verifyRoot, "--json"]);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.verifyRoot, verifyRoot);
  assert.equal(report.files[0].path, path.join(verifyRoot, "assets", "app.js"));
});
