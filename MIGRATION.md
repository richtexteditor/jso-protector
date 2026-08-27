# Migrating from javascript-obfuscator

Use `jso-protector` when you want JavaScript Obfuscator account credentials, hosted HTTP API protection, CI guardrails, release manifests, and the same release workflow across the online tool, CLI, Node API, and build plugins.

Use a local-only obfuscator when source code cannot leave the build machine.

## Replace the package command

```bash
npm remove javascript-obfuscator
npm install --save-dev ./packages/jso-protector
npx jso-protector --init
```

For an application in another folder, pin the local package with a `file:` dependency:

```json
{
  "devDependencies": {
    "jso-protector": "file:../packages/jso-protector"
  }
}
```

For internal sharing without publishing to npm, install a private tarball produced by `npm pack --json`.

Set credentials from the JavaScript Obfuscator dashboard:

```bash
set JSO_API_KEY=base64-api-key
set JSO_API_PASSWORD=base64-api-password
```

Long aliases also work:

```bash
set JAVASCRIPT_OBFUSCATOR_API_KEY=base64-api-key
set JAVASCRIPT_OBFUSCATOR_API_PASSWORD=base64-api-password
```

## Map familiar concepts

| javascript-obfuscator concept | jso-protector / HTTP API direction |
| --- | --- |
| `stringArray`, `stringArrayEncoding` | `MoveStrings`, `EncodeStrings`, `EncryptStrings` |
| `reservedStrings` | `ReservedStrings` (matching literals remain verbatim; bounded regex input) |
| `numbersToExpressions` | `EncodeNumbers` (approximate: obscures numeric literals but does not preserve expression shape) |
| `forceTransformStrings` | `ForceTransformStrings` (matching literals override `ReservedStrings`) |
| Identifier rename settings | `ReplaceNames`, `RenameGlobals`, `RenameMembers`, `IdentityStyle` |
| `reservedNames` | `reservedNames`, `--reserved-name`, or `VariableExclusion` |
| Control-flow and dead-code transforms | `DeepObfuscate`, `ReorderCode`, `FlatTransform`, `AddDeadCode`, `DeadcodeLevel` |
| Formatting and compact output | `SelfCompression`, `CompressionRatio`, `WriteFormats` |
| Domain and date restrictions | `domainLock` maps to `LockDomain` and `LockDomainList`; date locks use `LockDate`, `LockDateValue` |

The names are not a one-to-one copy. Run this before porting a large config:

```bash
jso-protector --list-options --json
jso-protector --list-presets --json
jso-protector --list-migration-map --json
```

`--list-migration-map` includes a summary with mapped, direct, approximate, review-only, and total known option counts. Use that summary in migration tooling to decide whether a project can be converted automatically or needs manual review first.

You can generate a starter config from a common `javascript-obfuscator` JSON or trusted CommonJS config file:

```bash
jso-protector --migrate-javascript-obfuscator javascript-obfuscator.json --output jso.config.json
jso-protector --migrate-javascript-obfuscator javascript-obfuscator.config.cjs --output jso.config.json
jso-protector --config jso.config.json --release-check --json
jso-protector --config jso.config.json --competitor-gap-report --json
jso-protector --config jso.config.json --validate-config --json
```

Use `--json` with the migration command when internal tooling needs the generated config plus a per-config summary, mapped options, review items, and unmapped option lists:

```bash
jso-protector --migrate-javascript-obfuscator javascript-obfuscator.json --json
```

The converter maps familiar settings such as string arrays, control-flow flattening, dead-code insertion, identifier styles, `parseHtml`, `domainLock`, reserved names, and target runtime. When you protect inline scripts inside template files, add `markupExtensions` for the file types you ship such as `.php`, `.aspx`, or `.jsp`. The report summary includes source option, mapped, direct, approximate, review-only, unmapped, and automatic coverage counts, a review reference for every known review-only option, then prints the next validate, dry-run, doctor, release-check, competitor-gap-report, and protect commands. Use `--release-check --json` when you want those preflight checks in one CI report, and run `--competitor-gap-report --json` after migration to keep runtime-defense mapping, locks, source maps, identifier caches, and release-forensics review items visible. CommonJS source configs execute as Node.js code, so only migrate configs from your own repository or another trusted source.

You can also keep simple package scripts close to their old shape by using compatibility flags directly:

```bash
jso-protector src/app.js
jso-protector dist --output dist-protected --options-preset high-obfuscation --control-flow-flattening --string-array-encoding rc4 --reserved-names "^PublicApi$"
```

For direct single-file scripts, `jso-protector src/app.js` writes `src/app-obfuscated.js` when no `--output` or config `output` is set. Folder and config-file workflows keep using the configured output folder, usually `dist-protected`.

Mapped compatibility flags include `--options-preset`, `--parse-html`, `--string-array`, `--string-array-encoding`, `--unicode-escape-sequence`, `--control-flow-flattening`, `--dead-code-injection`, `--dead-code-injection-threshold`, `--identifier-names-generator`, `--rename-globals`, `--rename-properties`, `--reserved-names`, `--domain-lock`, `--target`, and `--compact`. Config and Node API `domainLock` arrays map to `LockDomain` plus newline-delimited `LockDomainList`; review `domainLockRedirectUrl` separately because the hosted API lock message is not a redirect. `--options-preset default`, `low-obfuscation`, `vm-default`, and `vm-low-obfuscation` map to `standard`; `medium-obfuscation` and `vm-medium-obfuscation` map to `balanced`; `high-obfuscation`, `vm-high-obfuscation`, `vm-ultra-high-obfuscation`, and `vm-anti-llm` map to `maximum`.

The same mapped compatibility keys can live in `jso.config.json` while you are migrating. Explicit `options` values override the compatibility mapping, so you can start familiar and then tune exact hosted API fields without changing scripts.

The CLI maps `--self-defending`, `--debug-protection`, `--debug-protection-interval`, `--disable-console-output`, `--domain-lock-redirect-url`, `--seed`, `--reserved-strings`, `--force-transform-strings`, `--split-strings`, and `--split-strings-chunk-length` directly to hosted engine options. String splitting uses fixed chunks from 1 through 1024 characters (default 10) and preserves directives, reserved literals, object keys, template segments, import/require specifiers, mixed-server markers, and Unicode surrogate pairs. String-array shuffle, rotation, index representation, call indirection, wrapper type/chaining/parameter controls, and thresholds map to native controls; index shift, wrapper count, and safe object-key transformation retain documented approximation boundaries. `--numbers-to-expressions` remains an approximate mapping. Source-map, identifier-cache/dictionary, rename-mode, strict-mode, and simplify workflow fields remain review-only. `--ignore-imports` is handled directly. Review-only fields emit compatibility warnings, and vendor-specific runtime behavior still requires validation.

For string-selection controls, the CLI maps `--reserved-strings`, and `--force-transform-strings` directly.

Quoted class method, accessor, and field names remain literal because class definition grammar does not accept concatenation expressions in those positions.

## Start with a conservative config

```json
{
  "$schema": "./node_modules/jso-protector/jso.config.schema.json",
  "apiKey": "$JSO_API_KEY",
  "apiPassword": "$JSO_API_PASSWORD",
  "input": "dist",
  "output": "dist-protected",
  "preset": "balanced",
  "exclude": ["**/*.map", "**/vendor/**", "**/polyfills-*.js"],
  "parseHtml": false,
  "honorConditionalComments": false,
  "reservedNames": ["^PublicApi$", "^renderWidget$"],
  "manifest": "dist-protected/jso-manifest.json",
  "maxGrowthRatio": 8,
  "options": {
    "OptimizationMode": "Web",
    "LockDomain": false
  }
}
```

## Replace direct Node usage

```js
const { obfuscate, obfuscateMultiple, getOptionsByPreset, protectCode } = require("jso-protector");

const obfuscationResult = await obfuscate(sourceCode, {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  controlFlowFlattening: true,
  domainLock: ["example.com", "app.example.com"],
  identifierNamesGenerator: "hexadecimal",
  reservedNames: ["^PublicApi$"],
  stringArrayEncoding: ["rc4"]
}, "app.js");

const protectedCode = obfuscationResult.getObfuscatedCode();
const alsoProtectedCode = obfuscationResult.toString();

const multipleResults = await obfuscateMultiple({
  "foo.js": "var foo = 1;",
  "bar.js": "var bar = 2;"
}, {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  ...getOptionsByPreset("balanced")
});
```

`obfuscate(code, options, fileName)` and `obfuscateMultiple(sourceCodesObject, options)` are the closest replacements for `JavaScriptObfuscator.obfuscate(...)` and `JavaScriptObfuscator.obfuscateMultiple(...)`, but they return Promises because protection happens through the hosted HTTP API. They accept common `javascript-obfuscator` option names directly, including `stringArray`, `stringArrayEncoding`, `controlFlowFlattening`, `deadCodeInjection`, `deadCodeInjectionThreshold`, `identifierNamesGenerator`, `renameGlobals`, `renameProperties`, `reservedNames`, `compact`, and `target`.

Use `getOptionsByPreset("standard" | "balanced" | "maximum")` when replacing preset lookup helpers, and `translateJavascriptObfuscatorOptions(sourceOptions, overrides)` when migration tooling needs to inspect the mapped hosted API config before making the API call.

`stringArrayIndexShift` maps approximately to native `StringArrayIndexShift`. When enabled, references use a deterministic nonzero one-slot offset in both plain and encrypted string tables. This preserves the index-shifting protection shape, but does not reproduce `javascript-obfuscator`'s randomized shift magnitude; run the protected application in its target runtime before release.

`stringArrayShuffle` maps directly to native `StringArrayShuffle`. It randomizes the order of unique moved strings and rewrites every generated lookup before plain or encrypted table emission. Builds use fresh entropy by default; supplying `Seed` makes the shuffled artifact reproducible.

`stringArrayRotate` maps directly to native `StringArrayRotate`. For tables with multiple values it applies a nonzero cyclic offset chosen per build, then rewrites every generated lookup. It uses an independent entropy stream and remains reproducible when `Seed` is supplied.

`stringArrayIndexesType` maps directly to native `StringArrayIndexesType`. Both documented values are supported: `hexadecimal-number` emits numeric hexadecimal indexes, while `hexadecimal-numeric-string` emits hexadecimal strings with explicit numeric coercion before lookup. Mixed arrays select a representation per lookup from an independent entropy stream and remain reproducible under `Seed`.

`stringArrayThreshold` maps directly to native `StringArrayThreshold`. Values must be from 0 through 1. Each unique eligible literal receives one stable probability decision, so duplicate literals cannot split between moved and verbatim forms; zero disables moving, one moves every eligible literal, and partial selection is reproducible under `Seed`.

`stringArrayCallsTransform` and `stringArrayCallsTransformThreshold` map directly to native secondary index-table indirection. Selected lookups become `stringTable[indexTable[n]]`; the threshold accepts 0 through 1, defaults to 0.5 when transformation is enabled, and uses an independent entropy stream that is reproducible under `Seed`. It composes with shifting, shuffle, rotation, encryption, index representation, and compression.

The wrapper controls map to native root-level string-table wrappers. `stringArrayWrappersType` supports `variable` aliases and `function` wrappers; count is bounded to 0-10, function parameters to 2-5, and chained calls delegate through predecessors. Noise arguments and wrapper selection use isolated seeded entropy. Wrapper type, chaining, and parameter behavior map directly, while count is approximate because the competitor places wrappers inside each root or function scope and JSO deliberately emits them only at the protected root.

`transformObjectKeys` maps approximately to native `TransformObjectKeys`. Safe identifier and quoted object-literal data keys become computed string-table lookups. Numeric keys, method/accessor definitions, shorthand-sensitive members, and `__proto__` remain literal because converting those shapes can change JavaScript property or prototype semantics.

## JS-Confuser migration

Use the dedicated JS-Confuser helpers when the current project is built around `js-confuser` rather than `javascript-obfuscator`:

```bash
jso-protector --list-js-confuser-migration-map --json
jso-protector --explain-js-confuser-compat lock.endDate --json
jso-protector --migrate-js-confuser js-confuser.config.cjs --output jso.config.json
```

The current JS-Confuser migration path maps common preset, lock, identifier, string, minify, and control-flow settings into the nearest hosted API equivalents. Anti-debugging, integrity/self-defending, start-date, and tamper-protection locks map approximately to native `DebugProtection`, `SelfDefending`, `LockStartDate`, and `AntiMonkeyPatching` controls. Numeric probability values collapse to enabled/disabled, so validate the protected build in its target browser. Arbitrary countermeasure functions, custom locks, opaque predicates, dispatcher mode, and similar JS-Confuser-specific behavior remain review items rather than being executed or guessed automatically.

`stringSplitting` maps approximately to native `SplitStrings`: booleans map directly and numeric probabilities greater than zero enable fixed-length splitting. Custom selector functions remain manual-review inputs and are not executed by migration tooling.

Existing custom build scripts can also use `protectCode(options, code, fileName)` when they prefer the JavaScript Obfuscator API naming:

```js
const { protectCode } = require("jso-protector");

const protectedCode = await protectCode({
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced",
  reservedNames: ["^PublicApi$"]
}, sourceCode, "app.js");
```

For full build output, prefer the CLI or a bundle plugin so the release can remove stale source maps, write a manifest, and enforce size budgets.

## Replace bundler plugins

```js
const jsoProtector = require("jso-protector/vite");

module.exports = {
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      include: ["assets/*.js"],
      exclude: ["**/vendor/**"],
      manifest: "dist/jso-manifest.json",
      maxGrowthRatio: 8
    })
  ]
};
```

Equivalent entrypoints are available for Rollup, Webpack, Webpack loader, Browserify, esbuild, React Native (`jso-protector/react-native`), Gulp, and Grunt.

## Checklist

1. Run `jso-protector --release-check --json` and confirm the file list.
2. Run `jso-protector --competitor-gap-report --json` and decide whether runtime-defense review items, source-map policy, or identifier-cache gaps block the migration.
3. Exclude vendor bundles, polyfills, generated framework runtime files, and source maps.
4. Add `reservedNames` for public globals, framework entry points, and names called by external code.
5. Protect into a separate output folder first, then run browser smoke tests.
6. Add `manifest`, `maxOutputBytes`, or `maxGrowthRatio` once the protected output is stable.
7. Verify the protected artifact with `jso-protector --verify-manifest dist-protected/jso-manifest.json` before publishing or after unpacking CI artifacts.
