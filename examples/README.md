# jso-protector Examples

These examples show the common release patterns:

- `cli-basic`: protect a generated `dist/` folder after any build tool, with JSON and CommonJS config examples.
- `node-api`: protect a generated `dist/` folder from custom Node.js release scripts, including a typed release-summary script.
- `electron-app` scaffold: run `jso-protector --init --init-template electron-app` when an Electron packager writes a release folder that mixes Node-oriented JavaScript with copied app assets.
- `parcel`: run Parcel normally, then protect the generated `dist/` folder as a post-build release step.
- `bun`: run `bun build`, then protect the generated output folder through the Node API.
- `turbopack`: run `next build --turbopack`, then protect selected `.next/static/` chunks as a post-build release step.
- `browserify`: protect selected Browserify modules through a transform.
- `metro.config.js`: wrap Metro or Expo serializer output so React Native release bundles are protected.
- `react-native/metro.config.js`: use the React Native alias entrypoint when project docs or templates expect a dedicated React Native package path.
- `nextjs`: wrap `next.config.js` so production client bundles are protected automatically.
- `rspack`: protect emitted Rspack assets or selected modules through the Rspack loader alias.
- `vite`: protect emitted Vite chunks.
- `rollup`: protect emitted Rollup chunks.
- `esbuild`: protect esbuild output.
- `webpack`: protect emitted Webpack assets.
- `webpack-loader`: protect selected Webpack modules through a loader.
- `gulp`: protect files in a legacy Gulp release task.
- `grunt`: protect file mappings in a legacy Grunt release task.
- `payment-page-script-inventory.json`: starter source-free attachment for
  `jso-protector compliance pci-dss-v4 --script-inventory`. You can also
  generate a review starter from observed checkout scripts with
  `jso-protector --script-inventory-from-snapshot reports/runtime-inventory.json --script-inventory-output reports/payment-script-inventory.json`.
  In GitHub Actions, set the JSO action's `payment-script-inventory` and
  `runtime-inventory-snapshot` inputs to run the same drift audit as a
  source-free preflight gate.
- `payment-page-security-headers.json`: starter source-free attachment for
  `jso-protector compliance pci-dss-v4 --payment-page-headers`. Generate a
  current snapshot from a browser or synthetic-monitor HAR with
  `jso-protector --payment-page-headers-from-har reports/checkout.har --payment-page-headers-baseline reports/payment-page-headers.baseline.json --payment-page-headers-output reports/payment-page-headers.json`.
  `matchesBaseline` uses `match`, `mismatch`, or `missing` so reviewers can
  see whether a checkout page or frame changed from the approved baseline.

Install the published package before running examples:

```bash
npm install --save-dev jso-protector@0.4.2
```

Repository contributors can instead use the existing `file:../..` development
dependency in the self-contained example projects. Customer projects should use
the pinned registry version above.

All examples expect API credentials in environment variables:

```bash
set JSO_API_KEY=base64-api-key-from-dashboard
set JSO_API_PASSWORD=base64-api-password-from-dashboard
```

Use CI secrets for shared pipelines.

Run `npm run preflight` in `examples/cli-basic` before protection when you want one offline release check that validates config, confirms matched files/assets, and runs doctor checks without sending source code to the API.

Run `jso-protector --config jso.config.json --competitor-gap-report --json` after migrating from another obfuscator when you need a source-free report of runtime-defense, source-map, lock, and release-forensics parity gaps.

Use `jso.config.json` for schema-friendly static config. Use `jso.config.cjs` when CI needs environment-aware inputs, outputs, presets, or release domain settings. JavaScript config files execute as Node.js code, so only load them from trusted repositories.

For Parcel, Bun, and Turbopack, the examples intentionally use the generic Node API after the framework build completes. That keeps the package aligned with the current hosted-API workflow while still giving modern toolchains a copy-paste release recipe.

## Protected regions

Projects migrating from `javascript-obfuscator` can preserve source regions marked with conditional comments by setting `honorConditionalComments: true` in CLI, Node API, or build-plugin config. The protector sends only enabled regions to the hosted API and recomposes the original file afterward.

```js
jsoProtector({
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced",
  honorConditionalComments: true
});
```

```js
console.log("protect this");
// javascript-obfuscator:disable
console.log("leave this exact code alone");
// javascript-obfuscator:enable
```
