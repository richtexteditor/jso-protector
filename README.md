# jso-protector

Obfuscate and protect JavaScript as part of your build: a dependency-free CLI,
Node API, and plugins for webpack, Vite, Rollup, esbuild, Next.js, Metro, and
the rest of the toolchain.

```bash
npm install --save-dev jso-protector
npx jso-protector --input dist --output dist-protected
```

That protects every JavaScript file in `dist/` and writes the result to
`dist-protected/`. Nothing else in your build has to change.

## What you need

An API key and password from your [javascriptobfuscator.com](https://javascriptobfuscator.com/)
dashboard, passed as `--api-key` / `--api-password` or read from the
`JSO_API_KEY` and `JSO_API_PASSWORD` environment variables. Run
`npx jso-protector --doctor` to check credentials, paths, and file matching
before you wire it into CI.

## Already using another obfuscator?

Bring your configuration with you rather than rewriting it:

```bash
npx jso-protector --migrate-javascript-obfuscator javascript-obfuscator.json --output jso.config.json
npx jso-protector --migrate-js-confuser js-confuser.config.cjs --output jso.config.json
```

`--list-migration-map` prints how each option maps, `--explain-compat <option>`
explains a single one, and `--competitor-gap-report` prints covered, partial,
and missing parity against common JavaScript obfuscators.

## What this gives you that a static transform does not

- **Protect on your own machine.** `--local` runs the bundled `jso-local`
  executable instead of sending source to the hosted API.
- **Reproducible when you need it.** `--seed <value>` makes the same input,
  options, and seed produce byte-identical output; omit it for the default
  per-build polymorphic output.
- **Evidence you can hand to a reviewer.** `--ai-resistance-evidence`,
  `--source-map-evidence`, `--vm-proof-pack`, `--deployment-hygiene-evidence`,
  and `--runtime-incident-evidence` turn a build into a written report.
- **Presets instead of forty switches.** `--preset standard|balanced|maximum`,
  or import a preset exported from the online tool with `--web-preset`.
- **Different profiles in one build.** `namedSets` maps file globs to their own
  preset and options, so a checkout flow can ship maximum protection while
  marketing pages stay on standard.

Full option reference: [Docs / npm CLI](https://javascriptobfuscator.com/docs/npmcli.aspx)
and [Docs / npm options](https://javascriptobfuscator.com/docs/npmoptions.aspx).

## Quick Start

```bash
npm install --save-dev jso-protector
npx jso-protector --init
```

`--init` writes a starter `jso.config.json`. It supports templates for common
release layouts:

- `browser-app`: default browser build output in `dist/`
- `html-app`: browser build output plus marked inline HTML/template script protection
- `node-app`: Node.js release output with `.js`, `.cjs`, and `.mjs` extensions
- `electron-app`: Electron release folders with Node-oriented JavaScript plus copied app assets
- `nextjs-app`: Next.js production client chunks in `.next/static/` with framework runtime exclusions
- `vite-app`: Vite/Rollup-style browser chunks in `dist/` with copied release assets
- `parcel-app`: Parcel post-build browser output in `dist/` with copied release assets
- `bun-app`: Bun browser-oriented release output in `dist/` with `.js` and `.mjs` targeting
- `browserify-app`: Browserify release bundles in `dist/` with copied assets and wrapper-name exclusions
- `webpack-app`: Webpack release output in `dist/` with copied assets and webpack chunk-name preservation
- `rspack-app`: Rspack release output in `dist/` with copied assets and webpack-compatible chunk-name preservation
- `turbopack-app`: Next.js Turbopack production client chunks in `.next/static/` with `chunks/*.js` and nested `chunks/**/*.js` targeting
- `react-native-app`: Metro/Expo release bundle outputs with mobile-oriented optimization defaults

Combine `--init` with normal flags to scaffold a closer first draft:

```bash
npx jso-protector --init --init-template node-app --input build --output build-protected --manifest build-protected/jso-manifest.json
npx jso-protector --init --init-template electron-app --input out --output out-protected --manifest out-protected/jso-manifest.json
npx jso-protector --init --init-template next --manifest .next/static-protected/jso-manifest.json
npx jso-protector --init --init-template vite --manifest dist-protected/jso-manifest.json
npx jso-protector --init --init-template turbopack --manifest .next/static-protected/jso-manifest.json
npx jso-protector --init --init-template expo --input dist --output dist-protected
```

## CI release tagging and crash symbolication

Two CLI flags help wire `jso-protector` into a CI pipeline that has to debug production crashes later:

- `--label <value>` tags the API request with a release label. The label appears as `ReleaseLabel` in the JSO dashboard audit log, so support tickets can be tied back to a specific commit. Typical CI usage:

  ```bash
  jso-protector --input dist --output dist-protected --label "$GITHUB_SHA"
  ```

  Also reads `JSO_LABEL` / `JAVASCRIPT_OBFUSCATOR_LABEL` from the environment, so CI runners with the variable already set don't have to add a flag.

- `--report <file>` writes the full API response JSON to a path. The report carries `BuildId`, `PolymorphismFingerprint`, the `GlobalIdentifierMap` / `MemberIdentifierMap` arrays, compatibility findings, and audit metadata. Pair with [`jso-symbolicate`](https://www.npmjs.com/package/jso-symbolicate) to demangle stack traces against the same build.

  ```bash
  jso-protector --input dist --output dist-protected --label "$GITHUB_SHA" --report dist-protected/jso-report.json
  jso-protector --verify-vm-proof dist-protected/jso-report.json --json
  jso-protector --vm-proof-pack dist-protected/jso-report.json --vm-proof-output reports/vm-proof-pack.md
  jso-protector --ai-resistance-evidence dist-protected/jso-report.json --ai-resistance-evidence-output reports/ai-resistance-evidence.md
  # later, when a crash arrives:
  npx jso-symbolicate --map dist-protected/jso-report.json --stack crash.txt
  npx jso-symbolicate --map dist-protected/jso-report.json --event sentry --event-file sentry-event.json > sentry-event.demangled.json
  ```

  Upload `dist-protected/jso-report.json` as a build artifact alongside the protected JS so the demangling map is available wherever crash triage happens. For VM beta reviews, `--verify-vm-proof` checks that the source-free report shows `UseVMProtection`, `VMProtectionApplied`, a non-zero virtualized function count, and no unresolved VM warnings. `--vm-proof-pack` turns the same report into a Markdown or JSON reviewer packet with build identity, release label, polymorphism fingerprint, VM pass/fail checklist, review decision, warnings, hot-path/cold-path guidance, recommendations, and a VM Proof Review Assistant for BYO AI or internal reviewers.
  For AI-resistance reviews, `--ai-resistance-evidence` turns the same source-free report into a current evidence checklist: build identity, strong protection options, optional VM proof, runtime-defense evidence, compatibility evidence, a non-scoring attacker-model review matrix, review decision, claim boundaries, a Review Assistant Packet for BYO AI or internal reviewers, and a clear `scoreStatus` that says the Resistance Score is still planned. Add `--ai-resistance-evidence-output reports/ai-resistance-evidence.md` for a reviewer artifact, `--json` for machine-readable evidence, and `--require-vm-proof` when VM-backed evidence must be a hard CI gate.

The [JSO GitHub Action](https://github.com/marketplace/actions/javascript-obfuscator)
wraps the saved-report workflow too: `report-path`, `vm-proof-pack-report`,
and `ai-resistance-evidence-report` outputs let CI upload source-free reviewer
artifacts beside the protected build, while `build-id` and
`polymorphism-fingerprint` remain available for runtime crash correlation.

## Payment-page evidence reports

For checkout, wallet, subscription, activation, and license pages, pair the
signed release manifest with a payment-page script inventory and Dashboard
Monitoring incident history. Export runtime incidents CSV or JSON from the
dashboard, keep a CSV or JSON list of payment-page scripts with authorization
and written justification, and attach a payment-page security-header snapshot
when reviewers ask for CSP/header change evidence. Include these source-free
attachments in the PCI DSS v4 report. Start from
`examples/payment-page-script-inventory.json` and
`examples/payment-page-security-headers.json` when you need the expected JSON
field names, or generate a review starter from a saved
`third-party-inventory` runtime snapshot:

```bash
npx jso-protector \
  --script-inventory-from-snapshot reports/runtime-inventory.json \
  --script-inventory-output reports/payment-script-inventory.json
```

If your checkout evidence starts as a browser or synthetic-monitor HAR export,
convert the document and iframe responses into the same source-free
security-header snapshot. The converter keeps CSP, HSTS, frame/referrer policy,
reporting endpoint, and related security headers, drops raw cookies and other
non-security headers, and stores a SHA-256 over each canonical selected-header
snapshot. Keep the last approved snapshot in your evidence repository and pass
it as `--payment-page-headers-baseline` when you want the new HAR export to
mark each checkout page or frame as `match`, `mismatch`, or `missing` for
security-header change review. The generated snapshot also includes a
source-free security-header Review Assistant Packet for BYO AI or internal
reviewers. It focuses the review on baseline drift, CSP/reporting, HSTS, and
frame-policy owner actions while reminding teams not to include
raw response headers, cookies, source code, payment data, customer data, provider keys, or
secrets.

```bash
npx jso-protector \
  --payment-page-headers-from-har reports/checkout.har \
  --payment-page-headers-baseline reports/payment-page-headers.baseline.json \
  --payment-page-headers-output reports/payment-page-headers.json \
  --payment-page-url-pattern "checkout|payment|wallet"
```

Review the generated script inventory file before audit use. Set `authorized`, add written
`justification`, assign `owner`, and fill `lastReviewedUtc` for every approved
payment-page script. Add `risk`, `dataAccess`, and `approvalTicket` when your
checkout review process tracks risk-based decisions or change approvals. Add
`checkoutSurface`, `frameContext`, `frameOwner`, `parentPageHref`, `frameHref`,
and `frameOrigin` when your payment flow has a parent page, hosted checkout
page, PSP iframe, or embedded payment frame that reviewers need to distinguish.
The
audit packet fails only on blocking script drift or required metadata gaps; it
also calls out missing optional review context so checkout owners can improve
QSA handoff quality without breaking an otherwise clean release. Before handing
the packet to reviewers, reconcile the approved inventory against a fresh
runtime snapshot:

```bash
npx jso-protector \
  --script-inventory-audit reports/payment-script-inventory.json \
  --runtime-inventory-snapshot reports/runtime-inventory.json \
  --script-inventory-audit-output reports/payment-script-inventory-audit.json \
  --json
```

The audit is local and source-free. It reports unknown observed scripts,
scripts observed while marked unauthorized, approved scripts missing from the
page, hash mismatches, scripts injected after page load, runtime violation
reasons, and missing inventory metadata. Omit `--json` or use a `.md` output
path when a standalone human-readable packet is preferred.

In GitHub Actions, the bundled JSO action exposes the same audit,
security-header snapshot, and PCI DSS v4 reviewer packet as opt-in workflow
steps: set
`payment-script-inventory`, `runtime-inventory-snapshot`, and optionally
`script-inventory-audit-report` to fail the release job on payment-page script
drift; set `payment-page-har`, optionally `payment-page-url-pattern`, and
optionally `payment-page-headers-baseline` and `payment-page-headers-report` to
convert a checkout HAR into the same source-free header evidence artifact and
mark baseline matches, mismatches, or missing pages; set `pci-dss-v4-evidence` with
`pci-dss-v4-report` and `pci-dss-v4-json-report` to assemble the Markdown and
JSON PCI evidence report from the protected manifest plus those attachments.
Use `manifest`, `sign-release-key`, `watermark`, and `watermark-key` when this
report needs to pass rather than document incomplete evidence. The action adds
a step summary and workflow annotations for the first audit, header, or PCI
findings so reviewers can see drift directly in the CI run.

```bash
npx jso-protector compliance pci-dss-v4 \
  --manifest dist-protected/jso-manifest.json.sig \
  --root dist-protected \
  --watermark-key "$JSO_WATERMARK_KEY" \
  --beacon-url "https://javascriptobfuscator.com/v1/runtime/beacon.ashx" \
  --siem splunk-hec \
  --script-inventory reports/payment-script-inventory.json \
  --script-inventory-audit reports/payment-script-inventory-audit.json \
  --payment-page-headers reports/payment-page-headers.json \
  --runtime-incidents reports/runtime-incidents.json \
  --organization "Example Corp" \
  --output reports/pci-dss-v4.md
```

The report hashes and summarizes these attachments, then adds a source-free PCI
DSS Review Assistant for BYO AI or internal reviewers. The assistant turns
evidence gaps, signed-release proof, script authorization, observed script
drift, header change evidence, runtime incident routing, and QSA handoff
boundaries into checkout-owner actions without sharing source code, protected
output, raw script rows, raw response headers, raw incident payloads,
payment-card data, provider keys, customer data, or secrets. Script inventory evidence is
summarized by authorization, justification, owner, domain, review range, and
integrity-reference coverage. When the inventory includes `risk`, `dataAccess`,
`approvalTicket`, `checkoutSurface`, `frameContext`, and `frameOwner`, the
report summarizes those fields, including iframe-scoped script counts, without
embedding every script row. Security-header evidence is summarized by CSP,
`script-src`, `frame-src`, reporting endpoint, HSTS, referrer-policy,
baseline-hash match/mismatch/missing state, checkout surface, frame context, monitor, alert
route, domain, observed range, and SHA-256 without embedding every raw page
row. Runtime incident evidence is summarized by status, severity,
open/reviewing count, per-incident next owner and due state, repeated-signal correlation, date range, Build IDs, and SHA-256. The Markdown does not
embed every incident URL, user agent, script row, or raw header snapshot, so it
can be handed to reviewers while the CSV or JSON exports remain the source-free
attachments. The report supports QSA-led assessment; it is not itself a Report
on Compliance.
When a Dashboard Monitoring JSON export includes filters such as
`runtime_status=active`, `runtime_severity=high-critical`, or
`runtime_build=checkout-2026-06-07`, the report keeps that filter context in
the runtime incident evidence table. The Dashboard JSON export also carries a
source-free summary block with status/severity counts, active high-risk count,
payload-hash coverage, BuildIDs, event/received date ranges, per-incident action-plan owner/due/status metadata, repeated fingerprint/reason groups, a routing
recommendation, an alert routing playbook, and a response checklist before the incident rows. Dashboard
Monitoring shows the same routing recommendation on the current filtered view
before export, including response target, next status action, and playbook
lanes for security response, customer-owned alerting, support handoff, and
reviewer packets. The JSON export also includes source-free dashboard action
metadata, such as the filtered "Move open in view to Reviewing" status action,
plus per-row action plans that name the next owner, evidence packet, response due state, and status move, so support automation can tell account owners what to do next without scraping
dashboard HTML. The PCI
evidence report preserves those Dashboard JSON fields so support and reviewers
can see whether the packet belongs in runtime triage, security response, or
archive evidence. The response checklist and alert routing playbook carry
owners, response targets, scope confirmation, downstream routing, and
safe-sharing boundaries for reviewer
or on-call handoff. A single-row Dashboard Monitoring Evidence JSON packet can also be passed to
`--runtime-incidents` when the review is about one specific event.

For non-PCI runtime reviews, generate a standalone source-free handoff packet
directly from the Dashboard Monitoring export:

```bash
npx jso-protector \
  --runtime-incident-evidence reports/runtime-incidents.json \
  --runtime-incident-evidence-output reports/runtime-incident-evidence.md
```

The packet summarizes status and severity counts, active high/critical count,
BuildIDs, per-incident action plans, repeated-signal correlation, routing recommendation, dashboard actions,
response window, response checklist, alert routing playbook, export SHA-256, and safe-sharing boundaries.
It also includes a source-free Runtime Incident Review Assistant for BYO AI or
internal reviewers, with prompts for urgent response, repeated-signal
correlation, overdue incident owners, dashboard status actions, response-window decisions, and
alert-routing handoff without sharing source code, raw incident payloads,
collector tokens, customer data, or secrets.
It exits nonzero when active high/critical incidents are present so CI can
block reviewer handoff until the incident is acknowledged and routed.

In GitHub Actions, the bundled JSO action exposes the same gate as
`runtime-incident-export` plus `runtime-incident-evidence-report`. The action
writes a source-free JSON artifact, adds a step summary and annotations, and
fails the job when the exported packet contains active high/critical runtime
incidents that have not started response.

## Deployment Hygiene Evidence

When `tools/Build-UpdatedArchives.ps1 -ReportPath _temp/archive-hygiene.json`
creates an updated-files archive hygiene report, turn it into a source-free
reviewer packet before sharing the zip:

```bash
npx jso-protector \
  --deployment-hygiene-evidence _temp/archive-hygiene.json \
  --deployment-hygiene-output reports/deployment-hygiene.md
```

The packet summarizes archive names, entry counts, byte sizes, missing required
entries, blocked entries, blocked category booleans, the exclusion policy,
operator checklist, rotation triggers, hygiene-report SHA-256, and a Deployment Hygiene Review Assistant for BYO AI or internal reviewers. It does not include
`Web.config` contents, raw secrets, provider keys, webhook signing secrets,
database strings, host-specific deployment transforms, customer data, or source
code. It exits nonzero when the archive builder reported blocked deployment
files or missing required entries, while still writing the failed packet for
internal remediation.

## Payment and API Access

`jso-protector` is a localhost developer client for the paid JavaScript Obfuscator service: it drives the hosted API by default, or the bundled `jso-local` protector with `--local`. The npm package does not unlock protection by itself and does not contain payment logic.

Payment and account enforcement stay on `javascriptobfuscator.com`:

1. The user buys a plan or credits on the JavaScript Obfuscator website.
2. The dashboard provides `JSO_API_KEY` and `JSO_API_PASSWORD`.
3. By default the local npm CLI sends selected JavaScript to the configured HTTPS API endpoint.
4. The hosted API validates the account, plan, limits, and credentials before returning protected code.

With `--local` the source body stays on the build machine and step 3 does not
happen, but entitlement is still enforced server-side: the run makes a
source-free plan/option check before protecting. Either way, billing and plan
limits live on the server, never in this package.

Keep billing, entitlement checks, plan limits, and API secrets on the server side. The local npm package should only read credentials from environment variables or config and call the API.

If the hosted API rejects a request, the CLI reports dashboard credential hints for authentication failures and account/plan/credit guidance for entitlement failures. API keys and passwords are redacted from error messages before they reach terminal logs.

Set credentials from the dashboard:

```bash
set JSO_API_KEY=base64-api-key-from-dashboard
set JSO_API_PASSWORD=base64-api-password-from-dashboard
```

For macOS/Linux shells:

```bash
export JSO_API_KEY=base64-api-key-from-dashboard
export JSO_API_PASSWORD=base64-api-password-from-dashboard
```

Protect generated build output:

```bash
npx jso-protector --config jso.config.json
```

### Runtime recovery and enterprise governance foundations

Browser-targeted API options now support bounded local recovery with
`SelfDefending`, `SelfHealing`, and `SelfHealingMaxAttempts`. A successful
repair emits a `self-healed-*` runtime event; when repair is unavailable or
exhausted, `RuntimeDefenseAction` can use `throw`, `blank`, `redirect`,
`reload`, `callback`, or `degrade`. Local recovery handles mutation after the
wrapper starts and does not claim to repair a bundle modified before startup.

Release automation can import `jso-protector/governance` for shared RBAC,
scoped-token descriptors, SHA-256 hash-chained audit events, validated
OIDC/SAML trust configuration, an organization directory, and a SCIM 2.0
`/Users` service core with bearer authentication, filtering, role updates, and
deactivation. Deployments still need to mount the service behind HTTPS and
persist directory changes in their account store.

`jso-protector/runtime/third-party-inventory` supports
`enforcementMode: "block"` for synchronous origin and late-injection decisions
on dynamically-created scripts. `jso-protector/runtime/managed-integrity` adds
versioned monitor/block policies, inventory evaluation, deduplicated incidents,
assignment/status transitions, and JSON export for hosted or on-prem operations.
`jso-protector/runtime/data-exfiltration-guard` adds opt-in monitor/block controls
for protected-field data sent through fetch, XHR, sendBeacon, WebSocket, or
programmatic form submission. Allow approved destinations explicitly and begin
in monitor mode. Evidence contains field names and counts, never captured values
or request bodies; encoded/encrypted bodies and script attribution remain stated
browser-runtime limitations.

Compare a migrated config against common JavaScript obfuscator capabilities:

```bash
npx jso-protector --config jso.config.json --competitor-gap-report
npx jso-protector --config jso.config.json --competitor-gap-report --json
npx jso-protector --config jso.config.json --migration-review \
  --migration-review-output reports/migration-review.md
npx jso-protector --config jso.config.json --identifier-cache-review \
  --identifier-cache-review-output reports/identifier-cache-review.md
npx jso-protector --config jso.config.json --runtime-defense-review \
  --runtime-defense-review-output reports/runtime-defense-review.md
```

The gap report groups parity into covered, partial, and gap areas across common
competitor surfaces such as control-flow flattening, string hiding, domain/date
locks, runtime monitoring, hosted dashboard intake, countermeasures, source
maps, and release forensics. It names Obfuscator.io, javascript-obfuscator,
JS-Confuser, Jscrambler, and JSDefender so migration reviews can separate exact
matches from features that need manual validation. Runtime-defense parity is
reported as partial: route `RuntimeDefenseBeaconUrl` to your monitoring stack
or the hosted `/v1/runtime/beacon.ashx` intake for first triage, then validate
any migrated anti-debug/self-defending switches manually. Use it after
`--migrate-javascript-obfuscator` or `--migrate-js-confuser` to keep
runtime-defense, source-map, and release-readiness assumptions visible in CI.
The JSON and text output include a dated source snapshot of the public
competitor pages reviewed for this migration framing, plus a reminder to
re-check current vendor pages before publishing named competitive claims.
The report also includes a source-free Competitor Gap Review Assistant for BYO
AI or internal reviewers. It turns gap prioritization, partial-parity
validation, triggered migration limitations, source-reading scan boundaries,
vendor-claim freshness, and plan handoff into owner actions without sharing
source code, protected output, API credentials, provider keys, customer data,
or secrets.
When source-map, identifier-cache, custom-dictionary, or runtime-defense
limitations are present, the report also includes `reviewArtifacts`: source-free
release-check, competitor-gap, all-up migration-review, source-map-evidence,
and identifier-cache replacement review commands, a source-free runtime-defense
review command, and a separate source-reading compatibility scan when
runtime-defense switches need manual validation.
Use `--migration-review` when a migrated config still carries any accepted
competitor-only fields. The generated Markdown packet gives release owners one
source-free checklist across source-map policy, identifier-cache replacement,
runtime-defense behavior, CLI compatibility warnings, saved report/manifest
readiness, follow-up commands, and protected-build smoke evidence without
embedding source code, protected output, source-map contents, cache contents,
dictionary values, prefixes, domains, URLs, dates, seed values, or reserved
expressions. The packet includes a Migration Review Assistant for BYO AI or
internal reviewers, turning manual review tracks, source-map policy,
identifier-cache replacement, runtime-defense behavior, source-reading command
boundaries, release metadata, and protected-build smoke into owner actions
without sharing raw config files, API credentials, provider keys, customer data,
or secrets.
Use `--identifier-cache-review` when a migrated config still carries
`identifierNamesCache`, `identifierNamesCachePath`, `identifiersDictionary`, or
`identifiersPrefix`. The generated Markdown packet gives release owners a
source-free checklist for replacing deterministic cache assumptions with
reserved-name review, saved API report, release manifest, and protected-build
smoke evidence without embedding cache contents, dictionary values, prefixes,
reserved-name expressions, or source code. It includes an Identifier Cache
Review Assistant for BYO AI or internal reviewers, turning deterministic cache
assumptions, custom dictionary replacement, reserved-name coverage, release
metadata, and protected-build smoke into owner actions without sharing raw
config files, API credentials, provider keys, customer data, or secrets.
Use `--runtime-defense-review` when a migrated config still carries anti-debug,
self-defending, runtime lock, console, and countermeasure migration settings.
The generated packet lists field names, configured evidence tracks, review
decision, monitoring and smoke-test follow-ups, and safe-sharing boundaries
without embedding domains, dates, redirect URLs, beacon URLs, countermeasure
values, source code, or protected output. It includes a Runtime Defense Review
Assistant for BYO AI or internal reviewers, turning runtime behavior scope,
monitoring handoff, countermeasure policy, domain/date lock smoke,
source-reading compatibility scan, release metadata, and protected-build smoke
into owner actions without sharing raw config files, API credentials, provider
keys, collector tokens, customer data, or secrets.

Protect one file through a shell pipe:

```bash
type dist\app.js | npx jso-protector --stdin --stdout --file-name app.js > dist\app.protected.js
```

## npm Scripts

```json
{
  "scripts": {
    "build": "vite build",
    "preflight": "jso-protector --config jso.config.json --release-check --json",
    "protect": "jso-protector --config jso.config.json",
    "release": "npm run build && npm run preflight && npm run protect && npm run smoke"
  }
}
```

## Node API

Use the API when you want to protect code or release folders from a custom build script without spawning the CLI:

```js
const { obfuscate, obfuscateMultiple, getOptionsByPreset, protectCode, protectFiles, planProtection } = require("jso-protector");

const obfuscationResult = await obfuscate("console.log('release');", {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  controlFlowFlattening: true,
  identifierNamesGenerator: "hexadecimal",
  reservedNames: ["^PublicApi$"],
  stringArrayEncoding: ["rc4"]
}, "app.js");

console.log(obfuscationResult.getObfuscatedCode());
console.log(obfuscationResult.toString());

const multipleResults = await obfuscateMultiple({
  "foo.js": "var foo = 1;",
  "bar.js": "var bar = 2;"
}, {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  ...getOptionsByPreset("balanced")
});

console.log(multipleResults["foo.js"].getObfuscatedCode());

const protectedCode = await protectCode({
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced"
}, "console.log('release');", "app.js");

const plan = planProtection({
  input: "dist",
  output: "dist-protected",
  preset: "balanced",
  exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"]
});

console.log(`Protecting ${plan.summary.files.length} file(s).`);

await protectFiles({
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  input: "dist",
  output: "dist-protected",
  preset: "balanced",
  manifest: "dist-protected/jso-manifest.json"
});
```

Use `obfuscate(code, options, fileName)` and `obfuscateMultiple(sourceCodesObject, options)` when migrating from `javascript-obfuscator` style Node scripts. These methods are asynchronous because they call the hosted API, and their result objects include `getObfuscatedCode()`, `toString()`, `getSourceMap()`, and `getIdentifierNamesCache()` for compatibility-friendly call sites. They use the same marked HTML and inline planning as the CLI, so `parseHtml`, `honorConditionalComments`, and `protectMarkedComments` work for object-map inputs too. Source maps and identifier caches return `null` because the hosted API workflow is designed to remove release source maps.

The Node API accepts common `javascript-obfuscator` option names directly and maps them to the closest hosted API options. Supported compatibility keys include `optionsPreset`, `parseHtml`, `stringArray`, `stringArrayEncoding`, `controlFlowFlattening`, `deadCodeInjection`, `deadCodeInjectionThreshold`, `identifierNamesGenerator`, `renameGlobals`, `renameProperties`, `reservedNames`, `domainLock`, `compact`, and `target`. Use `translateJavascriptObfuscatorOptions(sourceOptions, overrides)` when you want to inspect or reuse the mapped config before calling the API.

`stringArrayIndexShift` maps approximately to native `StringArrayIndexShift`: enabled builds use a deterministic nonzero one-slot offset in plain and encrypted string tables. This does not reproduce the competitor's randomized shift magnitude, so validate the protected build in its target runtime.

`stringArrayShuffle` maps directly to native `StringArrayShuffle`. It randomizes unique moved-string order and preserves every lookup across plain, encrypted, shifted, and self-compressed output. Default builds use fresh entropy; `Seed` makes the shuffle reproducible.

`stringArrayRotate` maps directly to native `StringArrayRotate`. It cyclically rotates multi-value tables by a nonzero per-build offset and rewrites every lookup. Rotation uses an independent entropy stream, composes with shuffle/index shifting/encryption, and is reproducible under `Seed`.

`stringArrayIndexesType` maps directly to native `StringArrayIndexesType`. Use `hexadecimal-number`, `hexadecimal-numeric-string`, or both. Numeric strings are explicitly coerced before array access; mixed lists select a type per lookup and become reproducible when `Seed` is supplied.

`stringArrayThreshold` maps directly to native `StringArrayThreshold`. It accepts 0 through 1 and makes one stable decision per unique eligible literal. Zero keeps all literals verbatim, one moves all eligible literals, duplicates stay consistent, and `Seed` makes partial selection reproducible.

`stringArrayCallsTransform` maps directly to native secondary index-table indirection, with `stringArrayCallsTransformThreshold` controlling per-lookup probability from 0 through 1. Selected calls become nested table lookups, the default threshold is 0.5, and `Seed` makes selection reproducible. The transform composes with all native moved-string storage and output modes.

String-array wrapper controls generate bounded root-level aliases or multi-parameter functions. Counts are limited to 0-10, function parameters to 2-5, and chaining can route each wrapper through its predecessor. The count mapping is approximate: unlike the competitor's per-function-scope placement, JSO keeps wrappers at the protected root. Selection and noise parameters are reproducible under `Seed`.

`transformObjectKeys` maps approximately to native safe data-key transformation. Identifier and quoted data keys become computed moved-string lookups; numeric keys, methods/accessors, shorthand-sensitive members, and `__proto__` stay literal to avoid changing property and prototype behavior.

For JS-Confuser migration scripts, pass a `jsConfuserOptions` object or call `translateJsConfuserOptions(sourceOptions, overrides)` first. The Node API also detects common top-level JS-Confuser options directly, including the `lock` bag, so existing build scripts can migrate with smaller edits. In addition to common transform and date/domain settings, `lock.antiDebug`, `lock.integrity`, `lock.selfDefending`, and `lock.tamperProtection` map to `DebugProtection`, `SelfDefending`, and `AntiMonkeyPatching`; `lock.startDate` maps to the native activation boundary. These runtime mappings are approximate: JS-Confuser numeric probabilities collapse to enabled/disabled and vendor-specific detection behavior still requires protected-browser testing. Arbitrary `lock.countermeasures` and custom locks remain review-only rather than being executed or guessed.

JS-Confuser `stringSplitting` also maps approximately to native `SplitStrings`. Boolean values map directly; numeric probabilities greater than zero enable splitting because the native engine does not reproduce per-literal probability scheduling. Custom selector functions require manual migration review and are never executed by translation tooling.

`getOptionsByPreset("standard" | "balanced" | "maximum")` returns a copy of the hosted API preset options for scripts that previously used preset lookup helpers.

Use `protectFile(options, sourcePath, outputPath)` for one physical source file, `protectFiles(options)` for a file or folder configured with `input` and `output`, and `planProtection(options)` when CI needs a dry plan before making the API call. The `obfuscateFile`, `obfuscateFiles`, and `obfuscateDirectory` aliases are available for teams that prefer obfuscator naming. These helpers use the same config merging, preset handling, asset copying, manifest writing, and size budget checks as the CLI.

TypeScript declarations are included for the CLI core, Node API, Browserify, Metro/React Native, esbuild/Vite/Rollup/Webpack/Rspack/Gulp/Grunt integrations, and the Webpack/Rspack loader entrypoints. No separate `@types` package is needed.

## Rspack

Use the Rspack entrypoint when a webpack-compatible Rust build should protect emitted JavaScript assets through the same final-asset stage used by the Webpack plugin.

```js
const JsoProtectorRspackPlugin = require("jso-protector/rspack");

module.exports = {
  plugins: [
    new JsoProtectorRspackPlugin({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json"
    })
  ]
};
```

Use `jso-protector/rspack-loader` when a Rspack project needs module-level protection before bundling. For complete release bundles, prefer the Rspack plugin so final emitted assets and stale source maps are handled together.

## Browserify

Use the Browserify transform when a legacy bundle protects selected modules before bundling:

```js
const browserify = require("browserify");
const fs = require("fs");
const jsoProtector = require("jso-protector/browserify");

browserify("src/app.js", {
  transform: [[jsoProtector, {
    apiKey: process.env.JSO_API_KEY,
    apiPassword: process.env.JSO_API_PASSWORD,
    input: "src",
    preset: "balanced",
    include: ["**/*.js"],
    reservedNames: ["^PublicApi$"],
    manifest: "dist/jso-manifest.json"
  }]]
})
  .bundle()
  .pipe(fs.createWriteStream("dist/app.js"));
```

The transform passes excluded files through untouched, protects selected JavaScript modules, and honors config files, filters, manifests, and size budgets. It respects configured protected extensions, so `.mjs` and `.cjs` module pipelines can opt in through `extensions`.

## Next.js

Use the Next.js entrypoint when you want a first-class wrapper around `next.config.js` instead of wiring the Webpack plugin manually. By default, it adds protection only for production client bundles.

```js
const withJsoProtector = require("jso-protector/next");

module.exports = withJsoProtector({
  reactStrictMode: true
}, {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced",
  exclude: ["static/chunks/webpack*.js"],
  manifest: ".next/jso-manifest.json"
});
```

Pass `target: "server"` to protect only server bundles or `target: "both"` to protect both server and client output. Development builds are skipped by default; pass `applyInDevelopment: true` only when you explicitly want protection during `next dev`.

## Metro / React Native

Use the Metro entrypoint when React Native or Expo projects need to protect the final release bundle through `serializer.customSerializer`.

```js
const { getDefaultConfig, mergeConfig } = require("@react-native/metro-config");
const { withJsoProtectorMetro } = require("jso-protector/metro");

const baseConfig = getDefaultConfig(__dirname);

module.exports = withJsoProtectorMetro(mergeConfig(baseConfig, {}), {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced",
  include: ["index.android.release.bundle.js", "index.ios.release.bundle.js"]
});
```

When you already have a serializer function, wrap it directly:

```js
const { getDefaultConfig } = require("expo/metro-config");
const { createMetroSerializer } = require("jso-protector/metro");

const config = getDefaultConfig(__dirname);
const expoSerializer = config.serializer.customSerializer;

config.serializer.customSerializer = createMetroSerializer({
  serializer: expoSerializer,
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  fileName: "index.android.release.bundle.js"
});

module.exports = config;
```

The Metro helper protects only matching bundle names and removes stale source maps from object-style serializer results unless `removeSourceMaps: false` is set. When maps are removed, stale `sourceMappingURL` comments are stripped from the protected bundle output too.

If you prefer a framework-specific package path for React Native docs or starter templates, `jso-protector/react-native` is an alias of `jso-protector/metro`:

```js
const { withJsoProtectorMetro } = require("jso-protector/react-native");
```

## esbuild

Use the esbuild entrypoint for direct esbuild release builds. It protects in-memory output files when `write: false` is used, and protects written `outdir` or `outfile` assets in place for normal builds.

```js
const esbuild = require("esbuild");
const jsoProtector = require("jso-protector/esbuild");

await esbuild.build({
  entryPoints: ["src/app.js"],
  bundle: true,
  outdir: "dist",
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json"
    })
  ]
});
```

The esbuild plugin respects configured protected extensions, so Node-oriented bundles can opt into `.mjs` or `.cjs` outputs through `extensions`.

## Parcel, Bun, and Turbopack

Parcel, Bun, and Turbopack do not need a dedicated runtime wrapper when your release flow already emits JavaScript files or chunks to disk. Run the framework build first, then protect the generated output folder through the Node API or CLI.

For Parcel builds that write `dist/`, use a post-build release script:

```js
const protectParcelBuild = require("jso-protector/parcel");

const options = {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD
};

const plan = protectParcelBuild.planParcelBuild(options);
console.log(`Protecting ${plan.summary.files.length} Parcel file(s).`);
await protectParcelBuild(options);
```

For Bun builds, keep the same post-build pattern after `bun build`:

```json
{
  "scripts": {
    "build": "bun build ./src/index.ts --outdir ./dist --target browser",
    "protect": "node ./scripts/protect-release.js",
    "release": "bun run build && node ./scripts/protect-release.js --plan && node ./scripts/protect-release.js"
  }
}
```

```js
const protectBunBuild = require("jso-protector/bun");

await protectBunBuild({
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD
});
```

For Next.js projects that use Turbopack in production, protect the emitted `.next/static/` chunks after `next build --turbopack` while excluding framework runtime files that should stay untouched:

```js
const protectTurbopackBuild = require("jso-protector/turbopack");

await protectTurbopackBuild({
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD
});
```

Copyable starter files for these post-build flows are included in `examples/parcel`, `examples/bun`, and `examples/turbopack`.

## Vite

Protect emitted JavaScript chunks after Vite finishes bundling:

```js
const jsoProtector = require("jso-protector/vite");

module.exports = {
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["**/vendor/**"],
      manifest: "dist/jso-manifest.json"
    })
  ]
};
```

The plugin removes stale JavaScript source maps by default. Pass `removeSourceMaps: false` only when another step regenerates or removes maps. When maps are removed, stale `sourceMappingURL` comments are stripped from the protected JavaScript so release artifacts do not point at missing `.map` files.

Bundler plugins use the same protection planner as the CLI and Node API, so `honorConditionalComments` and `protectMarkedComments` preserve marked JavaScript regions before chunks are sent to the hosted API.

## Rollup

Use the Rollup entrypoint when your release build writes Rollup chunks directly:

```js
const jsoProtector = require("jso-protector/rollup");

module.exports = {
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json"
    })
  ]
};
```

## Webpack

Protect emitted JavaScript assets during the final asset phase. The plugin supports Webpack 5 through `processAssets` and falls back to the legacy `emit` hook for Webpack 4 projects:

```js
const JsoProtectorWebpackPlugin = require("jso-protector/webpack");

module.exports = {
  plugins: [
    new JsoProtectorWebpackPlugin({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json"
    })
  ]
};
```

Like the Vite plugin, the Webpack plugin removes stale emitted source maps by default and strips stale `sourceMappingURL` comments from the protected assets. It respects configured protected extensions for emitted assets, so `.mjs` and `.cjs` library outputs can use the same plugin path. One package can cover both Webpack 4 and Webpack 5 release builds.

## Webpack Loader

Use the loader when a Webpack project already protects selected modules before bundling. For complete release bundles, prefer the Webpack plugin because it protects final emitted assets and removes stale source maps.

```js
module.exports = {
  module: {
    rules: [{
      test: /\.js$/,
      include: /src/,
      use: [{
        loader: "jso-protector/webpack-loader",
        options: {
          apiKey: process.env.JSO_API_KEY,
          apiPassword: process.env.JSO_API_PASSWORD,
          preset: "balanced",
          include: ["src/*.js"],
          reservedNames: ["^PublicApi$"]
        }
      }]
    }]
  }
};
```

The loader disables Webpack caching for protected modules, returns no source map after protection, strips stale `sourceMappingURL` comments unless `removeSourceMaps: false` is set, and honors config files, `extensions`, `include`, `exclude`, manifests, and size budgets.

## Gulp

Use the Gulp entrypoint when a legacy release task copies files through Vinyl streams:

```js
const { dest, src } = require("gulp");
const jsoProtector = require("jso-protector/gulp");

function protect() {
  return src(["dist/**/*.js", "dist/**/*.{css,html,png,svg}", "!dist/**/*.map"], { base: "dist" })
    .pipe(jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["**/vendor/**"],
      manifest: "dist-protected/jso-manifest.json"
    }))
    .pipe(dest("dist-protected"));
}

exports.protect = protect;
```

The Gulp transform batches buffered JavaScript files into one API request, passes non-JavaScript assets through, removes stale `.js.map` files by default, and strips stale `sourceMappingURL` comments from protected JavaScript. Pass `removeSourceMaps: false` only when another task handles maps.

## Grunt

Use the Grunt entrypoint when a release pipeline already uses Grunt file mappings:

```js
module.exports = function configureGrunt(grunt) {
  grunt.initConfig({
    jsoProtector: {
      release: {
        options: {
          apiKey: process.env.JSO_API_KEY,
          apiPassword: process.env.JSO_API_PASSWORD,
          input: "dist",
          output: "dist-protected",
          preset: "balanced",
          exclude: ["**/vendor/**"],
          manifest: "dist-protected/jso-manifest.json"
        },
        files: [{
          expand: true,
          cwd: "dist",
          src: ["**/*.js", "!**/*.map"],
          dest: "dist-protected"
        }]
      }
    }
  });

  require("jso-protector/grunt")(grunt);
  grunt.registerTask("protect", ["jsoProtector:release"]);
};
```

The Grunt task protects JavaScript file mappings and writes protected files to each mapping's `dest`. Use a copy task for non-JavaScript assets.

For bundle and stream plugins, `include` and `exclude` match emitted asset names. Use them to protect first-party release chunks while leaving vendor bundles, polyfills, and framework runtime files untouched.

```js
jsoProtector({
  preset: "balanced",
  include: ["assets/*.js"],
  exclude: ["**/vendor/**", "**/polyfills-*.js"],
  maxOutputBytes: 250000,
  maxGrowthRatio: 8
});
```

The Browserify, esbuild, Vite, Rollup, Webpack, Webpack loader, Gulp, and Grunt integrations also honor `manifest`, `maxOutputBytes`, and `maxGrowthRatio`. A failed size budget stops the build before protected chunks replace the original bundle output.

## Configuration

```json
{
  "$schema": "./node_modules/jso-protector/jso.config.schema.json",
  "endpoint": "https://javascriptobfuscator.com/HttpApi.ashx",
  "apiKey": "$JSO_API_KEY",
  "apiPassword": "$JSO_API_PASSWORD",
  "projectName": "browser-release",
  "input": "dist",
  "output": "dist-protected",
  "preset": "balanced",
  "extensions": [".js", ".jsx"],
  "markupExtensions": [".html", ".htm", ".php", ".aspx"],
  "exclude": ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
  "copyAssets": true,
  "assetExclude": ["**/*.map"],
  "mixedServer": false,
  "parseHtml": false,
  "honorConditionalComments": false,
  "protectMarkedComments": false,
  "keepHeaderComment": true,
  "protectObjectDeclaration": false,
  "moveNestedFunction": false,
  "formattedOutput": false,
  "keepIndent": false,
  "lineNumbers": false,
  "reservedNames": ["^PublicApi$", "^keep_"],
  "options": {
    "OptimizationMode": "Web",
    "LockDomain": false,
    "LockDate": false
  }
}
```

The package includes `jso.config.schema.json` for editor autocomplete and validation. Generated configs point to `./node_modules/jso-protector/jso.config.schema.json`; the in-package example points to `./jso.config.schema.json`.

For common product features that otherwise require raw HTTP API option names, the config also supports convenience aliases such as `keepHeaderComment`, `protectObjectDeclaration`, `moveNestedFunction`, `formattedOutput`, `keepIndent`, `lineNumbers`, `lockDomainSubdomains`, `lockDomainMessage`, `lockDate`, `lockDateValue`, and `lockDateMessage`. Runtime-defense aliases include `selfDefendingIntervalSeconds`, `selfHealing`, `selfHealingMaxAttempts`, `antiMonkeyPatching`, `antiMonkeyPatchingCleanRealm`, `antiMonkeyPatchingIncludeGlobals`, `antiMonkeyPatchingExcludeGlobals`, `runtimeDefenseAction`, `runtimeDefenseCallback`, and `runtimeDefenseRedirectUrl`. These map to the corresponding `options.*` values before explicit `options` overrides are applied. The CLI also exposes `--self-defending-interval-seconds`, `--self-healing`, `--self-healing-max-attempts`, `--anti-monkey-patching`, `--anti-monkey-patching-clean-realm`, `--runtime-defense-action`, `--runtime-defense-callback`, and `--runtime-defense-redirect-url`. Keep bearer beacon tokens in environment-backed configuration or raw options rather than command-line history. Self-defending intervals accept 1 through 86,400 seconds and use the protected page scheduler. Self-defending, self-healing, and anti-monkey-patching wrappers use JavaScript dynamic evaluation (`eval` and/or the `Function` constructor), so deployed CSP must permit it (commonly `script-src 'unsafe-eval'`); leave them disabled where that CSP relaxation is unacceptable.

Runtime wrappers apply to classic scripts. ES modules are protected without those wrappers so `import`/`export` linking stays valid. Classic-script top-level `var` globals are preserved, but cross-script top-level `let`, `const`, and `class` bindings are not; bundle dependent scripts or leave Self-Defending disabled for that contract.

`--config` accepts JSON files plus trusted CommonJS or ES module config files. When no config path is provided, the CLI looks for `jso.config.json`, then `jso.config.cjs`, then `jso.config.mjs`, then `jso.config.js`.

`--mode <name>` passes a release mode into JavaScript config functions. Use it when production, staging, or tenant-specific builds need different include/exclude rules, presets, or output folders without duplicating config files. When `--mode` is omitted, JavaScript config loaders fall back to `NODE_ENV` when it is set.

Config files can also carry mapped `javascript-obfuscator` compatibility keys including `splitStrings` and `splitStringsChunkLength`. These map directly to native fixed-length literal splitting; valid chunk lengths are 1-1024 and the default is 10. Directives, reserved literals, object keys, template segments, dynamic-import/static-require specifiers, mixed-server markers, and Unicode surrogate pairs are preserved, and splitting composes with enabled move/encode transforms. Runtime guards, deterministic seeds, string-selection patterns, string-array shuffle/rotation/index/call controls, and wrapper type/chaining/parameter controls also map directly; wrapper count and safe object-key transformation map approximately. `numbersToExpressions` remains an approximate mapping to `EncodeNumbers`. Source maps, identifier dictionaries/prefixes, rename mode, simplify, and strict-mode workflow policy remain review-only. Explicit `options` values still win over compatibility keys.

The config migration maps deterministic seed, and string-selection patterns map directly; a fixed seed reduces per-build polymorphism and is not a security control. Matching reserved literals remain verbatim outside `MoveStrings` and `EncodeStrings`.

Quoted class method, accessor, and field names are also definition-site literals and remain intact; only their ordinary string values and safe expression uses are eligible for splitting.

```js
module.exports = ({ env, mode }) => ({
  apiKey: "$JSO_API_KEY",
  apiPassword: "$JSO_API_PASSWORD",
  input: env.CI ? "dist" : "demo-dist",
  output: mode === "staging" ? "dist-staging-protected" : "dist-protected",
  preset: mode === "staging" ? "standard" : "balanced",
  reservedNames: ["^PublicApi$"],
  options: {
    LockDomain: Boolean(env.RELEASE_DOMAIN),
    LockDomainList: env.RELEASE_DOMAIN || ""
  }
});
```

JavaScript config files execute as Node.js code, so only load config files from your own repository or another trusted source. Use JSON config when you want schema validation and no executable config logic.

ES module configs can use `export default { ... }` or `export default ({ env, cwd, mode }) => ({ ... })`. This covers `jso.config.mjs` and `jso.config.js` inside repositories that already use `"type": "module"`.

`apiKey` and `apiPassword` should use the base64 values copied from the JavaScript Obfuscator dashboard. Environment references in the form `$NAME` are resolved at runtime.

Do not commit real API credentials. Keep `apiKey` and `apiPassword` as environment references in shared config files.

The CLI reads `JSO_API_KEY`, `JSO_API_PASSWORD`, and `JSO_ENDPOINT` by default. It also accepts long-form aliases: `JAVASCRIPT_OBFUSCATOR_API_KEY`, `JAVASCRIPT_OBFUSCATOR_API_PASSWORD`, and `JAVASCRIPT_OBFUSCATOR_ENDPOINT`.

## Presets and Public Names

Use `preset` to start from a repeatable protection profile:

- `standard`: core string encoding, string movement, name replacement, and compression.
- `balanced`: standard plus short local names, deep obfuscation, code transposition, string encryption, and flat transform.
- `maximum`: balanced plus member/global renaming, member movement, and low dead-code insertion.

Override or extend any preset with `options`. The option names are the same names sent to `HttpApi.ashx`, such as `EncodeStrings`, `DeepObfuscate`, `ReorderCode`, `FlatTransform`, `LockDomain`, and `LockDate`.

Use `reservedNames` to preserve public API names, framework entry points, globals, or names that external code calls. Each entry is a regular expression and is sent to the API as `VariableExclusion`. You can also set `variableExclusion` or `options.VariableExclusion` directly when you need a multiline value.

```json
{
  "preset": "balanced",
  "reservedNames": ["^PublicApi$", "^renderWidget$", "^keep_"],
  "options": {
    "LockDomain": true,
    "LockDomainList": "example.com\napp.example.com",
    "LockDomainMsg": "This script is not licensed for this domain."
  }
}
```

## Named Configuration Sets

Apply a different protection profile to different parts of one app in a
single build with `namedSets`. Each set names an array of `match` globs and
any of `preset`, `options`, and `countermeasures`; the first matching set
wins per file (write sets in priority order), a set's options merge on top of
the baseline, a set's preset contributes that preset's option block before
the set's own options, and files matching no set keep the baseline exactly.
Each set runs as its own API round, so a set your plan cannot afford fails
only its own group.

```json
{
  "preset": "balanced",
  "namedSets": {
    "checkout": {
      "match": ["src/checkout/**", "src/wallet/**"],
      "preset": "maximum",
      "options": { "DeadcodeLevel": "High" }
    },
    "marketing": {
      "match": ["src/marketing/**"],
      "preset": "standard"
    }
  }
}
```

The JSON summary reports the per-set grouping under `namedSetGroups`, and the
manifest spans every group.

## Online Presets

The online obfuscator can export a JSON preset for Standard options, premium preview features, and the Variable Exclusion List. Use it directly during a dry run or in a CI config:

```bash
npx jso-protector --config jso.config.json --web-preset javascript-obfuscator-preset.json --dry-run --json
```

Or reference it from config:

```json
{
  "webPreset": "javascript-obfuscator-preset.json",
  "input": "dist",
  "output": "dist-protected"
}
```

By default, the CLI ignores source maps, `node_modules`, and `*-obfuscated.js` files. When the output folder is nested under the input folder, reruns also skip that output folder so already protected files are not protected again. The CLI copies non-protected assets such as HTML, CSS, fonts, and images into the output folder. `assetExclude` keeps files such as source maps out of the protected release. Use `--no-copy-assets` or `"copyAssets": false` when another build step already handles assets.

## Commands

```bash
jso-protector --config jso.config.json
jso-protector --config jso.config.cjs
jso-protector --version
jso-protector --version --json
jso-protector src/app.js
jso-protector --input dist --output dist-protected
jso-protector --list-presets --json
jso-protector --list-options --json
jso-protector --list-migration-map --json
jso-protector --explain-compat self-defending --json
jso-protector --compat-scan --json
jso-protector --local-only --json
jso-protector --migrate-javascript-obfuscator javascript-obfuscator.json --output jso.config.json
jso-protector --migrate-javascript-obfuscator javascript-obfuscator.config.cjs --output jso.config.json
jso-protector --migrate-js-confuser js-confuser.config.cjs --output jso.config.json
jso-protector --config jso.config.json --release-check --json
jso-protector --config jso.config.json --release-check --strict --json
jso-protector --config jso.config.json --validate-config --json
jso-protector --config jso.config.json --print-config --json
jso-protector --init --init-template html-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template electron-app --input out --output out-protected
jso-protector --init --init-template nextjs-app --manifest .next/static-protected/jso-manifest.json
jso-protector --init --init-template vite-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template parcel-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template bun-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template browserify-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template webpack-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template rspack-app --manifest dist-protected/jso-manifest.json
jso-protector --init --init-template turbopack-app --manifest .next/static-protected/jso-manifest.json
jso-protector --init --init-template react-native-app --input dist --output dist-protected
jso-protector --verify-manifest dist-protected/jso-manifest.json
jso-protector --verify-manifest dist-protected/jso-manifest.json --verify-root protected-dist
jso-protector --verify-manifest dist-protected/jso-manifest.json --audit-source-maps
jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md
jso-protector --runtime-incident-evidence reports/runtime-incidents.json --runtime-incident-evidence-output reports/runtime-incident-evidence.md
jso-protector --verify-vm-proof dist-protected/jso-report.json --json
jso-protector --ai-resistance-evidence dist-protected/jso-report.json --ai-resistance-evidence-output reports/ai-resistance-evidence.md
jso-protector --config jso.config.json --parse-html
jso-protector --config jso.config.json --honor-conditional-comments
jso-protector --config jso.config.json --protect-marked-comments
jso-protector --config jso.config.json --keep-header-comment --protect-object-declaration --move-nested-function
jso-protector --config jso.config.json --formatted-output --keep-indent --line-numbers
jso-protector --preset maximum --input dist --output dist-protected
jso-protector --web-preset javascript-obfuscator-preset.json --dry-run --json
jso-protector --stdin --stdout --file-name app.js < dist/app.js > dist/app.protected.js
jso-protector --stdin --file-name app.js --output dist-protected < dist/app.js
jso-protector --config jso.config.json --manifest dist-protected/jso-manifest.json
jso-protector --config jso.config.json --max-output-bytes 250000 --max-growth-ratio 8
jso-protector --config jso.config.json --option LockDomain=true --option LockDomainList=example.com
jso-protector --config jso.config.json --include "assets/*.js" --exclude "**/legacy/**" --asset-exclude "**/*.license"
jso-protector --config jso.config.json --reserved-name "^PublicApi$" --reserved-name "^renderWidget$"
jso-protector dist --output dist-protected --options-preset high-obfuscation --control-flow-flattening --string-array-encoding rc4 --reserved-names "^PublicApi$"
jso-protector --dry-run --json
jso-protector --no-copy-assets
jso-protector --init
```

Use `--stdin` for small custom scripts and build steps that already know which single file should be protected. Use `--stdout` to compose with other shell commands, or omit it and pass `--output` to write the result as `output/file-name`.

For direct single-file migration scripts, `jso-protector src/app.js` writes `src/app-obfuscated.js` when no `--output` or config `output` is set. Folder and config-file workflows keep using the configured output folder, usually `dist-protected`.

Use repeatable `--option Name=value` flags to override API options from CI without editing shared config. Values `true`, `false`, `null`, and numbers are parsed into their JSON equivalents; other values are sent as strings.

Use repeatable `--include pattern` flags to replace the configured protected-file include list for one job. Use repeatable `--exclude pattern` and `--asset-exclude pattern` flags to add job-specific file and asset exclusions without removing the config defaults. Use repeatable `--reserved-name pattern` flags to override `reservedNames` for a release job.

When replacing existing `javascript-obfuscator` package scripts, the CLI accepts familiar flags and maps them to hosted API options. Supported mapped compatibility flags include `--options-preset`, `--string-array`, `--string-array-encoding`, `--unicode-escape-sequence`, `--control-flow-flattening`, `--dead-code-injection`, `--dead-code-injection-threshold`, `--identifier-names-generator`, `--rename-globals`, `--rename-properties`, `--reserved-names`, `--domain-lock`, `--target`, and `--compact`. Config and Node API `domainLock` arrays map to `LockDomain` plus newline-delimited `LockDomainList`; review redirect behavior separately. Config-level compatibility fields are also accepted and covered by the shipped JSON schema. `--options-preset default`, `low-obfuscation`, `vm-default`, and `vm-low-obfuscation` map to `standard`; `medium-obfuscation` and `vm-medium-obfuscation` map to `balanced`; `high-obfuscation`, `vm-high-obfuscation`, `vm-ultra-high-obfuscation`, and `vm-anti-llm` map to `maximum`.

`--seed <value>` requests a reproducible build: the same input, options, and seed produce byte-identical protected output. Omit it for the default per-build polymorphic output (each build differs, which is what you usually want in production). An integer seed is used directly; any other string folds to a stable value. It maps to the engine `Seed` option, so `--option Seed=<value>`, a config `seed` key, and `options.Seed` are equivalent. Keep seed values out of shared logs, and note that a fixed seed makes builds diffable but is not itself a security control.

The CLI maps runtime-defense flags plus `--split-strings` and `--split-strings-chunk-length` directly to hosted engine options. String chunks are bounded to 1-1024 characters (default 10), with syntax-sensitive literals preserved. String-array shuffle, rotation, index representation, call indirection, wrapper type/chaining/parameter controls, and thresholds map to native controls; index shift, wrapper count, and safe object-key transformation retain documented approximation boundaries. `--numbers-to-expressions` maps approximately to native `EncodeNumbers`. Source-map, identifier-cache/dictionary, rename-mode, strict-mode, and simplify workflow fields remain review-only. `--ignore-imports` is handled directly. Review-only flags emit compatibility warnings and vendor-specific runtime semantics still need runtime validation.

Specifically, it maps `--self-defending`, `--debug-protection`, `--debug-protection-interval`, `--disable-console-output`, and `--domain-lock-redirect-url` directly.

Use `--version` for a quick CLI parity check in scripts. Add `--json` to print package metadata and the default hosted API endpoint.

Use `--list-presets` and `--list-options` to inspect available presets and commonly used HTTP API options. Add `--list-migration-map --json` to inspect `javascript-obfuscator` option migration coverage before converting a config. The migration map includes mapped, direct, approximate, review-only, and total known option counts for migration tooling. Use `--explain-compat <option>` when one migrated option needs a human-readable answer before you edit a build script.

Use `--compat-scan` before protection when you want a local source scan for public browser-global contracts and common runtime reflection hazards. It recognizes classic distributions shaped like `var Library = function (...)` plus direct `window`, `globalThis`, or `self` assignments, and returns an anchored `suggestedVariableExclusion` for each public name so `RenameGlobals` does not break script-tag consumers. It also detects `Function.prototype.toString.call(...)`, `.constructor.name`, and `.name` access that may change after obfuscation. The scan is heuristic and warning-oriented; runtime-test the protected distribution and review each suggested exclusion before release. Add `--json` for machine-readable CI output.

### AI precheck 鈥?gate the obfuscation API call on AI compat-check findings

Use `--ai-precheck` to fold the JSO AI `/v1/ai/compat-check` call into your existing obfuscation command. The CLI scans every resolved input file *before* the obfuscation API is called; if anything in your source would produce a broken protected build 鈥?`eval`, `Function` constructor, framework reflection traps, decorator metadata 鈥?the build aborts and your obfuscation quota is not touched.

```sh
# Single command, single round-trip. Add to any CI step you already run:
jso-protector --config jso.config.json --ai-precheck --ai-precheck-fail-on error

# JSON output for machine consumers (CI annotations, GitHub status checks):
jso-protector --config jso.config.json --ai-precheck --json
```

Gate levels for `--ai-precheck-fail-on`:

- `error` (default): build aborts on any error-severity finding.
- `warning`: build aborts on any error or warning finding (paranoid mode).
- `never`: print findings, never fail (advisory mode).

For projects that want to run the gate stand-alone 鈥?pre-commit hooks, IDE integrations, ad-hoc audits 鈥?use the companion sub-command:

```sh
jso ai compat-scan --config jso.config.json --fail-on error
jso ai compat-scan --config jso.config.json --max-files 50    # cap quota burn on huge repos
```

Both paths hit the same `/v1/ai/compat-check` endpoint. `--ai-precheck` just folds it into the obfuscation flow so CI doesn't need a second step. Requires a JSO API key with AI access 鈥?FreeTrial works for testing the wire format; Basic and up for production usage. See the [JSO AI quick start](https://javascriptobfuscator.com/Docs/AIQuickStart.aspx) for tier details.

### AI usage and BYO key health

Use the bundled AI CLI when an account owner or release job needs to confirm quota and BYO provider-key readiness without opening the dashboard.

```sh
jso ai usage --pretty
# tier:               Pro
# actions:            12 / 500   (488 remaining)
# AI key health:      Key ready (openai) [ready]
# next key test:      2026-06-25T00:00:00Z
# rotation review:    2026-08-24T00:00:00Z
```

Programmatic callers get the same source-free state from the typed Node client:

```js
const { ai } = require("jso-protector");

const usage = await ai.usage();
if (usage.providerKey && usage.providerKey.status !== "ready") {
  console.warn("AI key health:", usage.providerKey.label);
}
```

The `AiProviderKeyHealth` shape reports provider, status label, last test, next stored-key test, rotation review, and recommended action. It does not return the provider secret or key suffix.

### Pre-flight quota gate 鈥?`--estimate`

Add `--estimate` to any obfuscation command to do a cost check before submitting any source. The CLI walks your input file set, hits the existing `/v1/ai/usage` endpoint to read the current month's quota, and prints a CI-friendly report. The gate has three states:

- **OK** (exit 0) 鈥?quota healthy, build can proceed.
- **WARN** (exit 0) 鈥?fewer than 5 actions remaining OR cost cap below 20%. Print, don't block.
- **FAIL** (exit 1) 鈥?actions remaining = 0. Block the build before it consumes any more.

```sh
jso-protector --config jso.config.json --estimate
jso-protector --config jso.config.json --estimate --json    # machine-readable
```

Network failures on `/v1/ai/usage` downgrade to WARN with a note (don't crash the build pipeline over an observability gap).

When the usage endpoint includes BYO provider-key health, `--estimate` also prints the source-free AI key state: provider, status label, next 30-day stored-key test due date, 90-day rotation review date, and recommended action. The JSON output exposes the same data under `estimate.providerKey` without returning the provider secret or key suffix, so CI can alert on missing, failed, stale, or rotation-review-due AI keys before a release run depends on provider-backed assistance.

### Watermarking 鈥?anti-piracy + dispute proof

`--watermark <tag> --watermark-key <secret>` injects an HMAC-SHA256-signed header comment at the top of every input file. The obfuscator's `KeepComment` option preserves it verbatim through every transform (string array moves, control-flow flattening, dead code, etc.), so the marker survives intact in the protected output. Holders of the secret can verify; everyone else sees an opaque comment block.

```sh
# Stamp during build:
jso-protector --config jso.config.json \
    --watermark "release-2026-Q3" --watermark-key "$JSO_WATERMARK_KEY"

# Verify a single file post-deploy:
jso-protector --verify-watermark dist-protected/app.js --watermark-key "$JSO_WATERMARK_KEY"
# OK    dist-protected/app.js: valid watermark, tag=release-2026-Q3

# Bulk-scan a directory (CDN audit / forensic inventory):
jso-protector --scan-watermarks dist-protected/ --watermark-key "$JSO_WATERMARK_KEY"
# Scanned 42 JS file(s) under dist-protected/
# Watermarked: 42   valid=42   invalid=0
```

Without `--watermark-key`, verifiers run in **lookup-only mode**: they print the embedded tag but skip the HMAC compare. Useful for forensic inspection of leaked artifacts where you don't (or shouldn't) ship the secret to the investigator.

Wire format is identical across the Node, Python (`jso_protector.watermark`), and .NET (`JsoProtector.Watermark`) clients 鈥?an artifact stamped by any verifies under any. Reads `JSO_WATERMARK_KEY` from env when the flag isn't passed.

Exit codes (`--scan-watermarks`): **0** all clean / **1** at least one invalid signature found / **2** no watermarks found at all.

### Signed release attestations 鈥?SLSA-style

`--sign-release <priv.pem>` produces an Ed25519-signed envelope alongside your existing `--manifest` file. The envelope covers BuildId, polymorphism fingerprint, release label, and per-file SHA-256 hashes:

```sh
# One-time: mint a keypair (writes .priv.pem 0o600, .pub.pem 0o644):
jso-protector --genkey-release ci-signing-key

# Build + sign:
jso-protector --config jso.config.json \
    --manifest dist-protected/build.manifest.json \
    --sign-release ci-signing-key.priv.pem
# -> dist-protected/build.manifest.json.sig

# Verify post-deploy:
jso-protector --verify-release dist-protected/build.manifest.json.sig \
    --public-key ci-signing-key.pub.pem \
    --verify-root dist-protected/
# OK    .../build.manifest.json.sig: signature valid (BuildId=...), 42 file(s) re-hashed
```

Two-stage verification:

- **Stage 1** 鈥?Ed25519 signature over canonical-JSON manifest (catches forgery + manifest tampering).
- **Stage 2** 鈥?re-hash every referenced file on disk and compare against the embedded SHA-256 (catches post-signing tampering of the actual artifacts). Triggered when `--verify-root <dir>` is supplied.

Without `--public-key`, the envelope's embedded public key is trusted (signature-only verification). With it, embedded != trusted 鈫?fail fast (defeats key-substitution attacks).

Ed25519 chosen for 64-byte signatures, 32-byte keys, fast verify, no key-size choices to fumble. Node has it built-in since v12 鈥?zero new dependencies.

Use `--migrate-javascript-obfuscator` to convert a common `javascript-obfuscator` JSON or trusted CommonJS config into a starter `jso.config.json`. The migration report maps familiar options where possible, lists review items for options that are not one-to-one, includes a per-config summary with source option, mapped, review-only, unmapped, and automatic coverage counts, and prints the next validate, dry-run, doctor, release-check, competitor-gap-report, and protect commands. When any review-only migration item is present, it adds a `migration-review` next command so release owners get one source-free checklist before approval. When source-map review items are present, it also adds the post-protect `source-map-evidence` next command. When identifier cache, custom dictionary, or runtime-defense review items are present, it also adds the `identifier-cache-review` or `runtime-defense-review` next command so release owners can generate focused source-free review packets immediately. CommonJS source configs execute as Node.js code, so only migrate configs from your own repository or another trusted source.

Use `--list-js-confuser-migration-map --json`, `--explain-js-confuser-compat <option>`, and `--migrate-js-confuser` when migrating from JS-Confuser. The current migration path maps common preset, lock, string, identifier, minify, and control-flow options into the closest hosted API settings. Anti-debugging, integrity/self-defending, start-date, and tamper-protection locks map approximately to native runtime controls; numeric probability values become enabled/disabled switches. Countermeasure hooks and custom locks remain visible review-only items.

Use `--release-check --json` as the default CI preflight before protection. It runs config validation, dry-run file planning, and doctor checks in one report without sending source code to the API unless you also pass `--check-api`. The plan includes the number of API items plus any transformed files created from marked HTML scripts or conditional regions. Add `--strict` when warnings, such as unknown option names or not-yet-created output folders, should fail the release job.

Use `--parse-html` when built HTML or template files contain inline scripts that should be protected. Markup files require this explicit mode before protection; the CLI will not send a whole document to the JavaScript API path by accident. Only marked inline blocks are sent to the API:

```html
<script data-javascript-obfuscator>
  window.releaseWidget = createWidget();
</script>
```

Unmarked inline scripts are preserved. Marked external scripts and marked module scripts fail with a clear warning because markup mode protects inline script contents only; protect referenced files directly through the JavaScript build pipeline. When `parseHtml` is enabled, the CLI automatically adds the configured `markupExtensions` list to protected extensions. By default that includes `.html`, `.htm`, `.php`, `.phtml`, `.asp`, `.aspx`, `.jsp`, `.cshtml`, and `.vbhtml`.

Use `--honor-conditional-comments` to preserve source regions marked with `javascript-obfuscator:disable` and `javascript-obfuscator:enable`. Without the flag, the CLI fails with a clear warning when markers are found so protected regions are not sent unexpectedly. With the flag, enabled regions are sent as separate API items and disabled regions are copied back verbatim. Markers must be balanced; an unmatched `disable`, unmatched `enable`, or nested disabled region fails before any source is sent.

```js
console.log("protect this");
// javascript-obfuscator:disable
console.log("keep this exact local code");
// javascript-obfuscator:enable
console.log("protect this too");
```

Use `--protect-marked-comments` when only selected sections of a file should be protected. Unmarked code is copied back verbatim, and only regions between `javascript-obfuscator:protect-begin` and `javascript-obfuscator:protect-end` are sent to the hosted API. Markers must be balanced and cannot be mixed with `disable`/`enable` markers in the same file.

```js
console.log("keep this exact local code");
// javascript-obfuscator:protect-begin
console.log("protect this algorithm");
// javascript-obfuscator:protect-end
console.log("keep this exact local code too");
```

Use `--local-only` when a teammate needs a quick reminder of which commands avoid the network: validation, dry-run planning, doctor checks, release-check reports, and competitor gap reports all run locally. The command also reports that this package is local-only as a distribution artifact, not published to npm, and should be installed from a workspace path, `file:` dependency, or internal `npm pack` tarball.

### `--local`: protect without sending source

`--local` protects on the build machine instead of POSTing source to the hosted API. It runs the `jso-local` executable that ships in the [Windows desktop download](https://javascriptobfuscator.com/downloads.aspx) under `cli/jso-local.exe`:

```bash
jso-protector --config jso.config.json --local
jso-protector --config jso.config.json --local --local-exe "C:\Tools\JSObfuscator\cli\jso-local.exe"
```

The executable is found via `--local-exe`, then `JSO_LOCAL_EXE`, then the usual desktop install locations. Config equivalents are `"local": true` and `"localExe"`.

State it accurately when a reviewer asks:

- **Your source stays on the machine.** The request body is written to a temporary file, handed to `jso-local`, and deleted after the run.
- **A source-free plan check still goes online.** Local Advanced is a paid capability, so the same short entitlement call the desktop app makes runs first, carrying only your credentials and a handful of plan-gated option switches. Fully disconnected operation is not available yet.
- **Windows only**, because the executable ships in the Windows desktop archive.
- **VM bytecode protection is refused, not silently dropped.** It runs in a server-side virtualizer; a `--local` build that requested it fails with a clear message instead of quietly shipping weaker output.

Everything downstream is unchanged: the same options, manifests, evidence packets, and size budgets apply, because the local path exchanges the same request and response shapes the hosted endpoint uses.

Use `--validate-config --json` to check config shape, endpoint format, credentials presence, credential storage, path settings, budget values, and local option-name references without sending source code to the API. Unknown option names are reported as warnings so teams can catch typos while still using advanced HTTP API options. Inline `apiKey`, `apiPassword`, `--api-key`, and `--api-password` values also warn; prefer `$JSO_API_KEY` and `$JSO_API_PASSWORD` environment references so dashboard credentials do not land in committed config, shell history, or process logs.

Use `--print-config --json` to inspect the final resolved config after presets, config files, environment variables, and CLI overrides are merged. API credentials are redacted as `[set]` or `[missing]`.

Use `--manifest file.json` or `"manifest": "file.json"` to write a release manifest after a successful protection run. The manifest includes project metadata, preset, enabled option names, processing metadata for virtual API items, protected file sizes and SHA-256 hashes, copied asset hashes, and any grouped migration `limitations` still present in the config so artifact review does not depend on one earlier CLI preflight step.

Use `--verify-manifest file.json` to verify that a protected output folder or unpacked release artifact still matches the manifest hashes. By default, verification reads each entry's recorded `outputPath`. Add `--verify-root path/to/artifact` when the protected files were moved into a different folder after the manifest was written; verification then resolves each manifest `fileName` under that alternate root. Add `--audit-source-maps` in release CI to fail when protected JavaScript still contains `sourceMappingURL` comments or when copied artifacts include `.map` files.

Use `--source-map-evidence file.json --source-map-evidence-output reports/source-map-evidence.md` when a release reviewer needs a source-free packet proving protected artifacts do not expose source maps. The command reuses manifest hash verification, audits `.map` files and `sourceMappingURL` comments, emits Markdown by default or JSON with `--json`, and lists artifact names/reasons without embedding source code or source-map contents. The packet now includes a Source Map Review Assistant for BYO AI or internal reviewers, with prompts for leak cleanup, manifest verification, secure debugging exceptions, bundler cleanup order, and clean reviewer handoff without sharing raw `.map` files, original source paths, source code, protected output, customer data, or secrets. Add `--verify-root path/to/artifact` when the manifest was moved before review.

Use `--verify-vm-proof report.json` to verify that a saved API report proves VM protection ran for at least one function. Add `--min-vm-functions 2` or a higher number when the release intentionally marks multiple functions. The check is local and source-free: it reads the report written by `--report`, then validates `UseVMProtection`, `VMProtectionApplied`, `VMProtectionVirtualizedCount`, and `VMProtectionWarnings`.

VM function markers accept `// @virtualize`, `/* @virtualize */`, and `/** @virtualize */` immediately before a supported synchronous function declaration. The server normalizes block and JSDoc markers before the VM sidecar runs, so proof failures should focus on unsupported function syntax, account eligibility, or sidecar warnings instead of comment shape.

Use `--vm-proof-pack report.json --vm-proof-output reports/vm-proof-pack.md` when a security reviewer needs one source-free VM evidence packet. The Markdown output includes build identity, release label, polymorphism fingerprint, VM proof checks, review decision, warnings, compatibility guidance, hot-path/cold-path performance guidance, next actions, and a VM Proof Review Assistant for BYO AI or internal reviewers. The assistant prompts owners to resolve failed proof checks, handle VM warnings, confirm cold sensitive function scope, exclude hot paths, and attach protected-build smoke results without sending source code, protected output, VM bytecode, source maps, provider keys, customer data, or secrets. Add `--json` to write the same packet as machine-readable JSON. A passing VM proof pack can still say `ready-for-manual-review` when the release owner must confirm the selected functions are cold sensitive paths and attach smoke-test results.

Use `--ai-resistance-evidence report.json --ai-resistance-evidence-output reports/ai-resistance-evidence.md` when a security reviewer or buyer asks what can be checked today for AI-aware protection. The command stays local, reads the saved API report, and emits a source-free evidence summary with a non-scoring attacker-model review matrix, review decision, claim boundaries, and a Review Assistant Packet for BYO AI or internal reviewers. The assistant prompts owners to resolve failed evidence, confirm missing review tracks, check VM/runtime/compatibility scope, and keep Resistance Score wording in the planned-methodology lane without pasting source code, protected output, source maps, provider keys, or secrets into a reviewer or AI prompt. The decision is `blocked` when required evidence fails, `ready-for-manual-review` when required checks pass but optional review tracks need confirmation, or `ready` when every current track is evidenced. It does not call an AI model and it does not claim the planned Resistance Score is live. Add `--json` to write the same packet as machine-readable JSON, and add `--require-vm-proof` to fail when the same report does not pass the VM proof checks.

Use `--script-inventory-audit inventory.json --runtime-inventory-snapshot snapshot.json` when checkout owners need a source-free reconciliation between the approved payment-page script inventory and what the browser actually observed. Markdown is emitted by default; add `--json` for automation. The command fails the gate when unknown, unauthorized, missing, changed, late-injected, or required metadata-incomplete scripts need review. Missing optional `risk`, `dataAccess`, and `approvalTicket` values are reported as review-context gaps, not blocking failures. Each audit also includes a source-free Review Assistant Packet for BYO AI or internal reviewer triage, with safe-input boundaries and prompts for owner actions, data-access review, integrity drift, and approval-ticket cleanup.

Use `--payment-page-headers-from-har checkout.har --payment-page-headers-output payment-page-headers.json` when checkout owners need a source-free payment-page security-header snapshot from a browser or synthetic-monitor HAR. Add `--payment-page-headers-baseline approved-headers.json` to mark each checkout page or frame as matching, changed, or missing from the approved header baseline. The JSON output includes a source-free security-header Review Assistant Packet for BYO AI or internal reviewers, with safe-input boundaries and prompts for baseline drift, CSP/reporting gaps, HSTS coverage, and frame-policy owner actions.

Use `jso-protector compliance pci-dss-v4 --script-inventory-audit audit.json` to include the JSON audit summary in the PCI evidence report alongside `--script-inventory` and `--runtime-incidents`. The generated Markdown and JSON also include a source-free PCI DSS Review Assistant for BYO AI or internal reviewers, with prompts for evidence gaps, signed-release proof, script authorization, observed script drift, header change evidence, runtime incident routing, and QSA handoff boundaries. Do not paste source code, protected output, raw script rows, raw response headers, raw incident payloads, payment-card data, provider keys, customer data, or secrets into that review.

Use `--max-output-bytes` / `"maxOutputBytes"` and `--max-growth-ratio` / `"maxGrowthRatio"` to fail CI when protected output exceeds your release size budget. The same budget fields work in bundle plugins.

## Package Verification

For ordinary development, run the deterministic verification chain with `npm run verify`. Before publishing or tagging an engine release, run the heavier release gate:

```bash
npm run verify:release
```

The release gate first runs every ordinary check, then regenerates protected output for the complete real-library corpus and compares the supported runtime samples against the freshly protected files. Do not run `verify:corpus-runtime` by itself as release evidence: it consumes the existing `tools/corpus-protect/.build/emitted` directory and therefore does not prove that the current engine produced those artifacts.

To check only package installation behavior, run:

```bash
npm run verify:package
```

The verifier packs the package, installs the tarball into a fresh temporary project, checks root and subpath exports, checks shipped example syntax/config JSON, runs the CLI through the installed bin link, and verifies the direct single-file output default.

## Security and Processing

See `SECURITY.md` for the source-processing matrix, CI secret guidance, source-map policy, manifest metadata notes, and local-preflight guidance. Use `--release-check`, `--competitor-gap-report`, `--dry-run`, `--validate-config`, and `--doctor` when you need preflight checks before sending source code to the hosted API.

## Live API Smoke Test

After setting `JSO_API_KEY` and `JSO_API_PASSWORD`, run a tiny live API check from this package directory:

```bash
npm run smoke:api
```

The command protects the sample file in `dist/` and writes the result to `dist-protected/`. Use `npm run smoke` when you only want offline validation and a dry run.

## Doctor

Run `release-check` before a release job when you want one CI-friendly report that combines config validation, dry-run file planning, and doctor checks:

```bash
jso-protector --config jso.config.json --release-check
jso-protector --config jso.config.json --release-check --json
jso-protector --config jso.config.json --release-check --strict --json
```

Run `validate-config` first when you want a fast static check:

```bash
jso-protector --config jso.config.json --validate-config
jso-protector --config jso.config.json --validate-config --json
jso-protector --config jso.config.json --validate-config --strict --json
```

Run `doctor` before a release job to check config, credentials, paths, matched files, copied assets, output readiness, presets, and enabled options without sending source code to the API:

```bash
jso-protector --config jso.config.json --doctor
jso-protector --config jso.config.json --doctor --json
```

`doctor` now includes a local compatibility scan summary. Run `jso-protector --config jso.config.json --compat-scan --json` when you need the detailed file-and-line findings before a release.

When a config still carries competitor-only migration fields such as source-map flags, identifier cache paths, custom naming dictionaries, or JS-Confuser custom countermeasure notes, `validate-config`, `doctor`, and `release-check` emit grouped `limitations` entries in JSON output and `LIMITATION ...` lines in text output so CI can surface the remaining manual-review items explicitly.

Run the standalone competitor gap report when you want a machine-readable parity summary for migrated configs:

```bash
jso-protector --config jso.config.json --competitor-gap-report --json
```

When a migrated config used deterministic identifier caches or custom
identifier dictionaries, generate a reviewer packet for that specific gap:

```bash
jso-protector --config jso.config.json --identifier-cache-review \
  --identifier-cache-review-output reports/identifier-cache-review.md
```

The packet is source-free. It lists the migration field names, counts,
replacement evidence tracks, and review decision without embedding cache
contents, dictionary values, prefixes, reserved-name expressions, or source
code. The Identifier Cache Review Assistant gives BYO AI or internal reviewers
owner-action prompts for deterministic cache assumptions, custom dictionary
replacement, reserved-name coverage, release metadata, and protected-build
smoke without exposing raw config files, API credentials, provider keys,
customer data, or secrets.

When a migrated config used anti-debug, self-defending, runtime lock, console,
or countermeasure controls, generate the runtime-defense migration review:

```bash
jso-protector --config jso.config.json --runtime-defense-review \
  --runtime-defense-review-output reports/runtime-defense-review.md
```

The packet is source-free. It turns anti-debug, self-defending, runtime lock,
console, and countermeasure migration settings into a reviewer checklist with
monitoring target, customer-owned forwarding, countermeasure policy,
domain/date lock, release metadata, compatibility scan, and protected-build
smoke-test tracks. It omits domains, dates, redirect URLs, beacon URLs,
countermeasure values, source code, protected output, and compatibility-scan
source snippets. The Runtime Defense Review Assistant gives BYO AI or internal
reviewers owner-action prompts for runtime behavior scope, monitoring handoff,
countermeasure policy, domain/date lock smoke, source-reading compatibility
scan, release metadata, and protected-build smoke without exposing raw config
files, API credentials, provider keys, collector tokens, customer data, or
secrets.

Add `--check-api` to `release-check` or `doctor` when CI should send a tiny live request to verify the endpoint and credentials:

```bash
jso-protector --config jso.config.json --release-check --check-api --json
jso-protector --config jso.config.json --doctor --check-api --json
```

## Examples and CI Templates

Copyable examples are included in `examples/`:

- `examples/cli-basic`
- `examples/node-api`
- `examples/parcel`
- `examples/bun`
- `examples/browserify`
- `examples/metro.config.js`
- `examples/nextjs`
- `examples/turbopack`
- `examples/rspack`
- `examples/esbuild`
- `examples/vite`
- `examples/rollup`
- `examples/webpack`
- `examples/webpack-loader`
- `examples/gulp`
- `examples/grunt`
- `examples/react-native/metro.config.js`

`examples/node-api/release-summary.js` is the most complete custom-script starting point: it validates config, prints a dry release plan, protects files, and reports written files, copied assets, and manifest output.

CI templates are included in `ci/`:

- `ci/github-actions.yml`
- `ci/gitlab-ci.yml`
- `ci/azure-pipelines.yml`

The templates run `npm run verify:publish-metadata --if-present` so package projects can confirm the local-only metadata policy while application projects can ignore the optional script.

## Migrating from javascript-obfuscator

See `MIGRATION.md` when replacing the open-source `javascript-obfuscator` package or one of its bundler plugins with the hosted JavaScript Obfuscator API workflow. It covers command changes, concept mapping, direct Node API replacement, bundle-plugin replacement, and a migration checklist.

For JS-Confuser projects, the same package now includes `--migrate-js-confuser`, `--list-js-confuser-migration-map`, `--explain-js-confuser-compat`, and `translateJsConfuserOptions(...)` so you can generate a starter `jso.config.json` and review the runtime-only gaps before switching release pipelines.

## GitHub Actions

Store `JSO_API_KEY` and `JSO_API_PASSWORD` as encrypted repository or organization secrets, then run release preflight and protection after your normal frontend build:

```yaml
name: protected-release

on:
  workflow_dispatch:

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npm run build
      - run: npm run verify:package --if-present
      - run: npm run verify:publish-metadata --if-present
      - name: Release preflight
        run: npx jso-protector --config jso.config.json --release-check --json
        env:
          JSO_API_KEY: ${{ secrets.JSO_API_KEY }}
          JSO_API_PASSWORD: ${{ secrets.JSO_API_PASSWORD }}
      - name: Protect JavaScript
        run: npx jso-protector --config jso.config.json --manifest dist-protected/jso-manifest.json
        env:
          JSO_API_KEY: ${{ secrets.JSO_API_KEY }}
          JSO_API_PASSWORD: ${{ secrets.JSO_API_PASSWORD }}
      - run: npm run smoke
      - uses: actions/upload-artifact@v4
        with:
          name: protected-dist
          path: |
            dist-protected/
            dist-protected/jso-manifest.json
```

## Working from a local checkout

Published releases install from the registry with
`npm install --save-dev jso-protector`. The paths below are for building the
package from a checkout of this repository — internal testing, a release
candidate, or an air-gapped install.

Install the workspace copy directly:

```bash
npm install --save-dev ./packages/jso-protector
```

Or pin it from another app in the same workspace:

```json
{
  "devDependencies": {
    "jso-protector": "file:../packages/jso-protector"
  }
}
```

For internal sharing without going through the registry, build a tarball and
install that artifact in the consuming project:

```bash
npm pack --json
npm install --save-dev path/to/jso-protector-0.4.0.tgz
```

Keep those tarballs in internal storage or build artifacts. `prepublishOnly`
runs the full verification chain before any real publish, so a release cannot
go out on an unverified tree.

## Release Checklist

1. Build unprotected JavaScript into a temporary output folder.
2. Run `jso-protector --release-check --json` to validate config, confirm the file list, and check paths, assets, output readiness, presets, and enabled options before source is sent.
3. Protect into a separate output folder such as `dist-protected` and write `dist-protected/jso-manifest.json`.
4. Run browser smoke tests against the protected output.
5. Run `jso-protector --verify-manifest dist-protected/jso-manifest.json --audit-source-maps` before publishing or after unpacking release artifacts.
6. Publish only the protected artifacts and release manifest.

## Notes

- The CLI sends file contents to the configured HTTP API endpoint.
- The desktop app also sends selected JavaScript to the hosted service. Use local preflight only when policy forbids source transfer; current protection workflows do not meet that requirement.
- The HTTP API is for paid accounts.
- The CLI expects the API response shape used by `HttpApi.ashx`: `Type`, `Items`, `Message`, `FileName`, and optional error fields.
