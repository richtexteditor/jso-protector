# Changelog

## 0.4.9 - 2026-09-01

README only. No behaviour changes.

- The npm registry truncates a README at 65,536 characters and ours is 100,725,
  so a third of it never rendered on the package page - including `--local`
  (protect without sending source), watermarking, signed release attestations,
  the migration guide and the security section. The 30 KB command reference and
  the PCI evidence walkthrough now sit at the end and take the truncation
  instead; everything that explains what the tool is fits above the cut. Nothing
  was deleted, and the full reference is on the docs site.
- Adds the measured dependency comparison against `javascript-obfuscator` 5.6.0:
  0 dependencies against 23, 3 installed directories against 120, 1s against 9s,
  2 MB against 56 MB. That was already true and stated once as an adjective; a
  build tool sold on reducing risk should show the number.

## 0.4.8 - 2026-09-01

The rate-limit message a first run actually sees.

- A keyless run that tripped the free-tier cap used to print
  `API returned non-JSON response (429): The custom error module does not
  recognize this error.` That sentence was IIS's, not ours: the server writes a
  proper JSON body, and IIS's custom-error module was discarding it before it
  left the machine. Fixed server-side; the message now says which of the two
  ceilings was hit and how to raise it.
- The CLI no longer appends its paid-plan hint to a 429. The word "limit" in a
  rate-limit message matched the billing regexp, so someone with no account was
  being told to go check their subscription state.
- `--help` now shows the positional form. `jso-protector app.js` has always
  worked and writes `app-obfuscated.js` beside the input - the same default the
  competitor's CLI uses - but nothing in the help output said so, so anyone
  arriving with that muscle memory had no way to find it.

## 0.4.7 - 2026-08-31

Attribution only. No behaviour changes.

- The dashboard links the CLI opens now carry a source tag: `src=cli-login`
  from `login`, and `src=cli-nokey` / `src=cli-nopwd` from the missing-credential
  errors. A sign-up that starts at the CLI was previously indistinguishable from
  a web sign-up, which made the free first run impossible to measure.
- Held back until the site could actually read the tag. It was being lost twice
  on the way: the dashboard bounced signed-out visitors to sign-in without the
  query string, and the sign-in page then hardcoded its own tag over whatever
  arrived. Both are fixed and live, verified end to end before this release.

## 0.4.6 - 2026-08-31

Documentation only. No behaviour changes.

- **The README said you needed an API key to use this package.** Since 0.4.5
  that is false for a first run, and it was the first thing anyone read on
  npmjs.com - so the page was arguing against the feature the release shipped.
  The quickstart now says no account is needed, "What you need" answers
  "nothing, to start", and the payment section describes the free tier and where
  it ends instead of claiming the package unlocks nothing on its own.
- The quickstart installs `javascriptobfuscator-com` and calls
  `javascriptobfuscator`, the current names.

## 0.4.5 - 2026-08-31

- **The first command now works without an account.** With no credentials at
  all the CLI sends the request anonymously and the service runs it on the free
  tier - up to 20 files and 200 KB per request, no VM protection, rate limited
  per IP. You get real protected output instead of an error, and the run says
  so on stderr. `javascriptobfuscator login` switches to your plan.
- Half-configured credentials are still an error. Only *no* credentials means
  anonymous, so a key that stopped resolving cannot silently downgrade a paid
  build to the free tier.

## 0.4.4 - 2026-08-31

- **`javascriptobfuscator login` saves your credentials once, for every project
  on the machine.** Getting a first protected build used to take about seven
  steps: install, hit the error, find the site, register, verify email, locate
  the dashboard, copy two values, work out two platform-specific environment
  variable names, set them, and run again - then set them again in the next
  shell. `login` opens the dashboard, takes the two values (the password is not
  echoed), and stores them in `~/.jso-protector/credentials.json`.
- `javascriptobfuscator logout` removes them.
- Stored credentials are resolved **last**, after an explicit flag, a project
  config and the environment variables, so no existing CI setup changes
  behaviour.
- The missing-credential errors now name `login` as the fastest fix.
- The store is written 0600. That is real protection on POSIX; Windows does not
  honour the mode, so there it is only as protected as your user profile - the
  same position as `~/.npmrc`.

## 0.4.3 - 2026-08-30

Error messages only. No behaviour changes.

- **The "Missing API key" error now says where to get one.** It previously named
  three places to *put* a key and no place to *obtain* one, which left a first-time
  user with a dead end: measured against `javascript-obfuscator`, their first
  command emits working protected output while ours printed this error. The
  message now links the dashboard page that issues a free key, and the npm setup
  guide. Same for "Missing API password", which is shown beside the key.
- Applied at all six sites - the protect path, `--doctor`, and config validation -
  so the guidance is the same wherever you hit it.
- Also published under the package's new name, `javascriptobfuscator-com`.

## 0.4.2 - 2026-08-27

Metadata only. No behaviour changes.

- **The package has a public source repository**:
  [richtexteditor/jso-protector](https://github.com/richtexteditor/jso-protector).
  npm now shows Repository and Issues links instead of nothing, which for a
  security tool is the difference between auditable and "trust us". The
  repository holds this package and nothing else - the protection engine runs
  on the hosted API, or on your machine through the bundled `jso-local`
  executable, and is not part of it.
- `bugs` points at GitHub issues and support@javascriptobfuscator.com.

## 0.4.1 - 2026-08-27

Documentation only. No behaviour changes: the CLI, the Node API, the plugins,
and the protection engine are byte-for-byte the same as 0.4.0.

- **The npm page told visitors to install from a local path.** The README's
  first instruction was `npm install --save-dev ./packages/jso-protector`, and
  a later paragraph said the package was "intentionally local-only" and should
  not go in a public registry — text written while it was, and left in place
  when it was published. Someone arriving from npm search read an install
  command that could not work and a claim that this was not a real product.
  The first screen now says what the package does, installs from the registry,
  and shows a two-line example.
- **Migration from another obfuscator is no longer buried.**
  `--migrate-javascript-obfuscator` and `--migrate-js-confuser` convert an
  existing config in one command; that was documented 1,500 lines down. It is
  now on the first screen, with `--list-migration-map`, `--explain-compat`,
  and `--competitor-gap-report` beside it.
- **`RELEASE.md` ships in the tarball and described the opposite of reality** —
  `private: true`, `UNLICENSED`, and a publish guard that "should fail". It is
  now the actual release runbook, including the site artifacts and checksums a
  version bump has to keep in step.
- **Package metadata**: the description names what the tool does and the
  toolchain it plugs into rather than calling itself an HTTP API wrapper, and
  the keywords gained the terms people actually search for (`obfuscator`,
  `code-protection`, `source-code-protection`, `anti-tamper`, `typescript`).
- Workspace and tarball install instructions still exist, under "Working from
  a local checkout", where they belong.

## 0.4.0 - 2026-08-26

- **Named configuration sets now protect.** `namedSets` — different protection
  profiles for different parts of one app in a single build — had its schema,
  resolver and tests in the package since the baseline but was never wired
  into the protect flow; a config carrying it validated and was silently
  ignored. It now works in both the CLI and the Node API (`protectFiles`):
  each named set becomes its own API round with the baseline options plus the
  set's preset block plus the set's own options; first matching set wins per
  file; files matching no set keep the baseline exactly. The JSON summary
  gains `namedSetGroups` (and `buildIds` when rounds produce multiple
  reports); the manifest spans every group. A set the plan cannot afford
  fails its own round with the normal API error and leaves other groups
  untouched.
- **`TargetVersion` and `DownlevelIteration` are now first-class.** Both
  engine options appear in `--list-options` (category `output`) and gain
  camelCase config aliases `targetVersion` (`"es5"`/`"modern"`) and
  `downlevelIteration` (spec-faithful ES5 for-of lowering: lazy stepping +
  IteratorClose, like TypeScript's `downlevelIteration`; off by default
  because it adds a per-step call on arrays; no effect on the modern target).
  The raw option names worked before through generic passthrough; now they
  are documented and validated.
- `--seed` is documented in `--help` (reproducible builds; omit for the
  default polymorphic output).

## 0.3.2 - 2026-08-10

- The shipped CI templates (all 13) now list `--local` in their
  "Optional: migration and supply-chain checks" discovery block, with its
  constraint attached: on-runner protection, no source upload, Windows agents
  only. That block exists so users of non-GitHub CI systems can find a
  capability without reading the docs site, and source-local protection was
  the one capability missing from it.

## 0.3.1 - 2026-08-10

- Documentation accuracy only, no behaviour change. The "Payment and API
  Access" section still described the package as a client for the hosted API
  and listed uploading source as an unconditional step, which stopped being
  true in 0.3.0. It now states that `--local` keeps the source body on the
  build machine while entitlement is still enforced server-side by a
  source-free plan check.

## 0.3.0 - 2026-08-10

- **`--local` protects without sending source.** The CLI can now run the
  `jso-local` executable from the Windows desktop download (`cli/jso-local.exe`)
  instead of POSTing source to the hosted API. Resolution order is
  `--local-exe`, `JSO_LOCAL_EXE`, then the usual desktop install locations;
  config equivalents are `local` and `localExe`.
- The local path is a transport swap, not a second implementation: it exchanges
  the same request and response shapes the hosted endpoint uses, so options,
  manifests, evidence packets, and size budgets behave identically. An option
  that works hosted works locally by construction.
- Honest boundaries, enforced rather than documented: a source-free plan check
  still runs online (Local Advanced is a paid capability), the payload holding
  source and credentials is deleted after each run, and a build that asks for
  VM bytecode protection fails with a clear message instead of silently
  shipping weaker output.
- Corrected README copy that said protection workflows "do not meet a policy
  that forbids source transfer" - true when written, false as of this release.

## Native string splitting (2026-08-03)

- `splitStrings` and `splitStringsChunkLength` now map directly to native `SplitStrings` and `SplitStringsChunkLength` engine options instead of migration-review warnings.
- Eligible literals split into fixed-length concatenated chunks. Chunk length is bounded to 1-1024 and defaults to 10; directives, reserved literals, object keys, template segments, and mixed-server markers remain intact.
- CLI/config/Node API mappings, wire schemas, option discovery, ASP.NET model binding, and executable engine regression coverage ship together.
- JS-Confuser `stringSplitting` now maps approximately to the same native transform: booleans map directly, positive probabilities enable it, and custom selector functions remain explicit manual-review inputs.
- Splitting preserves dynamic-import and static-require specifiers for bundler discovery and never cuts a UTF-16 surrogate pair; executable regressions cover module linking, CommonJS resolution text, emoji values, and self-compressed output.
- Quoted class method, accessor, and field definition names remain literal. An adversarial class-field case previously failed during protection after the name became a binary expression; normal and self-compressed class-member execution now have permanent coverage.
- `stringArrayIndexShift` now maps approximately to native `StringArrayIndexShift`. Enabling it adds a deterministic nonzero one-slot offset to plain and encrypted string tables; it does not reproduce the competitor's randomized shift magnitude.
- `stringArrayShuffle` now maps directly to native `StringArrayShuffle`. The engine shuffles unique moved strings with per-build entropy, or reproducibly under `Seed`, and rewrites every lookup before plain or encrypted table emission.
- `stringArrayRotate` now maps directly to native `StringArrayRotate`. It applies a nonzero per-build cyclic rotation, rewrites every lookup, and composes with shuffle, index shifting, encryption, and seeded builds.
- `stringArrayIndexesType` now maps directly to native `StringArrayIndexesType`, supporting `hexadecimal-number`, `hexadecimal-numeric-string`, and mixed lists. Numeric strings are explicitly coerced before array lookup so hexadecimal property text cannot silently return `undefined`.
- `stringArrayThreshold` now maps directly to a native 0-1 per-unique-literal probability gate. Duplicate values receive one stable decision, zero moves nothing, one moves everything eligible, and `Seed` makes partial selection reproducible.
- `stringArrayCallsTransform` and `stringArrayCallsTransformThreshold` now map directly to native secondary index-table indirection. The engine emits nested lookups for selected calls, supports 0-1 probability, and composes with shifting, shuffling, rotation, encryption, index representations, compression, and seeded builds.
- String-array wrapper count, chaining, parameter ceiling, and type now map to native root-level wrappers. Variable aliases and multi-parameter function wrappers execute through optional predecessor chains; count is approximate because competitor per-function-scope placement is not reproduced.
- `transformObjectKeys` maps approximately to native safe data-key transformation. Identifier and quoted data keys become computed moved-string lookups; numeric keys, methods/accessors, shorthand-sensitive members, and `__proto__` remain literal to preserve semantics.

## 0.2.1 - 2026-07-13

- Added OIDC/SAML configuration validation, organization directory behavior, and a bearer-authenticated SCIM 2.0 user lifecycle core to governance.
- Added versioned managed Web Integrity policies, monitor/block decisions, incident deduplication and workflow, plus active blocking for unknown dynamic scripts.
- Exported the managed integrity, third-party inventory, and countermeasure runtime entry points.

## 0.2.0 — 2026-05-19

- Added `--report <file>` flag. After a successful run, writes the full API
  response JSON (BuildId, PolymorphismFingerprint, GlobalIdentifierMap,
  MemberIdentifierMap, audit metadata) to the given path. Strips the heavy
  file payload before persisting since the protected source is already
  written to `config.output`. Pairs with `jso-symbolicate`.
- Added `--label <value>` flag. Tags the API request with a release label
  that appears as `ReleaseLabel` in the JSO dashboard audit log. Also reads
  `JSO_LABEL` / `JAVASCRIPT_OBFUSCATOR_LABEL` from the environment.
- `--json` output now includes `buildId`, `polymorphismFingerprint`, and
  `label` fields so CI scripts can capture them without a second read of the
  report file.
- All 149 existing CLI unit tests still pass.

## Unreleased

### Runtime recovery and governance foundations (2026-07-13)

- Added bounded browser-side `SelfHealing` for post-startup self-defending
  mutations, corrected the integrity baseline to hash the constructed function
  representation, and added `reload`, `callback`, and `degrade` response modes.
- Added `jso-protector/governance` with local RBAC, scoped-token descriptors,
  and SHA-256 hash-chained audit events. Hosted SSO/SCIM remains explicitly out
  of scope for this local module.

### Runtime incident action plans (2026-06-12)

- Dashboard Monitoring JSON/CSV exports now carry source-free per-incident
  action plans with next owner, evidence packet, response due state, status
  transition, acknowledgement requirement, and next action.
- `--runtime-incident-evidence` preserves those action plans in Markdown and
  JSON, adds an Incident Action Plan table, and prompts BYO AI or internal
  reviewers about overdue incident owners before external handoff.

### VM marker ergonomics (2026-06-12)

- VM protection now accepts `// @virtualize`, `/* @virtualize */`, and
  `/** @virtualize */` markers immediately before supported synchronous
  function declarations. The website pipeline normalizes block and JSDoc
  marker forms before invoking the VM sidecar, removing a silent-miss setup
  trap from the VM beta flow.
- The VM proof static guard now checks the server-side normalizer and public
  docs so marker support cannot drift back to line-comment-only wording.

### Parser engine compatibility smoke (2026-06-12)

- `tools/verify-parser-engine.ps1` now runs a multi-root compatibility smoke
  after the main parser conformance harness. The smoke compiles the legacy root
  `App_Code/JScriptProtectorV2` source tree and the framework
  `JScriptCodeDom` source tree, then verifies the Cesium-style `?.25`,
  optional-chain, nullish, and `.5e3` leading-dot exponent cases.
- Archive hygiene now requires the new `compat-run.ps1` and
  `compat-smoke.cs` files so deployment packages include the same parser drift
  guard used locally.

### PCI DSS review assistant (2026-06-08)

- `jso-protector compliance pci-dss-v4` Markdown and JSON now include a
  source-free PCI DSS Review Assistant for BYO AI or internal reviewer triage.
- The assistant turns evidence gaps, signed-release proof, script
  authorization, observed script drift, header change evidence, runtime
  incident routing, and QSA handoff boundaries into checkout-owner actions
  without sharing source code, protected output, raw script rows, raw response
  headers, raw incident payloads, payment-card data, provider keys, customer
  data, or secrets.

### Runtime defense review assistant (2026-06-08)

- `--runtime-defense-review` Markdown and JSON now include a source-free
  Runtime Defense Review Assistant for BYO AI or internal reviewer triage.
- The assistant turns runtime behavior scope, monitoring handoff,
  countermeasure policy, domain/date lock smoke, source-reading compatibility
  scan, release metadata, and protected-build smoke into owner prompts without
  sharing source code, protected output, domains, dates, redirect URLs, beacon
  URLs, countermeasure values, raw config files, API credentials, provider
  keys, collector tokens, customer data, or secrets.

### Identifier cache review assistant (2026-06-08)

- `--identifier-cache-review` Markdown and JSON now include a source-free
  Identifier Cache Review Assistant for BYO AI or internal reviewer triage.
- The assistant turns deterministic cache assumptions, custom dictionary
  replacement, reserved-name coverage, release metadata, and protected-build
  smoke into owner prompts without sharing source code, protected output, cache
  contents, dictionary values, prefixes, reserved-name expressions, raw config
  files, API credentials, provider keys, customer data, or secrets.

### Migration review assistant (2026-06-08)

- `--migration-review` Markdown and JSON now include a source-free Migration
  Review Assistant for BYO AI or internal reviewer triage.
- The assistant turns manual review tracks, source-map policy,
  identifier-cache replacement, runtime-defense behavior, source-reading
  command boundaries, release metadata, and protected-build smoke into owner
  prompts without sharing source code, protected output, source maps, cache
  contents, raw config files, API credentials, provider keys, customer data, or
  secrets.

### Competitor gap review assistant (2026-06-08)

- `--competitor-gap-report` JSON and text output now include a source-free
  Competitor Gap Review Assistant for BYO AI or internal reviewer triage.
- The assistant turns gap prioritization, partial-parity validation, triggered
  migration limitations, source-reading scan boundaries, vendor-claim
  freshness, and plan handoff into owner prompts without sharing source code,
  protected output, API credentials, provider keys, customer data, or secrets.

### Source-map evidence review assistant (2026-06-08)

- `--source-map-evidence` now includes a source-free Source Map Review
  Assistant for BYO AI or internal reviewer triage.
- The assistant turns leak cleanup, manifest verification, secure debugging
  exceptions, bundler cleanup order, and clean reviewer handoff into owner
  prompts without sharing source code, protected output, raw `.map` files,
  source-map contents, original source paths, customer data, or secrets.

### VM proof review assistant (2026-06-08)

- `--vm-proof-pack` now includes a source-free VM Proof Review Assistant for
  BYO AI or internal reviewer triage.
- The assistant turns failed proof checks, VM warnings, cold sensitive
  function scope, hot-path risk, build identity, and protected-build smoke
  evidence into owner prompts without sharing source code, protected output,
  VM bytecode, source maps, provider keys, customer data, or secrets.

### Deployment hygiene evidence packet (2026-06-08)

- Added `--deployment-hygiene-evidence <file>` and
  `--deployment-hygiene-output <file>` to turn
  `tools/Build-UpdatedArchives.ps1 -ReportPath` JSON into a source-free
  archive/deployment hygiene reviewer packet.
- The packet summarizes archive names, entry counts, byte sizes, missing
  required entries, blocked entries, blocked category booleans, exclusion
  policy, operator checklist, rotation triggers, and hygiene-report SHA-256
  without including `Web.config` contents, raw secrets, provider keys,
  database strings, host-specific transforms, customer data, or source code.
- The command writes failed packets before exiting nonzero when archive
  hygiene is blocked, and includes a Deployment Hygiene Review Assistant for
  BYO AI or internal reviewers.

### Runtime incident review assistant (2026-06-08)

- `--runtime-incident-evidence` now includes a source-free Runtime Incident
  Review Assistant for BYO AI or internal reviewer triage.
- The assistant turns urgent response, repeated-signal correlation, dashboard
  status actions, response-window decisions, and alert-routing handoff into
  owner prompts without sharing source code, raw incident payloads, collector
  tokens, customer data, or secrets.

### AI-resistance review assistant (2026-06-08)

- `--ai-resistance-evidence` now includes a source-free Review Assistant
  Packet for BYO AI or internal reviewer triage.
- The packet turns failed required checks, missing attacker-model review
  tracks, VM scope, runtime evidence, compatibility proof, and planned
  Resistance Score wording into owner actions without sending source code,
  protected output, source maps, provider keys, or secrets.
- Text output now renders the assistant packet beside the non-scoring review
  matrix, review decision, claim boundaries, and recommendations.

### Payment-page security-header review assistant (2026-06-08)

- HAR-derived payment-page security-header snapshots now include a
  source-free Review Assistant Packet for BYO AI or internal reviewer triage.
- The packet focuses checkout reviewers on baseline drift, CSP/reporting,
  HSTS, and frame-policy owner actions while explicitly excluding raw response
  headers, cookies, source code, payment data, customer data, provider keys,
  and secrets.
- PCI DSS v4 security-header evidence now preserves or rebuilds the same
  review assistant packet and renders it in Markdown beside the header summary.

### Runtime incident repeated-signal correlation (2026-06-08)

- `--runtime-incident-evidence` now preserves Dashboard Monitoring
  repeated-signal correlation and computes a CSV/row fallback when the export
  does not already include it.
- Runtime evidence Markdown now includes a repeated-signal correlation table
  for repeated fingerprints and reasons, plus recommendations for repeated
  active high/critical signals before reviewer handoff.
- PCI DSS v4 runtime-incident evidence now summarizes repeated-signal
  correlation beside routing, dashboard actions, response windows, and
  checklist metadata.

### Runtime incident evidence dashboard closeout (2026-06-08)

- Runtime incident evidence packets now preserve and recommend the dashboard's
  filtered `Reviewing -> Resolved` closeout action when it is present in a
  Dashboard Monitoring JSON export.
- CLI tests now cover multi-action dashboard metadata, including both
  `Open -> Reviewing` acknowledgement and `Reviewing -> Resolved` closeout.

### BYO AI key health in usage preflight (2026-06-08)

- `ai.usage()` test fixtures now pin the `/v1/ai/usage.ashx`
  `providerKey` health object so Node callers can monitor missing, failed,
  stale, or rotation-review-due BYO AI keys without receiving key material.
- `jso-protector --estimate` now preserves that source-free provider-key
  health in text output and under `estimate.providerKey` in JSON output while
  keeping quota as the only OK/WARN/FAIL gate.
- `jso ai usage --pretty` now prints the same provider-key health summary:
  source-free status label, provider, next stored-key test, rotation review,
  and recommended action.
- TypeScript callers now get an `AiProviderKeyHealth` declaration on
  `AiUsageResult.providerKey`, and package verification guards that declaration.
- The README now documents `jso ai usage --pretty`, typed
  `ai.usage().providerKey` monitoring, the 30-day stored-key test, and the
  90-day rotation review fields surfaced by usage preflight.

### Native parser-engine verification runners (2026-06-08)

- Added PowerShell runners for ES6 lowering conformance, real-world parser
  corpus parse/write-back checks, and the combined parser-engine pre-deploy
  gate so this Windows workspace can verify parser changes without git-bash.
- Added `verify:parser-engine` as a static package guard so the native engine
  runners, parser/ES6 harness docs, archive packaging, and polyglot smoke
  contract cannot drift out of the shipped updated-files package.

### Migration review packet (2026-06-08)

- Added `--migration-review` with optional
  `--migration-review-output <file>` so migrated release teams get one
  source-free owner checklist for all accepted competitor-only fields before
  running focused source-map, identifier-cache, or runtime-defense packets.
- The packet captures review-only field names, value types/counts, limitation
  groups, CLI compatibility warnings, saved report/manifest readiness,
  follow-up commands, protected-build smoke-test actions, and source-free
  sharing boundaries without embedding source code, protected output,
  source-map contents, cache contents, dictionary values, prefixes, domains,
  URLs, dates, seed values, or reserved expressions.
- Migration reports now add a `migration-review` next command whenever any
  review-only item is present, and `--competitor-gap-report` lists the packet
  as a source-free review artifact when limitation groups are triggered.
- The GitHub Action now exposes `migration-review` and
  `migration-review-report`, writes the same source-free JSON packet as a
  pre-protection artifact, and surfaces the report path for upload-artifact
  steps.

### Source-map migration next command (2026-06-08)

- Migration reports now add a post-protect `source-map-evidence` next command
  whenever the source config contains source-map review items.
- The generated command uses the same manifest path emitted by the `protect`
  next command:
  `jso-protector --source-map-evidence dist-protected/jso-manifest.json
  --source-map-evidence-output reports/source-map-evidence.md`.
- Updated the README, website migration docs, tests, and source-map evidence
  guard so source-map migrations point directly at the source-free reviewer
  packet instead of relying on separate documentation.

### Runtime defense migration review packet (2026-06-08)

- Added `--runtime-defense-review` with optional
  `--runtime-defense-review-output <file>` so migrated release teams can turn
  anti-debug, self-defending, runtime lock, console, and countermeasure
  settings into a source-free reviewer packet instead of a broad compatibility
  scan note.
- The packet lists review-only field names, configured runtime evidence,
  monitoring and customer-owned forwarding tracks, countermeasure-policy
  follow-up, source-free release metadata readiness, compatibility-scan
  follow-up, protected-build smoke-test follow-up, and safe-sharing boundaries
  without embedding domains, dates, redirect URLs, beacon URLs, countermeasure
  values, source code, protected output, or compatibility-scan snippets.
- `--competitor-gap-report` now points runtime-self-defending limitations at
  the dedicated `--runtime-defense-review` command and keeps
  `runtime-compatibility-scan` as an explicit source-reading follow-up.
- Migration reports now add a `runtime-defense-review` next command whenever
  the source config contains anti-debug, self-defending, runtime lock, console,
  or countermeasure review items.
- Added a `verify:runtime-defense-review` guard so CLI behavior, tests, docs,
  changelog, and competitive gap notes stay aligned.

### Identifier cache replacement review packet (2026-06-08)

- Added `--identifier-cache-review` with optional
  `--identifier-cache-review-output <file>` so migrated release teams can turn
  `identifierNamesCache`, `identifierNamesCachePath`, `identifiersDictionary`,
  and `identifiersPrefix` into a source-free reviewer packet instead of a
  vague manual-review note.
- The packet lists review-only field names, counts, reserved-name evidence,
  saved API report and manifest readiness, protected-build smoke-test follow-up,
  and safe-sharing boundaries without embedding cache contents, dictionary
  values, prefixes, reserved-name expressions, or source code.
- `--competitor-gap-report` now points identifier-cache and custom-dictionary
  limitations at the dedicated review command, and the main verify chain has a
  `verify:identifier-cache-review` guard so CLI, tests, docs, and gap notes stay
  aligned.
- Migration reports now add an `identifier-cache-review` next command whenever
  the source config contains identifier cache or custom dictionary review items,
  so release owners do not have to discover the packet from separate docs.

### Runtime incident dashboard action metadata (2026-06-08)

- `--runtime-incident-evidence` now preserves `dashboardActions` from
  Dashboard Monitoring JSON exports and renders them in Markdown.
- PCI DSS v4 runtime incident evidence also keeps the same action metadata, so
  reviewer packets can say which source-free dashboard status action is
  available without scraping dashboard HTML.
- The action metadata currently covers the filtered `Open` to `Reviewing`
  acknowledgement path, including scope, matching Open incident count, and the
  safety boundary for resolved, ignored, and already-reviewing incidents.

### Payment-page security-header evidence (2026-06-08)

- Added `--payment-page-headers <csv|json>` to `jso-protector compliance
  pci-dss-v4` so checkout owners can summarize CSP, `script-src`,
  `frame-src`, reporting endpoint, HSTS, referrer-policy, monitor,
  alert-route, baseline-hash match state, checkout surface, and frame context
  in the same source-free PCI evidence packet as script inventory and runtime
  incidents.
- Added `examples/payment-page-security-headers.json` as a starter snapshot
  for payment-page header evidence.
- Added `--payment-page-headers-from-har <file>` with
  `--payment-page-headers-output <file>` and optional
  `--payment-page-url-pattern <regex>` so browser or synthetic-monitor HAR
  exports can become the same source-free security-header snapshot without
  preserving raw cookie headers.
- Added optional `--payment-page-headers-baseline <file>` so the HAR converter
  marks each checkout page or frame as `match`, `mismatch`, or `missing`
  against the last approved security-header snapshot for PCI 11.6.1 change
  review.
- PCI DSS v4 security-header evidence now reports missing baseline pages as a
  first-class count instead of folding them into unstated baseline evidence.
- Added matching GitHub Action support through `payment-page-har`,
  `payment-page-headers-baseline`, `payment-page-url-pattern`, and
  `payment-page-headers-report`, including a source-free JSON artifact path,
  step-summary baseline metrics, and workflow annotations for header drift,
  missing CSP, or missing reporting-endpoint coverage.
- Updated the non-GitHub CI template hint blocks so Jenkins, GitLab, Azure,
  CircleCI, Bitbucket, Buildkite, Drone, Woodpecker, GoCD, Tekton, Argo, and
  TeamCity users see the same security-header baseline option.
- Added optional GitHub Action PCI DSS v4 evidence assembly through
  `pci-dss-v4-evidence`, `pci-dss-v4-report`, and
  `pci-dss-v4-json-report`. The action now auto-creates a manifest when the
  PCI gate is enabled, prefers the signed `.sig` envelope when present, reuses
  payment-page audit/header/runtime evidence inputs, and emits source-free
  Markdown plus JSON report paths.

### Payment-page iframe evidence context (2026-06-08)

- Payment-page script inventory starters, audit packets, and PCI DSS v4
  reports now preserve optional checkout-surface and frame metadata:
  `checkoutSurface`, `frameContext`, `frameOwner`, `parentPageHref`,
  `frameHref`, and `frameOrigin`.
- Audit and PCI Markdown/JSON summaries now include checkout surface counts,
  frame context counts, frame owner counts, and iframe-scoped script counts so
  checkout owners can distinguish parent-page, hosted-checkout, PSP iframe,
  and embedded-frame evidence without embedding raw source code.

### Source-map evidence verification guard (2026-06-08)

- Added `verify:source-map-evidence` to the main package verify chain. The
  guard checks that manifest verification, source-map leak auditing,
  `--source-map-evidence`, public npm docs, GitHub Action artifact wiring, and
  source-free reviewer-boundary wording stay aligned.

### Payment-page evidence verification guard (2026-06-08)

- Added `verify:payment-page` to the main package verify chain. The guard
  checks that payment-page script inventory generation, audit reconciliation,
  PCI DSS v4 evidence import, GitHub Action preflight wiring, public
  Payment Page Protection docs, and source-free Review Assistant Packet
  boundaries stay aligned.

### VM proof-pack verification guard (2026-06-08)

- Added `verify:vm-proof` to the main package verify chain. The guard checks
  that `--verify-vm-proof`, `--vm-proof-pack`, public VM Proof Pack docs,
  GitHub Action inputs/outputs, CLI tests, and reviewer handoff language stay
  aligned around source-free VM evidence, cold-path review, and
  `ready-for-manual-review` decisions.

### Runtime incident evidence packet (2026-06-08)

- Added `--runtime-incident-evidence <csv|json>` with optional
  `--runtime-incident-evidence-output <file>` so account owners can turn a
  Dashboard Monitoring runtime incident export into a standalone source-free
  Markdown or JSON handoff packet for support, on-call, and reviewer workflows.
- The packet summarizes incident counts, active high/critical count, BuildIDs,
  routing recommendation, response window, response checklist, alert routing
  playbook, export SHA-256, safe-sharing boundaries, and review decision. It
  exits nonzero when active high/critical incidents need response.

### Competitor gap review artifacts (2026-06-08)

- Refreshed the `--competitor-gap-report` public-source snapshot to 2026-06-08
  with current javascript-obfuscator, JS-Confuser, Jscrambler, AfterPack,
  Obfuscator.io, JSDefender, and Digital.ai public surfaces.
- Added a `reviewArtifacts` block to the JSON and text report so migrated
  release teams get concrete source-free handoff commands for release-check,
  competitor-gap, source-map evidence, and identifier-cache replacement review,
  plus a source-reading compatibility scan when runtime-defense switches need
  manual validation.

### Source-map evidence packet (2026-06-07)

- Added `--source-map-evidence <manifest>` with optional
  `--source-map-evidence-output <file>` so release teams can generate a
  source-free Markdown or JSON packet proving protected artifacts still match
  the manifest and do not expose `.map` files or `sourceMappingURL` comments.
  The packet lists artifact names, counts, policy boundaries, review decision,
  and next actions without embedding source code or source-map contents.

### Runtime incident alert routing playbook evidence (2026-06-07)

- PCI DSS v4 runtime-incident evidence now preserves Dashboard Monitoring
  `routing.alertRoutingPlaybook` metadata from JSON exports and renders it in
  Markdown. Reviewer packets keep the security-response, customer-owned
  alerting, support-handoff, and reviewer-packet lanes without embedding raw
  incident rows or turning JSO into a managed SOC console.

### Competitor gap source snapshot (2026-06-07)

- `--competitor-gap-report` now includes a dated public-source snapshot in JSON
  and text output. The report names the competitor pages reviewed for the
  migration framing and warns teams to re-check current vendor pages before
  publishing named competitive claims.

### AI evidence review decision (2026-06-07)

- `--ai-resistance-evidence` now includes a source-free `reviewDecision`
  object and text line. The packet is `blocked` when required evidence fails,
  `ready-for-manual-review` when required checks pass but review tracks need
  confirmation, and `ready` when every current track is evidenced.

### Public copy discipline verify gate (2026-06-07)

- Added `verify:copy-discipline` to the main verify chain. The guard scans
  public website copy and the npm README for stale competitor claims, absolute
  AI/security claims, and missing evidence-boundary statements so customer
  pages stay end-user focused and source-reviewable.

### Runtime incident response window (2026-06-07)

- PCI runtime-incident evidence now preserves Dashboard Monitoring
  `responseWindow` metadata from JSON exports and renders it in Markdown.
  The packet records the source-free timing basis, target, due time, overdue
  state, and status action so reviewers can see whether active runtime
  incidents are still inside the response target.
- CSV incident exports now get a conservative response-window fallback in the
  PCI report: the reporter can calculate the due time from the oldest active
  high/critical or active incident, while leaving overdue state unevaluated
  unless a dashboard JSON export supplies generation timing.

### Archive hygiene verify gate (2026-06-07)

- Added `verify:deployment-hygiene` to the main verify chain. The guard checks
  that `tools/Build-UpdatedArchives.ps1` still supports optional JSON hygiene
  reports, keeps blocked deployment files out of updated-files zips, and keeps
  the public Deployment Hygiene docs aligned with the archive handoff command.
- Archive hygiene JSON reports now include a source-free operator checklist
  with before-sharing steps, rotation triggers, and a support boundary so
  release handoffs can say what to verify without exposing config secrets.

### Payment-page inventory audit packet (2026-06-07)

- PCI runtime-incident evidence now includes a source-free response checklist
  derived from Dashboard Monitoring CSV/JSON exports. Dashboard JSON exports
  can carry that checklist directly, and the PCI report preserves it when
  present. The checklist keeps filter scope, routing scope, suggested owners,
  response targets, downstream incident destinations, and safe-sharing
  boundaries without embedding raw incident rows.
- Added optional payment-page script review metadata fields:
  `risk`, `dataAccess`, and `approvalTicket`. Generated inventory starters now
  include blank fields for checkout owners to complete, and PCI evidence
  reports summarize risk ratings, data-access scopes, and approval-ticket
  coverage without embedding every script row.
- The payment-page script inventory audit now reports review-context coverage
  for authorized scripts. Missing optional `risk`, `dataAccess`, or
  `approvalTicket` values show up as non-blocking review-context gaps, while
  unknown scripts, unauthorized scripts, hash drift, missing approved rows,
  late injection, runtime violations, duplicate rows, and required metadata
  gaps remain blocking.
- The same audit now includes a source-free Review Assistant Packet for BYO
  AI or internal reviewer triage, with safe-input boundaries, "do not include"
  reminders, and prompts for unknown scripts, authorization gaps, integrity
  drift, runtime behavior, missing approved scripts, and approval-ticket
  cleanup.
- Added `--script-inventory-audit <inventory.json|csv>` with required
  `--runtime-inventory-snapshot <snapshot.json>` and optional
  `--script-inventory-audit-output <file>` so checkout owners can reconcile an
  approved payment-page script inventory against a saved browser runtime
  snapshot before reviewer handoff.
- The audit stays local and source-free, emits Markdown by default or JSON with
  `--json`, and flags unknown observed scripts, unauthorized observed scripts,
  missing approved scripts, integrity hash mismatches, late injection, runtime
  violation reasons, duplicate approved rows, and incomplete inventory
  metadata.
- `jso-protector compliance pci-dss-v4` now accepts
  `--script-inventory-audit <json>` so the approved-vs-observed reconciliation
  summary can be included in the same PCI evidence report as the script
  inventory and Dashboard Monitoring runtime incident export.
- The shipped CI templates now advertise the same
  `--script-inventory-audit --runtime-inventory-snapshot
  --script-inventory-audit-output --json` gate in their optional preflight
  block, and the GitHub Action exposes matching
  `payment-script-inventory`, `runtime-inventory-snapshot`, and
  `script-inventory-audit-report` inputs for checkout release workflows.
- The GitHub Action audit preflight now writes a step summary and workflow
  annotations for the first source-free findings so checkout owners can see
  script drift in the CI run before opening the JSON artifact.

### VM proof pack handoff (2026-06-07)

- Added `--vm-proof-pack <report.json>` with optional
  `--vm-proof-output <file>` so release teams can turn a saved, source-free API
  report into a reviewer-ready VM evidence packet. Markdown is emitted by
  default; add `--json` for machine-readable evidence.
- The proof pack reuses `--verify-vm-proof` checks and adds build identity,
  release label, polymorphism fingerprint, enabled options, warnings,
  recommendations, and a required reviewer checklist.
- The proof pack now includes a `reviewDecision` object in JSON and a matching
  Markdown section. Passing VM evidence can still be labeled
  `ready-for-manual-review` when the reviewer must confirm cold-function scope
  and protected-build smoke-test results before approval.
- Generated Markdown and JSON proof packs now include hot-path/cold-path
  guidance so reviewers can confirm VM protection stayed on rare sensitive
  functions instead of render loops, animation ticks, scroll handlers, or
  high-frequency parsers.
- Generated proof packs now also include VM compatibility guidance covering
  supported function shape, skipped-with-warning syntax, public callback /
  framework-reflection risks, and reviewer actions before approval.

### Payment-page incident evidence for PCI reports (2026-06-06)

- Added `--script-inventory <csv|json>` to `jso-protector compliance
  pci-dss-v4` so payment-page script authorization, written justification,
  owner, review-date, domain, and integrity-reference coverage can be hashed
  and summarized in the same source-free evidence report.
- Added `examples/payment-page-script-inventory.json` as a starter attachment
  for the source-free payment-page inventory evidence workflow.
- Added `--script-inventory-from-snapshot <file>` with optional
  `--script-inventory-output <file>` so checkout owners can turn an observed
  `third-party-inventory` runtime snapshot into a source-free PCI inventory
  review starter before adding authorization, justification, owner, and review
  dates.
- Added `--runtime-incidents <csv|json>` to `jso-protector compliance
  pci-dss-v4` so the report can summarize the Dashboard Monitoring
  runtime-incident export as source-free PCI DSS v4 11.6.1 evidence.
- Broadened the same flag to accept the Dashboard Monitoring JSON export too,
  so support tooling and release automation can feed machine-readable incident
  evidence into the PCI report without converting to CSV first.
- Runtime incident JSON evidence now preserves Dashboard Monitoring export
  filters, such as active status or high/critical severity, in the JSON summary
  and Markdown evidence table.
- Runtime incident JSON evidence now also preserves Dashboard Monitoring
  routing recommendations, including escalation level, recommended queue, and
  preferred evidence packet, in the PCI evidence JSON and Markdown report.
- Dashboard Monitoring now shows that same source-free routing recommendation
  on the current filtered incident view before checkout and support owners
  export the JSON evidence packet.
- Runtime incident JSON evidence now preserves routing response targets and
  next status actions, so PCI reviewer packets can carry queue, timing, and
  triage-state guidance without embedding source code.
- The Markdown/JSON report now records CSV SHA-256, incident count, status and
  severity counts, open/reviewing totals, high-or-critical unresolved totals,
  received/event date ranges, and Build IDs without embedding every raw URL or
  user-agent row.
- Updated payment-page documentation so checkout owners can pair signed
  manifests, watermarks, beacon/SIEM routing, and dashboard incident history
  in one reviewer-friendly command.

### AI resistance evidence report (2026-06-06)

- Added `--ai-resistance-evidence <report.json>` so security reviewers can
  turn a saved, source-free API report into a current AI-resistance evidence
  checklist without sending source to an AI provider.
- Added `--ai-resistance-evidence-output <file>` so the same checklist can be
  written as a reviewer artifact, using text by default or JSON when `--json`
  is set.
- Extended `verify:ai` static checks so the AI evidence output artifact
  workflow remains visible in both the CLI and public AI Resistance Evidence
  docs.
- Added a non-scoring attacker-model review matrix to the evidence checklist.
  The matrix covers identifier recovery, string recovery, control-flow
  reconstruction, sensitive-function extraction, runtime instrumentation,
  compatibility regression, and source-free handoff without claiming the
  planned Resistance Score is live.
- The report checks build identity, strong protection options, optional VM
  proof, runtime-defense evidence, compatibility evidence, and source-free
  review data while clearly marking Resistance Score as planned, not live.
- The Markdown-style text output and JSON report now include explicit claim
  boundaries for current evidence, planned Resistance Score, bounded AI
  resistance claims, and client-side runtime secrecy limits.
- Added `--require-vm-proof` for release teams that want VM-backed evidence to
  be a hard CI gate.

### VM proof-pack verifier (2026-06-06)

- Added `--verify-vm-proof <report.json>` so security reviewers can validate a
  saved, source-free API report without inspecting private source.
- The verifier checks that VM protection was requested, VM protection was
  applied, the virtualized function count meets `--min-vm-functions`, and
  `VMProtectionWarnings` is empty.
- Added CLI regression tests for saved-report and direct-report shapes.

### Competitor gap report hosted-runtime evidence (2026-06-06)

- The runtime-defense capability now lists hosted dashboard intake,
  `RuntimeDefenseBeaconUrl`, Dashboard Monitoring, SIEM forwarding, and
  countermeasure helpers as the JSO evidence surface.
- The generated migration plan now tells teams to route runtime events to
  customer monitoring or `/v1/runtime/beacon.ashx` before manually validating
  competitor anti-debug/self-defending switches.
- Added regression coverage so the CLI report keeps the hosted first-triage
  path visible during competitor migrations.

### Migration documentation parity wording (2026-06-06)

- Updated the README, migration guide, and security checklist so runtime
  defense is described as a mapped/partial capability with monitoring and
  countermeasure helpers, not as a pure unresolved gap.
- The competitor report docs now name Obfuscator.io explicitly and call out
  manual validation for protected source-map generation, release readiness,
  and review-only migration fields.

### Competitor gap report runtime-defense parity (2026-06-06)

- Runtime-defense parity now reports as `partial` instead of a pure `gap`
  because `jso-protector` ships runtime monitoring, beacon forwarding, and
  countermeasure helpers.
- The competitor list now names Obfuscator.io explicitly alongside
  `javascript-obfuscator`, JS-Confuser, Jscrambler, and JSDefender.
- Migrated anti-debug, integrity, self-defending, and tamper-protection
  switches remain review-only limitations because they are not one-to-one
  hosted API options.
- Added a CLI test assertion so the runtime-defense capability cannot regress
  to a pure gap while the JSO runtime helpers remain available.

### Compliance evidence forwarder — push reports to GRC platforms (2026-06-02)

New `compliance/evidence-forwarder.js` + a `--push` flag on the
`compliance` CLI. After the PCI DSS v4 reporter generates a report, the
forwarder normalizes it into a vendor-neutral evidence artifact (control
mappings, summary, build id, content sha256) and POSTs it to a GRC
platform so the per-build report that already exists also lands in
Drata / Vanta / an in-house system without a manual upload.

```
npx jso-protector compliance pci-dss-v4 \
  --manifest dist/build.manifest.json.sig --root dist \
  --push drata --push-endpoint "$JSO_GRC_ENDPOINT" --push-token "$JSO_GRC_TOKEN"
```

Three profiles shape the envelope + headers: `generic` (artifact as-is,
optional HMAC signing identical to the jso-beacon-slack webhook adapter),
`drata`, and `vanta`. Field names are overridable via `fieldMap`. The
tenant endpoint + token are operator-supplied — GRC platforms are
multi-tenant, so the module deliberately does not hardcode a vendor API
version it can't keep current; the profile only shapes the request.

Contract matches the SIEM adapters: the forwarder never throws — a flaky
GRC endpoint resolves to `{ ok:false, status:0, error }` and does NOT
change the compliance exit code (the report's own verdict is the
authority; forwarding is a side channel). 14 new tests (artifact
normalization + stable hashing, all three profiles, fieldMap overrides,
HMAC verifiability, transport-failure + throw isolation, non-2xx
handling). 315/315 full jso-protector suite passes.

### AI script data governance — block LLM-bound exfiltration (2026-06-02)

New browser runtime module `jso-protector/runtime/ai-script-governance.js`
that hooks `fetch`, `XMLHttpRequest`, and `WebSocket` on the protected
page and watches for requests that hit a known LLM provider endpoint.
Closes the Jscrambler "AI Data Governance" parity gap surfaced by the
latest deep-research workflow.

What it catches:

- a Magecart-style script exfiltrating card data to a free OpenAI
  endpoint ("summarize this number")
- an untrusted third-party widget quietly streaming page contents to
  its own AI backend
- a compromised CI/CD dependency that POSTs conversation history to
  a side-channel LLM

Default known-host list covers OpenAI / Anthropic / Google
(Gemini + Vertex) / Groq / Together / Mistral / AWS Bedrock
(region-prefixed) / Cohere / Perplexity / xAI / DeepSeek / Replicate /
Hugging Face Inference / Azure OpenAI (tenant-prefixed). Extensible via
`config.additionalKnownLLMHosts`.

Two enforcement modes:

- `log` (default) — records destination + payload size + caller stack
  frame; request proceeds.
- `block` — refuses. `fetch` returns a synthetic HTTP 451; XHR
  transitions to `readyState=4 status=0`; `WebSocket` constructor
  throws.

Events emit through the same beacon channel as `third-party-inventory`,
so the existing `jso-beacon-slack` SIEM adapters forward them unchanged
(envelope `kind: "ai-data-access"`).

17 new tests, 301/301 full jso-protector suite passes.

### Electron V8 bytecode adapter + React Native 2026 playbook (2026-06-02)

Completes deep-research GAP 5.

- New sibling package **`jso-protector-electron`** (`packages/jso-protector-electron/`)
  with `compileDirectory({input, output, mode})` that walks JSO-protected
  JS and emits V8 bytecode `.jsc` files via `vm.Script.createCachedData()`.
  Two execution modes:
  - `embedded` (run under Electron): emits real `.jsc` files bound to
    the host Electron's V8 build.
  - `scaffold-only` (plain Node): emits the source + per-file
    `.bytecode-meta.json` for CI environments that don't ship Electron.
  - `auto` picks based on `process.versions.electron`.
  CLI: `jso-protector-electron --input dist-protected --output dist-bytecode`.
  Each `.jsc` carries an 8-byte magic + length-prefixed JSON header +
  the V8 cachedData blob so an auditor can validate coverage. 14 tests
  cover both modes, the CLI surface, the header layout, and the
  actionable error when embedded mode is invoked under plain Node.

- New **`examples/react-native/README.md`** playbook (2026 refresh)
  walking the modern React Native + JSO pipeline:
  - Metro `customSerializer` JSO integration (existing `metro.js`).
  - Hermes bytecode layering (`.hbc`).
  - **Play Integrity API** (Android) replacing the deprecated
    SafetyNet Attestation (shut down 2024-06-30).
  - **DCAppAttestService** (iOS) for on-device attestation.
  - JSO release manifest + beacon flow for the in-app verifier.
  - Field-tested gotchas (Reanimated worklets, native-module bridge
    name preservation, dev-mode bypass).

### RASP active countermeasures + named config sets (2026-06-02)

Two paired build-time + browser-runtime features completing deep-research
GAP 4 (JSDefender v2 / Jscrambler RASP parity).

**Browser runtime (`runtime/countermeasures.js`):**

Six configurable reactions to runtime-defense tamper events, fired after
the beacon POST so even destructive actions leave telemetry:

- `log` - record-only; default, no UI side effects
- `break` - stub every function on `window.__jsoEntry.*` so the protected
  entry points become no-ops
- `deleteCookies` - clear cookies + sessionStorage + localStorage to
  defuse stale credentials in a poisoned page
- `selfDestruct` with `mode: blank-body | crashWithMemory | crashTimeout`
- `redirect` to a safe URL (`javascript:` schemes rejected at build time)
- `callback` invoking a customer function with the violation event

Configurable as a single action or an ordered array
(`onTamper: ["break", "deleteCookies"]`). An `allowList` keeps dev
environments from accidentally shipping destructive escalations.

**Build-time named sets (`config/named-sets.js`):**

Apply different protection profiles to different parts of one app:

```json
{
  "preset": "balanced",
  "countermeasures": { "onTamper": "log" },
  "namedSets": {
    "checkout":      { "match": ["src/checkout/**", "src/wallet/**"],
                       "preset": "maximum",
                       "options": { "AddDeadCode": true, "DeadcodeLevel": "High" },
                       "countermeasures": { "onTamper": ["break", "deleteCookies"],
                                            "redirectUrl": "https://example.com/outage" } },
    "authenticated": { "match": ["src/dashboard/**", "src/account/**"],
                       "preset": "maximum",
                       "countermeasures": { "onTamper": ["deleteCookies"] } }
  }
}
```

First-matching-set wins, so config authors get deterministic precedence
by writing sets in priority order (like a route table). The glob matcher
supports `**`, `*`, `?`, `[a-z]`, `{a,b}` — including `/**` at end which
matches the bare directory plus any nested files (so `src/checkout/**`
covers `src/checkout` AND `src/checkout/a/b.js`).

Schema (`jso.config.schema.json`) extends with `countermeasures` and
`namedSets` as top-level properties plus a `$defs/countermeasures`
shared definition. Strict `additionalProperties: false` is preserved
on both the top-level and per-set objects.

28 new tests (15 countermeasures + 13 named-sets), full jso-protector
suite **284/284 pass**, verify chain green.

### Third-party script inventory + Magecart detection (2026-06-02)

New browser-side runtime module `jso-protector/runtime/third-party-inventory.js`
that snapshots every script loaded by a payment page and flags violations
to a beacon URL.

Detection signals:

- script `src` outside the configured `originAllowlist`
- inline `<script>` whose sha256 is not in `inlineContentAllowlist`
- script DOM-injected AFTER `document.readyState === "complete"`
  (defer-injection is a common Magecart evasion)
- same script URL but its content sha256 changed since the previous
  deploy (catches CDN supply-chain swap attacks)

Pure browser code (Web Crypto, fetch, PerformanceObserver) so it ships
in the protected bundle without server-side support. The module's
inventory snapshots emit through the same beacon channel as the rest
of the runtime-defense suite, so jso-beacon-slack forwards them to
Splunk / Elasticsearch / generic webhook unchanged.

```js
// In the page that's being protected:
const tpi = require("jso-protector/runtime/third-party-inventory");
tpi.attach(window, {
  buildId: window.__jsoBuildId,
  originAllowlist:        ["https://www.example.com", "https://cdn.example.com"],
  inlineContentAllowlist: ["a3f5...sha256...", "b07e..."],
  previousContentBySrc:   { "https://cdn.example.com/lib.js": "<old-sha256>" },
  beaconUrl:              "https://beacon.example.com/v1/jso/inventory",
  flushIntervalMs:        15000,
});
```

16 new tests (256 total in jso-protector) cover the pure-engine path
(unknown-origin / unknown-inline / injected-after-load /
content-changed-vs-previous-deploy / dedup / backpressure /
'*'-wildcard / trailing-slash) and the DOM-attach path
(idempotency + `createElement('script')` setter intercept).

### PCI DSS v4.0.1 compliance reporter (2026-06-02)

New offline subcommand `jso-protector compliance pci-dss-v4` that consumes
a `--sign-release`-produced manifest envelope and emits a Markdown +
JSON evidence report mapping JSO primitives onto the two PCI DSS v4
controls JSO directly contributes to:

- **Req 6.4.3** payment-page script management — covered by HMAC watermarks
  (sub-req .a, authorized), Ed25519 release attestation (.b, integrity),
  and the manifest `files[]` array (.c, inventory).
- **Req 11.6.1** change/tamper detection — covered by Runtime Defense +
  BeaconUrl wiring (.a/.b, detection + cadence) and jso-beacon-slack SIEM
  adapters (.c, personnel alerts).

CLI:

```
jso-protector compliance pci-dss-v4 \
  --manifest dist/build.manifest.json.sig \
  --root dist \
  --watermark-key "$JSO_WATERMARK_KEY" \
  --beacon-url https://beacon.example.com/v1/jso \
  --siem splunk-hec \
  --organization "Example Corp" \
  --output reports/pci-dss-v4.md
```

Exit codes follow the same shape as `--verify-release`: 0 = fully evidenced,
1 = evidence gaps, 2 = manifest unsigned. The reporter is pure-offline —
no HTTP traffic, no telemetry. New `compliance/pci-dss-v4/` directory
ships in the npm tarball; 12 new tests (240 total) all pass.

### Supply-chain integrity surface

- Added `--competitor-gap-report` to summarize covered / partial / gap parity
  against common JavaScript obfuscator surfaces after migrations, including
  runtime-defense, source-map, lock, and release-forensics guidance.
- Added public TypeScript declarations and package verification coverage for
  the competitor gap report helpers.
- Added `--competitor-gap-report` to the optional CI template hint block and
  extended CI template verification so all shipped pipelines keep surfacing
  competitor migration gap checks.
- Added the same competitor gap report step to Kubernetes and Helm release
  examples, plus migration/security/example docs that call out its
  source-free behavior.
- Added `competitor-gap` to migration next-command output, gave the JSON report
  a stable `format` / `version` envelope, and included the report in
  `--local-only` preflight guidance.
- Added `--watermark <tag> --watermark-key <key>` &mdash; injects an HMAC-SHA256
  header-comment marker into every input file before submission to the
  obfuscation API. The obfuscator's `KeepComment` option preserves the
  block verbatim through every transform so the marker survives in the
  protected output. `JSO_WATERMARK_KEY` env-var fallback. Wire format
  documented at /Docs/WireFormat.aspx#watermark.
- Added `--verify-watermark <file>` &mdash; single-file watermark validator.
  With `--watermark-key`, runs a constant-time HMAC compare; without, prints
  the embedded tag (lookup-only mode for forensic inspection of leaked
  artifacts). Exit codes: 0 valid / 1 invalid / 2 missing-or-no-key.
- Added `--scan-watermarks <dir>` &mdash; tree walker for forensic / inventory
  use. Skips `node_modules` + `.git`. Aggregates findings into a sorted
  report. Exit codes: 0 all clean, 1 at least one invalid signature, 2 no
  watermarks found at all.
- Added `--sign-release <priv.pem>` &mdash; produces an Ed25519-signed release
  attestation `.manifest.json.sig` next to the manifest. Covers BuildId +
  polymorphism fingerprint + label + per-file SHA-256. Canonical-JSON
  serialization so verifiers in any language produce byte-identical
  signatures.
- Added `--verify-release <sig>` &mdash; validates the envelope. Stage 1 is
  Ed25519 signature over canonical manifest. Stage 2 (when `--verify-root
  <dir>` is also passed) re-hashes referenced files on disk to catch
  post-signing artifact tampering. `--public-key <pem>` pins to a trusted
  public key (defeats key-substitution attacks).
- Added `--genkey-release <name>` &mdash; mints a fresh Ed25519 keypair, writes
  `<name>.priv.pem` (0o600) and `<name>.pub.pem` (0o644). Removes the
  "where do I get keys" friction.
- Added `--estimate` &mdash; pre-flight quota gate. Walks input files, calls
  `/v1/ai/usage` for current-month counters, prints a three-state report
  (OK / WARN / FAIL). FAIL (exit 1) when actions remaining = 0 blocks
  builds that can't finish. Network failure on the usage endpoint
  downgrades to WARN with a note (doesn't crash the pipeline).
- Added `--ai-precheck` &mdash; inline AI compatibility gate. Runs
  `/v1/ai/compat-check` on every input file before the obfuscation API
  is called; aborts the build on findings per `--ai-precheck-fail-on`
  (`error` / `warning` / `never`). Quota untouched on failure.
- New `jso ai compat-scan` subcommand &mdash; stand-alone compat-check over
  every input file in `jso.config.json`. Useful for pre-commit hooks and
  IDE integrations.
- jso.config.schema.json: added `report`, `label`, `watermark`, and
  `watermarkKey` to the schema so config validators stop rejecting these
  documented keys. (Previous behavior: `additionalProperties: false`
  caused IDE schema validators to flag the keys as unknown.)
- Coverage: new test suites `test/ai-precheck.test.js`, `test/watermark.test.js`,
  `test/release-signer.test.js`, `test/estimate.test.js`,
  `test/scan-watermarks.test.js`, `test/compat-scan.test.js`,
  `test/wire-format-vectors.test.js` &mdash; 54 new cases on top of the
  pre-existing AI client tests. Full suite 64/64.

### --init templates

- Added `nextjs-app` and `react-native-app` `--init` templates plus `next`, `nextjs`, `react-native`, `reactnative`, `metro`, and `expo` aliases so scaffolded configs match the existing framework integrations.
- Added `vite-app`, `webpack-app`, `rspack-app`, and `turbopack-app` `--init` templates plus matching aliases so supported modern build paths now have first-class starter configs.
- Added `parcel-app`, `bun-app`, and `browserify-app` `--init` templates plus matching aliases so shipped Parcel/Bun/Browserify workflows now scaffold directly from the CLI.
- Added first-class `parcel`, `bun`, and `turbopack` package exports so the documented post-build workflows now ship with callable helpers and typed plan/config APIs.

## 0.1.1

- Added `--mode` support so CommonJS and ES module config functions can branch cleanly across production, staging, and similar release profiles.
- Added the `electron-app` init template plus `electron` and `desktop` aliases for faster Electron/Desktop release onboarding.
- Added shipped Parcel, Bun, and Turbopack post-build examples plus README coverage for modern release pipelines without dedicated wrapper entrypoints.
- Fixed TypeScript init-template declarations so the public types include the shipped `electron-app` scaffold and aliases.
- Added regression coverage to ensure package JSON files do not introduce duplicate keys.
- Updated local-install tarball references and package metadata for the new patch release.

## 0.1.0

Initial private package scaffold for JavaScript Obfuscator HTTP API workflows.

- Added dependency-free CLI for directory, single-file, stdin/stdout, and dry-run workflows.
- Added named presets: `standard`, `balanced`, and `maximum`.
- Added JSON config schema, `--init`, online web-preset import, and CI option overrides.
- Added `doctor` preflight checks with optional tiny live API validation.
- Added Node API plus esbuild, Vite, Rollup, and Webpack entrypoints.
- Added a dedicated `react-native` alias entrypoint for Metro/Expo integrations.
- Added TypeScript declarations for public entrypoints.
- Added source-map removal, asset copying, include/exclude filtering, and public-name preservation helpers.
- Added Webpack 4 compatibility through a legacy `emit`-hook fallback while keeping Webpack 5 and Rspack support.
- Expanded Browserify, Webpack plugin, and Webpack/Rspack loader coverage to respect configured script extensions such as `.mjs` and `.cjs`.
- Added JS-Confuser migration helpers for the CLI and Node API, including starter-config conversion, option explanations, and direct translation for common presets, locks, and string/control-flow settings.
