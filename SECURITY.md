# Security and Processing Notes

`jso-protector` is a workflow wrapper around the JavaScript Obfuscator HTTP API.

## Workflow Matrix

| Workflow | Sends source to hosted API | Typical use | Notes |
| --- | --- | --- | --- |
| `--dry-run` | No | CI file-list and config checks | Prints matched files and config summary only. |
| `--validate-config` | No | Static config validation | Checks config shape, paths, budgets, and option names without API calls. |
| `--doctor` | No | Release preflight | Checks credentials presence, path readiness, matched files, and output readiness. |
| `--release-check` | No | Combined release preflight | Runs validation, dry-run planning, and doctor checks as one report. |
| `--release-check --strict` | No | Strict release gate | Treats validation warnings as release-check failures. |
| `--competitor-gap-report` | No | Migration parity review | Reports covered, partial, and gap areas for common competitor migration surfaces. |
| `--doctor --check-api` | Yes, generated sample only | Endpoint and credential smoke test | Sends a tiny generated `jso-doctor.js` sample, not project source. |
| `--local-only` | No | Source-handling policy check | Prints the local/offline path and exits without reading project source. |
| CLI protection | Yes | Protect built JavaScript files | Sends matched JavaScript file contents to `endpoint`. |
| Node API | Yes | Custom build scripts | Sends provided source strings or matched files to `endpoint`. |
| Bundle plugins | Yes | Vite, Rollup, Webpack, esbuild, Browserify, Gulp, Grunt | Sends selected emitted JavaScript chunks or stream files to `endpoint`. |
| Desktop workflow | Yes | GUI batch and mixed-file projects | Sends selected JavaScript to the hosted service; surrounding mixed-file content stays local. |

## Source Processing

- CLI protection sends matched JavaScript file contents to the configured `endpoint`.
- `--parse-html` sends only marked inline `<script data-javascript-obfuscator>` blocks from HTML files to the API. Unmarked inline scripts, external scripts, and module scripts are preserved locally.
- Conditional markers fail by default. Passing `--honor-conditional-comments` sends enabled regions to the API and preserves disabled `javascript-obfuscator:disable` regions locally.
- Bundle plugins send emitted JavaScript chunks to the configured `endpoint`.
- `--release-check` and `--doctor` do not send source code unless `--check-api` is also provided.
- `--competitor-gap-report` reads config metadata and migration fields only; it does not read or send project source.
- `--check-api` sends a tiny generated sample named `jso-doctor.js`.
- `--dry-run` does not call the API.
- `--print-config --json` redacts API credentials as `[set]` or `[missing]`.
- Release manifests contain file names, source/output paths, byte counts, SHA-256 hashes, and processing metadata for virtual API items. Treat manifests as release metadata.
- `--verify-manifest` checks protected output against those recorded hashes and can verify a relocated artifact tree with `--verify-root`.

Use `jso-protector --local-only --json` in package scripts or onboarding docs when users need the source-handling decision in the terminal. It exits without reading project source and identifies the available local preflight checks. Current protection workflows, including desktop, send selected JavaScript to the hosted service and do not meet a policy that forbids source transfer.

## Credentials

- Prefer `JSO_API_KEY` and `JSO_API_PASSWORD` environment variables or CI secrets.
- Do not commit dashboard credentials to `jso.config.json`.
- `--validate-config` warns when `apiKey`, `apiPassword`, `--api-key`, or `--api-password` contain inline values instead of environment references.
- Rotate credentials if they are pasted into logs, tickets, chat, or build output.
- Use the short environment names for new automation. Long aliases are accepted for compatibility: `JAVASCRIPT_OBFUSCATOR_API_KEY`, `JAVASCRIPT_OBFUSCATOR_API_PASSWORD`, and `JAVASCRIPT_OBFUSCATOR_ENDPOINT`.

## Payment and Entitlements

The npm package is a local client only. It must not contain billing rules, plan limits, shared service credentials, or payment bypass logic. Paid access is enforced by the hosted JavaScript Obfuscator API after the CLI sends the user's dashboard API key and password.

Server-side checks should validate account status, plan/credit limits, endpoint access, and request size before protection work runs. Unpaid, expired, disabled, or over-limit accounts should be rejected by the API regardless of how the local npm client was installed.

Client-side API error messages should help users find the dashboard credential or account issue without echoing secrets. The CLI redacts API key and password values from hosted API error messages before printing them.

## Source Maps

The CLI and bundle plugins exclude or remove JavaScript source maps by default because source maps can reveal original source. Keep this behavior for protected release artifacts unless another secure build step handles maps. Use `--source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md` when a reviewer needs a source-free handoff proving the protected artifact has no `.map` files or `sourceMappingURL` comments.

## Vendor Code

Use `include` and `exclude` to protect first-party release chunks and skip vendor bundles, polyfills, framework runtime files, and generated code that should not be transformed.

## CI Practices

- Run `jso-protector --config jso.config.json --release-check --json` before sending source code.
- Run `jso-protector --config jso.config.json --competitor-gap-report --json` for migrated competitor configs so runtime-defense mapping, source-map policy, and other manual-review items stay visible.
- Run `jso-protector --verify-manifest dist-protected/jso-manifest.json` after packaging or artifact download when release integrity needs a local proof step.
- Run `jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.md` before publishing protected artifacts that must prove source maps are absent.
- Store API credentials as encrypted CI secrets.
- Keep protected output in a separate directory such as `dist-protected`.
- Publish protected artifacts, not the unprotected build folder.
- Store release manifests with build artifacts only when your release process allows path and hash metadata.
