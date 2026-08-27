# Release Guide

`jso-protector` is a published npm package. It is the developer-workflow front
end for JavaScript Obfuscator: protection itself runs through the hosted HTTP
API with the user's own dashboard credentials, or on their machine with
`--local`.

## Metadata Policy

| Field | Value | Reason |
| --- | --- | --- |
| npm name | `jso-protector` | Published name on the public registry. |
| license | `SEE LICENSE IN LICENSE` | Proprietary; the LICENSE file ships in the tarball. |
| credentials | Environment variables or CLI flags only | Keeps API credentials out of package files and logs. |
| payment enforcement | Hosted API only | Keeps billing, account status, credits, and plan limits on the server. |

Do not add billing logic, shared API keys, account secrets, or plan-limit
decisions to this package. The server must reject unpaid, expired, disabled, or
over-limit accounts.

## Verification before any release

```bash
npm test                        # offline suite
npm run smoke                   # package smoke
npm run verify:package          # packaged contents + documentation contract
npm run verify:publish-metadata # license, files, metadata policy
npm run verify                  # everything, ~10 minutes
```

With test credentials only, the live API preflight:

```bash
npm run smoke:api
jso-protector --config jso.config.example.json --doctor --check-api --json
```

`prepublishOnly` runs the verification chain again at publish time, so a release
cannot go out on an unverified tree.

## Release loop

A version bump is not just `package.json` — the site serves matching artifacts
and their checksums, and `check-download-artifacts` fails when any of them
disagree. Work in this order:

1. **Bump the version** in `package.json`, and anywhere an example or template
   pins it. `npm run verify` catches a stale pin.
2. **Write the CHANGELOG entry** — newest first, describing what changed for a
   user rather than which files moved.
3. **Build the artifacts** into `2026/JSO-Website/download/jso-protector/`:
   ```bash
   npm pack                     # jso-protector-<version>.tgz
   ```
   plus the `-server-upload.zip` companion of the same contents.
4. **Update the published checksums** in
   `2026/JSO-Website/download/SHA256SUMS.txt`, and the version strings on
   `downloads.aspx`, `jso-protector.aspx`, and `Docs/NpmCli.aspx`. Bump the
   `?v=` query on anything cached.
5. **Remove the superseded artifacts** from the download folder. The inventory
   check is exact: an extra file fails it as loudly as a missing one.
6. **Run `npm run verify` again** and fix anything it finds before uploading.
7. **Deploy the site surface** (see `trust/DEPLOY-LOG.md` for the FTPS flow and
   the standing requirement to record every deploy there).
8. **Publish**: `npm publish`. Then install from the registry into a scratch
   directory and exercise the new behaviour end to end — a green local tree
   proves the tarball, not the release.

## What ships in the tarball

`files` in `package.json` is the allowlist. `verify:package` asserts the packed
contents against it, so adding a runtime file means adding it there too.
Documentation that ships to customers — `README.md`, `MIGRATION.md`,
`SECURITY.md`, and this file — is read on npmjs.com by people deciding whether
to trust the product. Keep it true to what the published package actually is.
