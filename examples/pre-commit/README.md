# Pre-commit hook example for jso-protector

[`pre-commit`](https://pre-commit.com/) is a popular framework for managing git hooks. This example wires `jso-protector --release-check` and `--dry-run` into your local commit cycle so misconfiguration is caught at the developer's machine instead of in CI.

## Why this is a release-check, not a full protect

A pre-commit hook runs on every `git commit` — potentially dozens of times a day per developer. POSTing source to the JSO API on every commit would:

- Burn quota fast (Corporate plan has request limits)
- Send your in-flight, sometimes-broken-mid-refactor code to the hosted API
- Make commits slow (the full protection round-trip is seconds, not milliseconds)

The release-check and dry-run modes were built for exactly this use case. They validate configuration, file enumeration, and credentials without sending source. The actual protection happens later — in CI, when the release artifact is built.

## Install

```bash
# 1. Install pre-commit if you haven't already.
pip install pre-commit

# 2. Make sure jso-protector is installed as a dev dependency.
npm install --save-dev jso-protector

# 3. Copy `.pre-commit-config.yaml` from this folder to your repo root,
#    then activate the hooks.
pre-commit install
```

After that every `git commit` runs the JSO checks against staged JavaScript.

## What the hooks check

| Hook | Stage | Catches |
|---|---|---|
| `jso-release-check` | pre-commit | Config drift: missing required option, broken path, malformed JSON, credential not configured. |
| `jso-dry-run` | pre-commit, pre-push | File enumeration: catches "I added a new vendor file nobody intended to protect" mistakes. |

## CI parity

The CI templates in `node_modules/jso-protector/ci/` all run `--release-check` BEFORE the full protect. The pre-commit hooks call the same check, so a commit that passes locally is overwhelmingly likely to pass the CI gate.

## See also

- [npm CLI workflow](https://javascriptobfuscator.com/docs/npmcli.aspx)
- [Build integrations hub](https://javascriptobfuscator.com/build-integrations.aspx)
