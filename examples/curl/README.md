# curl / bash reference implementation

The smallest possible compliant client of the [JSO HTTP API](https://javascriptobfuscator.com/docs/wireformat.aspx). Use this when:

- You need to add JSO protection to a build pipeline written in a language we don't ship a client for.
- You want a copy-paste reference for what the wire format actually looks like on the network.
- You're debugging an API call and want to bypass any client-side magic.

## Requirements

- `bash` (any modern version)
- `curl`
- `jq`

## Usage

```bash
export JSO_API_KEY="<base64-from-dashboard>"
export JSO_API_PASSWORD="<base64-from-dashboard>"

# Protect a single file (input/output pair):
./protect.sh dist/app.js dist-protected/app.js

# Or several pairs at once:
./protect.sh \
    dist/app.js     dist-protected/app.js \
    dist/vendor.js  dist-protected/vendor.js

# Pick a preset:
JSO_PRESET=maximum ./protect.sh dist/app.js dist-protected/app.js

# Tag the release:
JSO_LABEL="$(git rev-parse HEAD)" ./protect.sh dist/app.js dist-protected/app.js
```

## Limitations

This is a 100-line shell script. It deliberately doesn't implement:

- The `--dry-run` / `--release-check` validation modes (use the npm CLI for those).
- Identifier-map persistence as a separate `jso-report.json` file (parse `Report.GlobalIdentifierMap` / `Report.MemberIdentifierMap` from the response yourself).
- The bundler-plugin integration surface (`vite`, `webpack`, `rollup`, ...).
- Retry logic, exponential backoff, or rate-limit handling.

For a production CI integration, use one of the [shipped language clients](https://javascriptobfuscator.com/docs/clients.aspx) instead. The shell script is a reference, not a target.

## Verify the response shape

```bash
JSO_API_KEY=... JSO_API_PASSWORD=... ./protect.sh dist/app.js dist-protected/app.js
# protect.sh: wrote dist-protected/app.js
# protect.sh: BuildId=rel-abcdef123 Fingerprint=1234567890abcdef
```

If you see "BuildId=" with an empty value, the server response didn't carry the field — check that your account is on Basic+ and the API key is current.
