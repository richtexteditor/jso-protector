#!/usr/bin/env bash
# Minimum-viable curl reference implementation of the JSO HTTP API client.
#
# Use this when the language you need isn't covered by one of the shipped
# clients (Node / Python / Go / .NET / Ruby / PHP / Rust). The script
# matches the wire format documented at
# https://www.javascriptobfuscator.com/Docs/WireFormat.aspx
#
# Required: curl, jq.
#
# Required env vars:
#   JSO_API_KEY      — base64 API key from the JSO dashboard
#   JSO_API_PASSWORD — base64 API password from the JSO dashboard
#
# Optional env vars:
#   JSO_PRESET       — standard | balanced (default) | maximum
#   JSO_LABEL        — release label tagged on the request
#   JSO_ENDPOINT     — override the API endpoint URL
#
# Usage:
#   ./protect.sh path/to/input.js path/to/output.js [more input/output pairs...]

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
    echo "protect.sh: jq is required (install via your package manager)" >&2
    exit 2
fi
if [ -z "${JSO_API_KEY:-}" ] || [ -z "${JSO_API_PASSWORD:-}" ]; then
    echo "protect.sh: JSO_API_KEY and JSO_API_PASSWORD must be set" >&2
    exit 2
fi
if [ $# -lt 2 ] || [ $(($# % 2)) -ne 0 ]; then
    echo "Usage: $0 input1.js output1.js [input2.js output2.js ...]" >&2
    exit 2
fi

preset="${JSO_PRESET:-balanced}"
endpoint="${JSO_ENDPOINT:-https://www.javascriptobfuscator.com/HttpApi.ashx}"

# Build the Items array from the (input, output) argument pairs.
items_json="[]"
pairs=()
while [ $# -ge 2 ]; do
    in="$1"; out="$2"; shift 2
    if [ ! -f "$in" ]; then echo "protect.sh: input not found: $in" >&2; exit 1; fi
    pairs+=("$in:$out")
    file_name="$(basename "$in")"
    file_code="$(jq -Rs . < "$in")"
    items_json="$(jq --arg n "$file_name" --argjson c "$file_code" \
        '. += [{FileName: $n, FileCode: $c}]' <<< "$items_json")"
done

# Preset option blocks — keep these in sync with the WireFormat.aspx doc.
case "$preset" in
    standard)
        preset_opts='{"Compress":true,"EncodeStrings":true,"MoveStringsIntoArray":true,"NameMangling":true}' ;;
    balanced)
        preset_opts='{"Compress":true,"EncodeStrings":true,"EncryptStrings":true,"MoveStringsIntoArray":true,"NameMangling":true,"DeepObfuscate":true,"FlatTransform":true,"CodeTransposition":true}' ;;
    maximum)
        preset_opts='{"Compress":true,"EncodeStrings":true,"EncryptStrings":true,"MoveStringsIntoArray":true,"NameMangling":true,"DeepObfuscate":true,"FlatTransform":true,"CodeTransposition":true,"ProtectMembers":true,"RenameGlobals":true,"MoveMembers":true,"DeadCodeInsertion":true}' ;;
    *) echo "protect.sh: unknown preset: $preset" >&2; exit 2 ;;
esac

# Assemble payload.
payload="$(jq -n \
    --arg key "$JSO_API_KEY" \
    --arg pwd "$JSO_API_PASSWORD" \
    --arg name "${JSO_NAME:-bash-session}" \
    --arg label "${JSO_LABEL:-}" \
    --argjson items "$items_json" \
    --argjson preset "$preset_opts" \
    '{APIKey: $key, APIPwd: $pwd, Name: $name, Items: $items} + $preset
     + (if $label == "" then {} else {ReleaseLabel: $label} end)')"

# POST. -f fails on HTTP 4xx/5xx; -sS keeps quiet but surfaces errors.
response="$(curl -fsS -X POST \
    -H "Content-Type: text/json" \
    -H "User-Agent: jso-curl/0.1" \
    --data "$payload" \
    "$endpoint")"

type="$(jq -r '.Type' <<< "$response")"
if [ "$type" != "Succeed" ]; then
    msg="$(jq -r '.Message // .ErrorCode // "API request failed"' <<< "$response")"
    echo "protect.sh: $msg" >&2
    exit 1
fi

# Write each protected file back to its output path.
for pair in "${pairs[@]}"; do
    in="${pair%%:*}"; out="${pair#*:}"
    file_name="$(basename "$in")"
    code="$(jq -r --arg n "$file_name" '.Items[] | select(.FileName == $n) | .FileCode' <<< "$response")"
    if [ -z "$code" ]; then
        echo "protect.sh: API response did not include $file_name" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$out")"
    printf '%s' "$code" > "$out"
    echo "protect.sh: wrote $out"
done

build_id="$(jq -r '.Report.BuildId // ""' <<< "$response")"
fp="$(jq -r '.Report.PolymorphismFingerprint // ""' <<< "$response")"
echo "protect.sh: BuildId=$build_id Fingerprint=$fp"
