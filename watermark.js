"use strict";

// Watermarking for jso-protector.
//
// What it does: before source goes to the obfuscation API, the CLI
// prepends a header-comment block carrying an HMAC-SHA256 over a
// caller-supplied tag. The obfuscator's existing "Keep Header Comment"
// option preserves the block through every transform (string array
// moves, encryption, control-flow flattening, dead code, etc.), so the
// marker survives intact in the protected output.
//
// Use cases:
//   - Anti-piracy: "this build came from our official pipeline; here is
//     the cryptographic proof"
//   - License-enforcement: bind a per-customer tag to the obfuscated
//     artifact so a leak can be traced back
//   - Forensics: dispute that an attacker claims to have produced the
//     code themselves — the watermark verifies otherwise
//
// Why a header comment and not a string literal inside the program?
//   The obfuscator preserves header comments verbatim when KeepComment
//   is true. String literals get encoded / encrypted / moved into the
//   string array, so a verifier would need to reverse the obfuscation
//   to find them. The header-comment path is robust and zero-friction.
//
// Format (versioned so we can evolve without breaking old artifacts):
//
//   /*! __jso_watermark_v1
//    * tag: <base64url>
//    * sig: <base64url HMAC-SHA256(tag, key)>
//    */
//
// The `/*!` opening is the convention preserved by most minifiers /
// transforms (it's a "bang comment"); we use it so the marker survives
// even if a customer pipes the protected output through a second tool.

const crypto = require("node:crypto");

const MARKER     = "__jso_watermark_v1";
const MARKER_RE  = /\/\*!?\s*__jso_watermark_v1\s+\*\s*tag:\s*([A-Za-z0-9_-]+)\s*\*\s*sig:\s*([A-Za-z0-9_-]+)\s*\*\//;

function b64url(buf) {
    return Buffer.from(buf).toString("base64")
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
    str = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Buffer.from(str, "base64");
}

// Compute the canonical HMAC-SHA256 over a watermark tag. Returns the
// signature as base64url-encoded bytes. The tag itself is the plaintext
// caller-supplied identifier (e.g. customer-id, release-id, license
// number) — we sign it so a leaked artifact can be authenticated even
// when the tag is publicly visible inside the protected file.
function signTag(tag, key) {
    if (!tag) throw new Error("watermark: tag is required");
    if (!key) throw new Error("watermark: key is required");
    const h = crypto.createHmac("sha256", key);
    h.update(Buffer.from(String(tag), "utf8"));
    return b64url(h.digest());
}

// Build the header-comment block. Slot it at the very top of the file
// so the obfuscator treats it as the file's leading comment.
function buildHeader(tag, key) {
    const tagB = b64url(Buffer.from(String(tag), "utf8"));
    const sigB = signTag(tag, key);
    return "/*! " + MARKER + "\n"
         + " * tag: " + tagB + "\n"
         + " * sig: " + sigB + "\n"
         + " */\n";
}

// Inject the header at the start of source. If the file begins with
// `"use strict"` directive it stays at line 1 (V8 only honors it when
// it's the literal first statement); we put the comment ABOVE it,
// which is still semantically valid because comments don't break the
// directive prologue.
function injectInto(source, tag, key) {
    return buildHeader(tag, key) + (source || "");
}

// Scan protected output for the watermark marker. Returns
// { present, tag, sig, valid } where:
//   present: true iff the marker block was found
//   tag:     plaintext tag (already base64url-decoded back to a string)
//   sig:     the embedded base64url signature
//   valid:   true iff HMAC(tag, key) matches sig (constant-time)
//   error:   set when the file lacks a marker or the parse fails
function verify(protectedSource, key) {
    const src = String(protectedSource || "");
    const m = MARKER_RE.exec(src);
    if (!m) {
        return { present: false, valid: false, error: "watermark: marker not found in input" };
    }
    const tagB64 = m[1];
    const sigB64 = m[2];
    let tag;
    try { tag = b64urlDecode(tagB64).toString("utf8"); }
    catch (e) { return { present: true, valid: false, error: "watermark: tag is not valid base64url" }; }

    if (!key) {
        // Lookup-only mode: caller just wants to read the embedded tag.
        return { present: true, tag: tag, sig: sigB64, valid: false };
    }
    const expected = signTag(tag, key);
    // Constant-time compare to defeat timing attacks against a verifier
    // that's exposed publicly (e.g. webhook that checks if an uploaded
    // artifact is "ours").
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(sigB64, "utf8");
    const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
    return { present: true, tag: tag, sig: sigB64, valid: valid };
}

module.exports = {
    MARKER,
    MARKER_RE,
    signTag,
    buildHeader,
    injectInto,
    verify,
};
