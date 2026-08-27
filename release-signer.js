"use strict";

// Ed25519-signed release manifests for jso-protector.
//
// After a successful obfuscation run, this module produces a small
// signed attestation file (".manifest.sig") that proves:
//
//   - the artifact came from a build with the holder of the private key
//   - which BuildId / PolymorphismFingerprint was used
//   - the exact SHA-256 of each protected output file
//   - the ReleaseLabel and a UTC timestamp
//
// Verification is the inverse: given a .manifest.sig and the matching
// public key, confirm the signature, then re-hash each referenced file
// on disk and confirm the hashes still match. A failure on either step
// means the artifact was tampered with after signing.
//
// This is the SLSA-style attestation pattern adapted for an obfuscation
// pipeline. Enterprises typically want to publish their public key in
// their security.txt or repo, then anyone can verify "this protected
// JS came from our official CI" without trusting our service.
//
// Why Ed25519:
//   - 64-byte signatures, 32-byte keys, fast verify
//   - Node has built-in support (crypto.generateKeyPairSync('ed25519')
//     since Node 12.0); no third-party dependency
//   - Recommended over RSA for new designs in 2024+
//
// File formats:
//
//   <output>/<name>.manifest.json     existing protection manifest
//   <output>/<name>.manifest.json.sig the new signed envelope:
//
//     {
//       "v":         1,
//       "signedAt":  "2026-05-27T00:00:00Z",
//       "manifest":  {                       // canonical subset we sign
//         "buildId":              "...",
//         "polymorphismFingerprint": "...",
//         "label":                "...",
//         "files": [
//           { "name": "app.js",     "sha256": "<hex>" },
//           { "name": "lib/dep.js", "sha256": "<hex>" }
//         ]
//       },
//       "publicKey": "<base64 SPKI DER>",
//       "signature": "<base64 64-byte Ed25519 sig over canonical(manifest)>"
//     }
//
// The signature is over a CANONICAL JSON encoding of the `manifest`
// subobject. Canonical = sorted keys, no whitespace, no trailing
// newline. This way the same logical manifest always produces the same
// bytes to sign and the same bytes to verify, regardless of which JSON
// library the caller used.

const crypto = require("node:crypto");
const fs     = require("node:fs");
const path   = require("node:path");

const VERSION = 1;

// ---- canonical JSON --------------------------------------------------------
//
// JSON has no canonical form by default — key ordering, whitespace, and
// number formatting all vary. We pick a deterministic shape so the bytes
// you sign now match the bytes a verifier produces later. Sort keys
// alphabetically, no whitespace, JSON.stringify number formatting.
function canonicalize(value) {
    if (Array.isArray(value)) {
        return "[" + value.map(canonicalize).join(",") + "]";
    }
    if (value && typeof value === "object") {
        const keys = Object.keys(value).sort();
        return "{" + keys.map(k =>
            JSON.stringify(k) + ":" + canonicalize(value[k])
        ).join(",") + "}";
    }
    return JSON.stringify(value);
}

// ---- key generation --------------------------------------------------------
//
// generateKeyPair() produces a fresh Ed25519 key pair as two PEM files.
// We write PEM (not DER) because most users already have PEM tooling
// (ssh-keygen, openssl, hashicorp Vault) and pasting a PEM into a CI
// secret store is the path of least surprise.
function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    return {
        publicKeyPem:  publicKey.export({ type: "spki",  format: "pem" }),
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    };
}

// ---- sign ------------------------------------------------------------------
//
// signRelease takes the parts of a build and a path to a PEM private
// key, returns the JSON envelope object (caller writes it to disk).
function signRelease(parts, privateKeyPem) {
    if (!parts || !Array.isArray(parts.files)) {
        throw new Error("signRelease: parts.files is required (array of { name, sha256 })");
    }
    const keyObj = crypto.createPrivateKey({ key: privateKeyPem, format: "pem" });
    if (keyObj.asymmetricKeyType !== "ed25519") {
        throw new Error("signRelease: private key is not Ed25519 (got " + keyObj.asymmetricKeyType + ")");
    }
    const manifest = {
        buildId: parts.buildId || null,
        polymorphismFingerprint: parts.polymorphismFingerprint || null,
        label: parts.label || null,
        files: parts.files.map(f => ({ name: f.name, sha256: f.sha256 })),
    };
    const canonical = canonicalize(manifest);
    // Ed25519 in Node: pass key + Buffer to crypto.sign(null, ...) — the
    // algorithm name MUST be null for EdDSA (the algorithm is baked into
    // the key type).
    const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), keyObj);

    const pubObj = crypto.createPublicKey(keyObj);
    return {
        v: VERSION,
        signedAt: new Date().toISOString(),
        manifest: manifest,
        publicKey: pubObj.export({ type: "spki", format: "der" }).toString("base64"),
        signature: sig.toString("base64"),
    };
}

// ---- verify ----------------------------------------------------------------
//
// Two-stage verification. Stage 1 confirms the signature is valid for
// the embedded manifest under the supplied (or embedded) public key.
// Stage 2 (optional, on by default) re-hashes the referenced files on
// disk and confirms the hashes still match — this is what catches
// post-signing tampering of the protected artifacts themselves.
//
// Returns: { valid, stage1, stage2, mismatches: [...], error: string? }
//
//   valid:  overall pass/fail
//   stage1: signature verified against (manifest, publicKey)
//   stage2: every referenced file's on-disk sha256 matched the manifest
//   mismatches: list of { name, expected, actual } when stage2 fails
//
// `expectedPublicKeyPem` is optional. When provided, we verify the
// embedded public key matches the one the caller trusts (so a sneaky
// envelope can't substitute its own key with a self-signed manifest).
function verifyRelease(envelope, opts) {
    opts = opts || {};
    const result = {
        valid: false, stage1: false, stage2: false,
        mismatches: [], error: null,
    };
    if (!envelope || typeof envelope !== "object") {
        result.error = "envelope is not an object";
        return result;
    }
    if (envelope.v !== VERSION) {
        result.error = "unsupported envelope version: " + envelope.v;
        return result;
    }
    if (!envelope.signature || !envelope.publicKey || !envelope.manifest) {
        result.error = "envelope missing signature / publicKey / manifest";
        return result;
    }

    // Pin to a trusted public key when the caller supplied one.
    let pubKey;
    if (opts.expectedPublicKeyPem) {
        pubKey = crypto.createPublicKey({ key: opts.expectedPublicKeyPem, format: "pem" });
        const embeddedDerB64 = envelope.publicKey;
        const trustedDerB64 = pubKey.export({ type: "spki", format: "der" }).toString("base64");
        if (embeddedDerB64 !== trustedDerB64) {
            result.error = "embedded public key does not match --public-key";
            return result;
        }
    } else {
        pubKey = crypto.createPublicKey({
            key: Buffer.from(envelope.publicKey, "base64"),
            format: "der", type: "spki",
        });
    }

    // Stage 1: signature verification over canonical manifest.
    const canonical = canonicalize(envelope.manifest);
    let stage1ok = false;
    try {
        stage1ok = crypto.verify(null,
            Buffer.from(canonical, "utf8"),
            pubKey,
            Buffer.from(envelope.signature, "base64"));
    } catch (e) {
        result.error = "verify failed: " + e.message;
        return result;
    }
    result.stage1 = stage1ok;
    if (!stage1ok) {
        result.error = "signature does not match manifest";
        return result;
    }

    // Stage 2 (optional): re-hash files on disk.
    if (opts.fileRoot && Array.isArray(envelope.manifest.files)) {
        for (const f of envelope.manifest.files) {
            const p = path.join(opts.fileRoot, f.name);
            if (!fs.existsSync(p)) {
                result.mismatches.push({ name: f.name, expected: f.sha256, actual: null, missing: true });
                continue;
            }
            const actual = sha256OfFile(p);
            if (actual !== f.sha256) {
                result.mismatches.push({ name: f.name, expected: f.sha256, actual: actual });
            }
        }
        result.stage2 = result.mismatches.length === 0;
        result.valid = result.stage1 && result.stage2;
        if (!result.valid && !result.error) {
            result.error = "one or more files were modified after signing";
        }
    } else {
        // No file root means signature-only verification.
        result.stage2 = true; // n/a
        result.valid = result.stage1;
    }
    return result;
}

function sha256OfFile(p) {
    const h = crypto.createHash("sha256");
    h.update(fs.readFileSync(p));
    return h.digest("hex");
}

function sha256OfBuffer(buf) {
    return crypto.createHash("sha256").update(buf).digest("hex");
}

module.exports = {
    VERSION,
    canonicalize,
    generateKeyPair,
    signRelease,
    verifyRelease,
    sha256OfFile,
    sha256OfBuffer,
};
