# React Native + JSO playbook (2026 refresh)

A walkthrough for layering jso-protector on top of a React Native build,
plus the device-attestation moves you should make in parallel. Targets
React Native 0.74+ with the new architecture and Hermes enabled.

## Why this is two problems

You're defending TWO surfaces simultaneously:

1. **The JS bundle** that Metro emits and Hermes byte-codes. JSO
   obfuscates this before Hermes ever sees it.
2. **The native shell** (the .ipa / .aab) that hosts the JS engine.
   Even perfect JS obfuscation doesn't help if the device itself is
   rooted / on an emulator / running on Frida. That's where device
   attestation (Play Integrity on Android, App Attest + DeviceCheck
   on iOS) comes in.

JSO covers (1) end-to-end. You wire (2) yourself; this doc tells you
what's current as of June 2026.

## The pipeline

```
src/*.{js,ts,jsx,tsx}
    |   Metro + jso-protector/metro serializer
    v
.build/bundle.js                <-- obfuscated, watermarked,
    |                                 release-signed
    |   Hermes compiler (release builds)
    v
.build/bundle.hbc               <-- Hermes bytecode shipped to device
```

Three layers stacked: source obfuscation -> Hermes bytecode -> native
container -> device attestation.

## Step 1 - JSO via the Metro serializer

`jso-protector/metro` plugs into Metro's `serializer.customSerializer`.
The serializer intercepts the bundle on its way to Hermes, sends it to
the JSO HTTP API, and replaces the bundle's `code` with the protected
output before Hermes byte-codes it.

`metro.config.js`:

```js
const { mergeConfig, getDefaultConfig } = require("@react-native/metro-config");
const { createMetroSerializer } = require("jso-protector/metro");

const defaultConfig = getDefaultConfig(__dirname);
module.exports = mergeConfig(defaultConfig, {
  serializer: {
    customSerializer: createMetroSerializer({
      apiKey:      process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset:      "maximum",
      watermark:   `${process.env.npm_package_name}@${process.env.npm_package_version}`,
      watermarkKey: process.env.JSO_WATERMARK_KEY,
      // Named sets work here too -- escalate checkout / wallet bundles:
      namedSets: {
        wallet: { match: ["src/wallet/**", "src/checkout/**"], preset: "maximum",
                  countermeasures: { onTamper: ["break", "deleteCookies"] } },
      },
    }),
  },
});
```

Validate locally with `npx jso-protector ai compat-scan` BEFORE shipping. The
compat scanner flags obfuscation pitfalls (eval, Function constructor,
hot-loaded modules) the bundle is using.

## Step 2 - Hermes bytecode

Hermes is on by default in modern React Native. The bytecode `.hbc`
file is what ships to the device; the JS source never does. No JSO
config needed for this layer - just don't disable Hermes.

Verify after a release build:

```sh
unzip -l app-release.aab | grep '\.hbc$'   # should NOT see .js
```

If you see `.js` files in the AAB, Hermes is disabled. Re-enable it
in `android/app/build.gradle`:

```
hermesEnabled = true
```

## Step 3 - Device attestation (REPLACE SafetyNet)

**Read this section even if you've shipped before.** SafetyNet
Attestation was deprecated on **June 30, 2024** and the API was
permanently shut down. Any blog post older than that is referencing
a dead API.

### Android: Play Integrity API

You want **Play Integrity API** (com.google.android.play.integrity).
The token tells you three things:

| Field | Tells you |
|---|---|
| `deviceIntegrity` | Whether the device passes Google's basic / standard / strong integrity bars (no root, no Frida, no emulator) |
| `appIntegrity` | Whether the running APK is the same one Google distributed (catches sideloads + repackages) |
| `accountDetails` | Whether the device's Play account is licensed for your app |

Wiring (native module on Android side):

```kotlin
val standardIntegrityManager =
    IntegrityManagerFactory.createStandard(applicationContext)
val tokenProvider = standardIntegrityManager.prepareIntegrityToken(
    PrepareIntegrityTokenRequest.builder()
        .setCloudProjectNumber(YOUR_CLOUD_PROJECT_NUMBER)
        .build()
).await()

val integrityToken = tokenProvider.request(
    StandardIntegrityTokenRequest.builder()
        .setRequestHash(payloadHash)
        .build()
).await().token()
```

Send `integrityToken` to your server. Validate it via Google's
`playintegrity.googleapis.com/v1/.../decodeIntegrityToken`. Reject the
session if `deviceIntegrity.deviceRecognitionVerdict` is empty or
`appIntegrity.appRecognitionVerdict != PLAY_RECOGNIZED`.

### iOS: App Attest + DeviceCheck

`DCAppAttestService` is now the iOS equivalent. Per-install you do:

```swift
let service = DCAppAttestService.shared
guard service.isSupported else { return }
service.generateKey { keyId, error in
    service.attestKey(keyId!, clientDataHash: payloadHash) { attestation, error in
        // POST { keyId, attestation, deviceIdentifier } to your backend
    }
}
```

The server forwards the attestation to Apple's
`https://data.appattest.apple.com/v1/attestationData` (production) or
`development` host (for sandbox). The response confirms the request
came from a real, un-jailbroken iOS device running your app.

`DeviceCheck` (the older `DCDevice` API) is still supported for
non-attestation use cases (one-bit-per-device state). Use it as a
secondary signal, not the primary defense.

### What attestation does NOT cover

- It can't prove the user isn't running a clean device with a tampered
  JS bundle - that's what JSO + Hermes + signed release manifests
  cover. Layer both.
- Token validation must run server-side. A client that says
  "I'm trustworthy" is not.

## Step 4 - Release attestation

`jso-protector --sign-release` writes an Ed25519-signed manifest of
the protected bundle alongside the .hbc. Ship it with the app (in
`assets/`) so an in-app verifier can confirm the bundle hasn't been
swapped post-deploy:

```sh
jso-protector --sign-release release-key.pem \
              --manifest .build/bundle.manifest.json \
              --label "rn-${npm_package_version}"
```

Pair with a periodic in-app re-check that posts to your beacon URL.
The jso-beacon-slack adapters forward beacons to Splunk / Elastic /
generic-webhook SIEM downstream.

## Field-tested gotchas

- **Reanimated worklets**: they evaluate via `Function()`-equivalents
  on the UI thread. Mark them with the `// jso:protect-disable` comment
  or list them in `exclude:` so JSO leaves them alone.
- **Native-module bridge**: function names that JS uses to call
  native modules must NOT be mangled. Add them to `VariableExclusion`.
  Examples: `NativeModules.WalletKit.*`, all of `NativeRouter`.
- **Hot-reload in development**: don't run JSO in dev. Gate the
  Metro serializer on `process.env.NODE_ENV === "production"`.
- **Source maps for symbolication**: keep them - just don't ship
  them. Upload to your symbolication endpoint (Sentry / Bugsnag /
  Rollbar) as part of the release step.

## What's still on the roadmap

- A first-party `@react-native-jso/integrity` JS module that wraps
  Play Integrity + DCAppAttest with one promise-based API. Until
  it ships you need to write the native bindings yourself (snippets
  above). Tracking: jso-protector-electron ROADMAP.

## Refs

- Google Play Integrity API: https://developer.android.com/google/play/integrity
- Apple DCAppAttestService:    https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
- Hermes bytecode:             https://reactnative.dev/docs/hermes
- jso-protector Metro adapter: ./metro.config.js
