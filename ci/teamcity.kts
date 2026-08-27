// TeamCity Kotlin DSL template for jso-protector.
//
// Drop this at .teamcity/settings.kts in your repo and enable
// Versioned Settings �?Kotlin DSL in your TeamCity project. Add JSO_API_KEY
// and JSO_API_PASSWORD as project-level parameters with the password type
// so they're masked in logs.
//
// Every protection run is tagged with %build.vcs.number% via --label and
// the API report is published as a build artifact for later symbolication.

import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script

version = "2024.03"

project {
    buildType(ProtectedRelease)
}

object ProtectedRelease : BuildType({
    name = "Protected release"
    description = "Protect built JavaScript with JavaScript Obfuscator and archive the API report for later symbolication."

    vcs {
        // Wire your VCS root here.
    }

    artifactRules = """
        dist-protected/** => dist-protected
        dist-protected/jso-report.json => jso-report.json
    """.trimIndent()

    params {
        // Override these as Project-level password parameters in the TeamCity UI.
        password("env.JSO_API_KEY", "")
        password("env.JSO_API_PASSWORD", "")
    }

    steps {
        script {
            name = "Install"
            scriptContent = "npm ci"
        }
        script {
            name = "Build"
            scriptContent = "npm run build"
        }
        script {
            name = "Release preflight"
            scriptContent = "npx jso-protector --config jso.config.json --release-check --json"
        }
        script {
            name = "Protect JavaScript"
            // %build.vcs.number% expands to the current commit SHA.
            scriptContent = """
                npx jso-protector \
                  --config jso.config.json \
                  --label "%build.vcs.number%" \
                  --manifest dist-protected/jso-manifest.json \
                  --report dist-protected/jso-report.json
                  # Optional: migration and supply-chain checks. Copy into a preflight/protect step as needed.
                  # Configure JSO_WATERMARK_KEY as a masked secret; check in ci-key.pub.pem,
                  # store ci-key.priv.pem in a CI file secret. See WireFormat.aspx#watermark.
                  #   npx jso-protector --config jso.config.json --competitor-gap-report --json  # competitor migration gap report
                  #   npx jso-protector --source-map-evidence dist-protected/jso-manifest.json --source-map-evidence-output reports/source-map-evidence.json --json  # source-map absence evidence
                  #   npx jso-protector --script-inventory-audit reports/payment-script-inventory.json --runtime-inventory-snapshot reports/runtime-inventory.json --script-inventory-audit-output reports/payment-script-inventory-audit.json --json  # payment-page script drift gate
                  #   npx jso-protector --payment-page-headers-from-har reports/checkout.har --payment-page-headers-baseline reports/payment-page-headers.baseline.json --payment-page-headers-output reports/payment-page-headers.json --payment-page-url-pattern "checkout|payment|wallet" --json  # payment-page security-header evidence
                  #   --ai-precheck --ai-precheck-fail-on error      // AI compat scan gate
                  #   --estimate                                     // pre-flight quota gate
                  #   --watermark "$COMMIT_SHA"                      // HMAC marker (needs JSO_WATERMARK_KEY env)
                  #   --sign-release ci-key.priv.pem                 // Ed25519 attestation -> .manifest.json.sig
                  #   --local                                        // protect on the runner, no source upload (Windows agents only)
            """.trimIndent()
        }
        script {
            name = "Smoke"
            scriptContent = "npm run smoke --if-present"
        }
    }
})
