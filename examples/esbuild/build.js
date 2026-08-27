const esbuild = require("esbuild");
const jsoProtector = require("jso-protector/esbuild");

esbuild.build({
  entryPoints: ["src/app.js"],
  bundle: true,
  outdir: "dist",
  sourcemap: true,
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json",
      reservedNames: ["^PublicApi$"]
    })
  ]
}).catch(() => process.exit(1));
