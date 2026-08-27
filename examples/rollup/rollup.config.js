const jsoProtector = require("jso-protector/rollup");

module.exports = {
  input: "src/app.js",
  output: {
    dir: "dist",
    format: "iife",
    sourcemap: true
  },
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      include: ["app.js"],
      manifest: "dist/jso-manifest.json",
      reservedNames: ["^PublicApi$"]
    })
  ]
};
