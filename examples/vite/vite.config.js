const jsoProtector = require("jso-protector/vite");

module.exports = {
  build: {
    outDir: "dist",
    sourcemap: true
  },
  plugins: [
    jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["**/vendor/**", "**/polyfills-*.js"],
      manifest: "dist/jso-manifest.json",
      reservedNames: ["^PublicApi$"]
    })
  ]
};
