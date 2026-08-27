module.exports = ({ env }) => ({
  endpoint: env.JSO_ENDPOINT || "https://javascriptobfuscator.com/HttpApi.ashx",
  apiKey: "$JSO_API_KEY",
  apiPassword: "$JSO_API_PASSWORD",
  projectName: env.CI ? "browser-release-ci" : "browser-release-local",
  input: env.JSO_INPUT || "dist",
  output: env.JSO_OUTPUT || "dist-protected",
  preset: env.JSO_PRESET || "balanced",
  extensions: [".js", ".jsx"],
  exclude: ["**/*.map", "**/vendor/**", "**/*-obfuscated.js"],
  copyAssets: true,
  assetExclude: ["**/*.map"],
  parseHtml: false,
  honorConditionalComments: false,
  reservedNames: ["^PublicApi$", "^keep_"],
  manifest: "dist-protected/jso-manifest.json",
  maxGrowthRatio: 8,
  options: {
    OptimizationMode: "Web",
    LockDomain: Boolean(env.RELEASE_DOMAIN),
    LockDomainList: env.RELEASE_DOMAIN || ""
  }
});
