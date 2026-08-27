const { getDefaultConfig, mergeConfig } = require("@react-native/metro-config");
const { withJsoProtectorMetro } = require("jso-protector/metro");

const baseConfig = getDefaultConfig(__dirname);

module.exports = withJsoProtectorMetro(mergeConfig(baseConfig, {}), {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced",
  include: ["index.android.release.bundle.js", "index.ios.release.bundle.js"]
});
