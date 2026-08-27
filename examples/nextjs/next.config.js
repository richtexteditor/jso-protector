const withJsoProtector = require("jso-protector/next");

module.exports = withJsoProtector({
  reactStrictMode: true
}, {
  apiKey: process.env.JSO_API_KEY,
  apiPassword: process.env.JSO_API_PASSWORD,
  preset: "balanced",
  exclude: ["static/chunks/webpack*.js"],
  manifest: ".next/jso-manifest.json"
});
