const JsoProtectorWebpackPlugin = require("jso-protector/webpack");

module.exports = {
  mode: "production",
  entry: "./src/app.js",
  output: {
    filename: "app.js",
    path: require("path").resolve(__dirname, "dist")
  },
  devtool: "source-map",
  plugins: [
    new JsoProtectorWebpackPlugin({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json",
      reservedNames: ["^PublicApi$"]
    })
  ]
};
