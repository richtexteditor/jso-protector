const JsoProtectorRspackPlugin = require("jso-protector/rspack");

module.exports = {
  plugins: [
    new JsoProtectorRspackPlugin({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["vendor.js"],
      manifest: "dist/jso-manifest.json"
    })
  ],
  module: {
    rules: [{
      test: /\.js$/,
      include: /src/,
      use: [{
        loader: "jso-protector/rspack-loader",
        options: {
          apiKey: process.env.JSO_API_KEY,
          apiPassword: process.env.JSO_API_PASSWORD,
          include: ["src/*.js"],
          reservedNames: ["^PublicApi$"]
        }
      }]
    }]
  }
};
