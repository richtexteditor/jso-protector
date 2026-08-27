"use strict";

module.exports = {
  mode: "production",
  module: {
    rules: [{
      test: /\.js$/,
      include: /src/,
      use: [{
        loader: "jso-protector/webpack-loader",
        options: {
          apiKey: process.env.JSO_API_KEY,
          apiPassword: process.env.JSO_API_PASSWORD,
          preset: "balanced",
          include: ["src/*.js"],
          reservedNames: ["^PublicApi$"],
          maxGrowthRatio: 8
        }
      }]
    }]
  }
};
