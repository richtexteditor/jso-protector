"use strict";

const browserify = require("browserify");
const fs = require("fs");
const jsoProtector = require("jso-protector/browserify");

browserify("src/app.js", {
  transform: [[jsoProtector, {
    apiKey: process.env.JSO_API_KEY,
    apiPassword: process.env.JSO_API_PASSWORD,
    input: "src",
    preset: "balanced",
    include: ["**/*.js"],
    reservedNames: ["^PublicApi$"],
    manifest: "dist/jso-manifest.json",
    maxGrowthRatio: 8
  }]]
})
  .bundle()
  .pipe(fs.createWriteStream("dist/app.js"));
