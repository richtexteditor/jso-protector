"use strict";

const { dest, src } = require("gulp");
const jsoProtector = require("jso-protector/gulp");

function protect() {
  return src(["dist/**/*.js", "dist/**/*.{css,html,png,svg}", "!dist/**/*.map"], { base: "dist" })
    .pipe(jsoProtector({
      apiKey: process.env.JSO_API_KEY,
      apiPassword: process.env.JSO_API_PASSWORD,
      preset: "balanced",
      exclude: ["**/vendor/**"],
      manifest: "dist-protected/jso-manifest.json",
      maxGrowthRatio: 8
    }))
    .pipe(dest("dist-protected"));
}

exports.protect = protect;
