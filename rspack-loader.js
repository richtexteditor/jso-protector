"use strict";

const webpackLoader = require("./webpack-loader.js");

function jsoProtectorRspackLoader(source, sourceMap, meta) {
  return webpackLoader.call(this, source, sourceMap, meta);
}

module.exports = jsoProtectorRspackLoader;
module.exports.jsoProtectorRspackLoader = jsoProtectorRspackLoader;
module.exports.default = jsoProtectorRspackLoader;
