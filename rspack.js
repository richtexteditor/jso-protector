"use strict";

const WebpackProtector = require("./webpack.js");

class JsoProtectorRspackPlugin extends WebpackProtector {}

module.exports = JsoProtectorRspackPlugin;
module.exports.JsoProtectorRspackPlugin = JsoProtectorRspackPlugin;
module.exports.default = JsoProtectorRspackPlugin;
