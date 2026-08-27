"use strict";

const fs = require("fs");
const path = require("path");

const dist = path.join(__dirname, "..", "dist");
fs.mkdirSync(dist, { recursive: true });
fs.writeFileSync(path.join(dist, "app.js"), "window.PublicApi = { renderWidget(){ console.log('release'); } };\n", "utf8");
fs.writeFileSync(path.join(dist, "index.html"), "<script src=\"app.js\"></script>\n", "utf8");
console.log("built dist/");
