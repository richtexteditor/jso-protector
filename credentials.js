"use strict";

// User-level credential store for the CLI.
//
// Before this existed, credentials could only come from environment variables
// or a project-local jso.config.json. That meant a first-time user had to find
// the dashboard, copy two values, work out two platform-specific env var names,
// and set them again in every new shell. Measured against the competitor, whose
// package needs no account at all, that was the widest part of the gap we can
// actually close without changing the API's paid-only contract.
//
// The file is per-user and outside any project directory, so it is never
// committed by accident. It is written 0600, which is real protection on POSIX.
// On Windows the mode bits are not honoured - MEASURED, the file reports 666 -
// so there the secret is only as protected as the user profile directory's ACL.
// That is the same protection npm gives ~/.npmrc, and it is worth knowing rather
// than assuming the chmod did something.

const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline");
const { spawn } = require("child_process");

// ?src= is attribution, not decoration: a signup that starts at `login` is
// otherwise indistinguishable from a web signup, and the CLI is the entry
// point whose value we are trying to measure. register.aspx carries plan/src/deal
// forward from the referrer, so the tag survives the sign-in hop.
const DASHBOARD_URL = "https://javascriptobfuscator.com/dashboard/APIKeys.aspx?src=cli-login";
const STORE_DIR = path.join(os.homedir() || ".", ".jso-protector");
const STORE_FILE = path.join(STORE_DIR, "credentials.json");

function storePath() { return STORE_FILE; }

function readStored() {
  try {
    const raw = fs.readFileSync(STORE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const apiKey = typeof parsed.apiKey === "string" ? parsed.apiKey : "";
    const apiPassword = typeof parsed.apiPassword === "string" ? parsed.apiPassword : "";
    if (!apiKey || !apiPassword) return null;
    return { apiKey, apiPassword, endpoint: typeof parsed.endpoint === "string" ? parsed.endpoint : "" };
  } catch (err) {
    // A missing store is the normal case, not an error. A corrupt one must not
    // take down a build that has working credentials in the environment.
    return null;
  }
}

function writeStored(apiKey, apiPassword, endpoint) {
  fs.mkdirSync(STORE_DIR, { recursive: true, mode: 0o700 });
  const body = { apiKey, apiPassword };
  if (endpoint) body.endpoint = endpoint;
  // Write with the restrictive mode from the start rather than chmod-ing after,
  // so the secret is never briefly world-readable.
  fs.writeFileSync(STORE_FILE, JSON.stringify(body, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  // No-op on Windows, which does not honour POSIX modes; see the header note.
  try { fs.chmodSync(STORE_FILE, 0o600); } catch (err) { /* best effort */ }
  return STORE_FILE;
}

function clearStored() {
  try { fs.unlinkSync(STORE_FILE); return true; }
  catch (err) { return false; }
}

// A dashboard value is base64. Catching an obviously wrong paste here turns a
// confusing failure at protect time into an immediate, specific message.
function looksLikeDashboardValue(value) {
  return typeof value === "string" && value.length >= 8 && /^[A-Za-z0-9+/=_-]+$/.test(value.trim());
}

function openBrowser(url) {
  const cmd = process.platform === "win32" ? "cmd" : (process.platform === "darwin" ? "open" : "xdg-open");
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
    return true;
  } catch (err) {
    return false;
  }
}

function ask(rl, question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    if (!hidden) { rl.question(question, (answer) => resolve(answer.trim())); return; }
    // Mute the echo so a pasted secret does not stay on screen or in a shared
    // terminal recording.
    const output = rl.output;
    let muted = false;
    const onData = (chunk) => { if (muted) return; };
    output.write(question);
    muted = true;
    const origWrite = output.write.bind(output);
    output.write = (chunk, ...rest) => { if (muted && typeof chunk === "string" && chunk !== "\n" && chunk !== "\r\n") return true; return origWrite(chunk, ...rest); };
    rl.question("", (answer) => {
      muted = false;
      output.write = origWrite;
      output.write("\n");
      resolve(answer.trim());
    });
    void onData;
  });
}

async function login(argv = []) {
  const noBrowser = argv.includes("--no-browser");
  const out = process.stdout;

  out.write("Sign in to javascriptobfuscator.com and copy your API credentials.\n\n");
  out.write("  " + DASHBOARD_URL + "\n\n");
  if (!noBrowser) {
    if (openBrowser(DASHBOARD_URL)) out.write("Opened that page in your browser.\n");
    else out.write("Could not open a browser automatically - use the link above.\n");
  }
  out.write("The dashboard shows an API Key and an API Password. Both are already\n");
  out.write("base64 encoded; paste them exactly as shown.\n\n");

  if (!process.stdin.isTTY) {
    out.write("No interactive terminal. Set JSO_API_KEY and JSO_API_PASSWORD instead,\n");
    out.write("or run this command in a terminal.\n");
    return 1;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  try {
    const apiKey = await ask(rl, "API Key: ");
    const apiPassword = await ask(rl, "API Password: ", { hidden: true });

    if (!apiKey || !apiPassword) {
      out.write("\nBoth values are required. Nothing was saved.\n");
      return 1;
    }
    if (!looksLikeDashboardValue(apiKey) || !looksLikeDashboardValue(apiPassword)) {
      out.write("\nThat does not look like a dashboard value. They are base64 strings -\n");
      out.write("check you copied the value and not the label. Nothing was saved.\n");
      return 1;
    }

    const file = writeStored(apiKey, apiPassword, "");
    out.write("\nSaved to " + file + "\n");
    out.write("Every project on this machine now uses these credentials.\n");
    out.write("Run `javascriptobfuscator --input dist --output dist-protected` to protect a build.\n");
    out.write("Run `javascriptobfuscator logout` to remove them.\n");
    return 0;
  } finally {
    rl.close();
  }
}

function logout() {
  const removed = clearStored();
  process.stdout.write(removed
    ? "Removed " + STORE_FILE + "\n"
    : "No stored credentials at " + STORE_FILE + "\n");
  return 0;
}

module.exports = { login, logout, readStored, writeStored, clearStored, storePath, looksLikeDashboardValue, DASHBOARD_URL };
