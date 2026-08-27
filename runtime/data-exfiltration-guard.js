"use strict";

// Browser-side protected-field egress control. Values are inspected in memory
// only; snapshots contain field names/counts, never field values or bodies.

const SCHEMA_VERSION = 1;
const MAX_EVENTS = 500;
const DEFAULT_SELECTORS = Object.freeze([
  "input[type=password]", "input[autocomplete=current-password]",
  "input[autocomplete=new-password]", "input[autocomplete=cc-number]",
  "input[autocomplete=cc-csc]", "input[autocomplete=cc-exp]"
]);

function normalizeOrigin(value, base) {
  try {
    const url = new URL(String(value), base || undefined);
    if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol)) return null;
    return url.origin.replace(/^ws/, "http");
  } catch (_) { return null; }
}

function createPolicy(input) {
  input = input || {};
  const mode = String(input.mode || "monitor").toLowerCase();
  if (mode !== "monitor" && mode !== "block") throw new Error("data-exfiltration-guard: mode must be monitor or block");
  const pageOrigin = input.pageOrigin ? normalizeOrigin(input.pageOrigin) : null;
  const allowed = (input.allowedOrigins || []).map((v) => normalizeOrigin(v, pageOrigin || undefined)).filter(Boolean);
  if (input.allowSameOrigin !== false && pageOrigin) allowed.push(pageOrigin);
  return Object.freeze({
    id: String(input.id || "default"), version: String(input.version || "1"), mode,
    pageOrigin, allowedOrigins: Object.freeze(Array.from(new Set(allowed)).sort()),
    protectedSelectors: Object.freeze((input.protectedSelectors || DEFAULT_SELECTORS).map(String)),
    protectedFieldNames: Object.freeze(Array.from(new Set((input.protectedFieldNames || []).map(String).filter(Boolean)))),
    allowSameOrigin: input.allowSameOrigin !== false
  });
}

function createGuard(input) {
  const policy = input && input.allowedOrigins && Object.isFrozen(input) ? input : createPolicy(input);
  const events = [];
  let sequence = 0;
  function inspect(row) {
    row = row || {};
    const destinationOrigin = normalizeOrigin(row.url, policy.pageOrigin || undefined);
    const names = Array.from(new Set((row.protectedFieldNames || []).map(String).filter(Boolean))).sort();
    const valueCount = Math.max(0, Number(row.protectedValueCount) || 0);
    const containsProtectedData = names.length > 0 || valueCount > 0 || row.protectedForm === true;
    const allowed = !!destinationOrigin && policy.allowedOrigins.includes(destinationOrigin);
    if (!containsProtectedData || allowed) return { acted: false, blocked: false, allowed, destinationOrigin };
    if (events.length >= MAX_EVENTS) return { acted: false, blocked: false, dropped: true, allowed, destinationOrigin };
    const blocked = policy.mode === "block";
    const event = Object.freeze({
      seq: ++sequence, reason: destinationOrigin ? "protected-data-to-unapproved-origin" : "protected-data-to-invalid-destination",
      transport: String(row.transport || "unknown"), method: row.method ? String(row.method) : null,
      destinationOrigin, protectedFieldNames: Object.freeze(names), protectedFieldCount: names.length,
      protectedValueCount: valueCount, protectedForm: row.protectedForm === true, blocked,
      observedAt: row.observedAt || new Date().toISOString()
    });
    events.push(event);
    return { acted: true, blocked, allowed: false, destinationOrigin, event };
  }
  return {
    policy, inspect, events: () => events.slice(),
    reset: () => { events.length = 0; sequence = 0; },
    snapshot: () => ({ v: SCHEMA_VERSION, kind: "protected-data-egress", policyId: policy.id, policyVersion: policy.version, mode: policy.mode, events: events.slice() })
  };
}

function attach(win, input) {
  if (!win || !win.document) throw new Error("data-exfiltration-guard.attach: browser window required");
  if (win.__jsoDataExfiltrationGuard) return win.__jsoDataExfiltrationGuard;
  input = Object.assign({}, input || {});
  if (!input.pageOrigin && win.location) input.pageOrigin = win.location.origin;
  const guard = createGuard(input);
  function fields() {
    const result = [];
    for (const selector of guard.policy.protectedSelectors) {
      let nodes = [];
      try { nodes = win.document.querySelectorAll(selector); } catch (_) {}
      for (let i = 0; i < nodes.length; i++) if (!result.includes(nodes[i])) result.push(nodes[i]);
    }
    if (guard.policy.protectedFieldNames.length) {
      let nodes = [];
      try { nodes = win.document.querySelectorAll("input[name],textarea[name],select[name]"); } catch (_) {}
      for (let i = 0; i < nodes.length; i++) if (guard.policy.protectedFieldNames.includes(nodes[i].name) && !result.includes(nodes[i])) result.push(nodes[i]);
    }
    return result;
  }
  function bodyText(body) {
    if (typeof body === "string") return body;
    if (win.URLSearchParams && body instanceof win.URLSearchParams) return body.toString();
    return null;
  }
  function inspectBody(transport, method, url, body, form) {
    const names = []; let valueCount = 0; const text = bodyText(body);
    for (const field of fields()) {
      const name = String(field.name || field.id || "protected-field");
      const value = field.value == null ? "" : String(field.value);
      let matched = !!form && field.form === form;
      if (win.FormData && body instanceof win.FormData && field.name) { try { matched = body.has(field.name); } catch (_) {} }
      if (text && ((field.name && (text.includes(encodeURIComponent(field.name) + "=") || text.includes('"' + field.name + '"'))) || (value.length >= 3 && text.includes(value)))) matched = true;
      if (matched) { names.push(name); if (value.length >= 3 && text && text.includes(value)) valueCount++; }
    }
    return guard.inspect({ transport, method, url, protectedFieldNames: names, protectedValueCount: valueCount, protectedForm: !!form && names.length > 0 });
  }
  const originals = {};
  if (typeof win.fetch === "function") {
    originals.fetch = win.fetch.bind(win);
    win.fetch = function (request, init) {
      const url = typeof request === "string" ? request : request && request.url;
      const verdict = inspectBody("fetch", (init && init.method) || "GET", url, init && init.body, null);
      if (verdict.blocked) return Promise.resolve(new win.Response(JSON.stringify({ ok: false, error: "protected_data_egress_blocked" }), { status: 451, headers: { "Content-Type": "application/json" } }));
      return originals.fetch(request, init);
    };
  }
  if (typeof win.XMLHttpRequest === "function") {
    originals.XMLHttpRequest = win.XMLHttpRequest;
    const OriginalXHR = win.XMLHttpRequest;
    function GuardedXHR() {
      const xhr = new OriginalXHR(); let url = "", method = "GET";
      const open = xhr.open; const send = xhr.send;
      xhr.open = function (m, u) { method = m; url = u; return open.apply(xhr, arguments); };
      xhr.send = function (body) { const verdict = inspectBody("xhr", method, url, body, null); if (verdict.blocked) { try { xhr.abort(); } catch (_) {} return; } return send.apply(xhr, arguments); };
      return xhr;
    }
    try { GuardedXHR.prototype = OriginalXHR.prototype; } catch (_) {}
    win.XMLHttpRequest = GuardedXHR;
  }
  if (win.navigator && typeof win.navigator.sendBeacon === "function") {
    originals.sendBeacon = win.navigator.sendBeacon.bind(win.navigator);
    win.navigator.sendBeacon = function (url, body) { const verdict = inspectBody("beacon", "POST", url, body, null); return verdict.blocked ? false : originals.sendBeacon(url, body); };
  }
  if (typeof win.WebSocket === "function") {
    originals.WebSocket = win.WebSocket;
    const OriginalWebSocket = win.WebSocket;
    function GuardedWebSocket(url, protocols) { const socket = new OriginalWebSocket(url, protocols); const send = socket.send; socket.send = function (body) { const verdict = inspectBody("websocket", "WS", url, body, null); if (verdict.blocked) throw new Error("protected_data_egress_blocked"); return send.apply(socket, arguments); }; return socket; }
    try { GuardedWebSocket.prototype = OriginalWebSocket.prototype; } catch (_) {}
    win.WebSocket = GuardedWebSocket;
  }
  if (win.HTMLFormElement && win.HTMLFormElement.prototype) {
    for (const methodName of ["submit", "requestSubmit"]) {
      const original = win.HTMLFormElement.prototype[methodName];
      if (typeof original !== "function") continue;
      originals[methodName] = original;
      win.HTMLFormElement.prototype[methodName] = function () { const verdict = inspectBody("form", String(this.method || "GET").toUpperCase(), this.action || (win.location && win.location.href), null, this); if (verdict.blocked) throw new Error("protected_data_egress_blocked"); return original.apply(this, arguments); };
    }
  }
  guard.detach = function () {
    if (originals.fetch) win.fetch = originals.fetch;
    if (originals.XMLHttpRequest) win.XMLHttpRequest = originals.XMLHttpRequest;
    if (originals.sendBeacon) win.navigator.sendBeacon = originals.sendBeacon;
    if (originals.WebSocket) win.WebSocket = originals.WebSocket;
    if (originals.submit) win.HTMLFormElement.prototype.submit = originals.submit;
    if (originals.requestSubmit) win.HTMLFormElement.prototype.requestSubmit = originals.requestSubmit;
    delete win.__jsoDataExfiltrationGuard;
  };
  win.__jsoDataExfiltrationGuard = guard;
  return guard;
}

module.exports = { SCHEMA_VERSION, DEFAULT_SELECTORS, createPolicy, createGuard, attach };
