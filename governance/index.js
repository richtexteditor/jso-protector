"use strict";

// Local enterprise-governance primitives for release automation. This module
// deliberately does not pretend to be an identity provider: SAML/OIDC login,
// SCIM provisioning, and server-side session enforcement belong in the hosted
// account service. It provides the shared RBAC, scoped-token, and tamper-evident
// audit contracts those surfaces can enforce consistently.

const crypto = require("crypto");

const ROLE_PERMISSIONS = Object.freeze({
  owner: ["protect", "view_evidence", "export_evidence", "manage_projects", "manage_members", "manage_tokens", "manage_billing", "view_audit"],
  admin: ["protect", "view_evidence", "export_evidence", "manage_projects", "manage_members", "manage_tokens", "view_audit"],
  developer: ["protect", "view_evidence", "export_evidence", "manage_projects"],
  reviewer: ["view_evidence", "export_evidence", "view_audit"],
  viewer: ["view_evidence"]
});

const TOKEN_SCOPES = Object.freeze(["protect", "evidence:read", "evidence:export", "projects:write", "audit:read"]);

function stableJson(value) {
  if (Array.isArray(value)) return "[" + value.map(stableJson).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + stableJson(value[key])).join(",") + "}";
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function normalizeMember(member) {
  if (!member || !member.id) throw new Error("governance: member id is required");
  const role = String(member.role || "viewer").toLowerCase();
  if (!ROLE_PERMISSIONS[role]) throw new Error("governance: unknown role '" + role + "'");
  return Object.freeze({ id: String(member.id), role, active: member.active !== false });
}

function createGovernancePolicy(config) {
  config = config || {};
  const members = new Map((config.members || []).map((member) => {
    const normalized = normalizeMember(member);
    return [normalized.id, normalized];
  }));

  function authorize(actorId, action) {
    const member = members.get(String(actorId || ""));
    if (!member || !member.active) return { allowed: false, reason: "inactive-or-unknown-member" };
    const allowed = ROLE_PERMISSIONS[member.role].includes(String(action));
    return { allowed, reason: allowed ? "role-allowed" : "role-denied", role: member.role };
  }

  return {
    authorize,
    describe: () => ({
      memberCount: members.size,
      roles: Array.from(new Set(Array.from(members.values()).map((member) => member.role))).sort(),
      permissions: ROLE_PERMISSIONS
    })
  };
}

function createTokenDescriptor(input) {
  input = input || {};
  if (!input.id || !input.createdBy) throw new Error("governance: token id and createdBy are required");
  const scopes = Array.from(new Set((input.scopes || []).map(String))).sort();
  for (const scope of scopes) {
    if (!TOKEN_SCOPES.includes(scope)) throw new Error("governance: unknown token scope '" + scope + "'");
  }
  const expiresAt = input.expiresAt ? new Date(input.expiresAt).toISOString() : null;
  return Object.freeze({
    id: String(input.id),
    name: String(input.name || input.id),
    createdBy: String(input.createdBy),
    scopes,
    expiresAt,
    revokedAt: input.revokedAt ? new Date(input.revokedAt).toISOString() : null
  });
}

function authorizeToken(token, scope, now) {
  if (!token || token.revokedAt) return { allowed: false, reason: "revoked-or-missing-token" };
  const clock = now ? new Date(now) : new Date();
  if (token.expiresAt && clock >= new Date(token.expiresAt)) return { allowed: false, reason: "expired-token" };
  const allowed = Array.isArray(token.scopes) && token.scopes.includes(String(scope));
  return { allowed, reason: allowed ? "scope-allowed" : "scope-denied" };
}

function createAuditTrail(config) {
  config = config || {};
  const organizationId = String(config.organizationId || "");
  if (!organizationId) throw new Error("governance: organizationId is required");
  const events = [];

  function append(event) {
    event = event || {};
    if (!event.actorId || !event.action) throw new Error("governance: audit actorId and action are required");
    const previousHash = events.length ? events[events.length - 1].hash : null;
    const row = {
      sequence: events.length + 1,
      organizationId,
      actorId: String(event.actorId),
      action: String(event.action),
      target: event.target == null ? null : String(event.target),
      outcome: String(event.outcome || "success"),
      occurredAt: new Date(event.occurredAt || Date.now()).toISOString(),
      metadata: event.metadata && typeof event.metadata === "object" ? event.metadata : {},
      previousHash
    };
    row.hash = sha256(stableJson(row));
    events.push(Object.freeze(row));
    return row;
  }

  function verify(rows) {
    rows = rows || events;
    let previousHash = null;
    for (let index = 0; index < rows.length; index++) {
      const row = rows[index];
      if (row.sequence !== index + 1 || row.previousHash !== previousHash) return false;
      const copy = Object.assign({}, row);
      delete copy.hash;
      if (sha256(stableJson(copy)) !== row.hash) return false;
      previousHash = row.hash;
    }
    return true;
  }

  return { append, verify, events: () => events.slice() };
}

function validateEnterpriseIdentityConfig(input) {
  input = input || {};
  const protocol = String(input.protocol || "").toLowerCase();
  if (protocol !== "oidc" && protocol !== "saml") throw new Error("governance: identity protocol must be oidc or saml");
  const domains = Array.from(new Set((input.domains || []).map((value) => String(value).trim().toLowerCase()).filter(Boolean)));
  if (!domains.length) throw new Error("governance: at least one verified sign-in domain is required");
  if (protocol === "oidc") {
    if (!/^https:\/\//i.test(String(input.issuer || ""))) throw new Error("governance: OIDC issuer must use https");
    if (!input.clientId) throw new Error("governance: OIDC clientId is required");
  } else {
    if (!/^https:\/\//i.test(String(input.ssoUrl || ""))) throw new Error("governance: SAML ssoUrl must use https");
    if (!input.entityId || !input.certificate) throw new Error("governance: SAML entityId and signing certificate are required");
  }
  return Object.freeze({
    protocol,
    domains: Object.freeze(domains),
    issuer: protocol === "oidc" ? String(input.issuer).replace(/\/+$/, "") : null,
    clientId: protocol === "oidc" ? String(input.clientId) : null,
    ssoUrl: protocol === "saml" ? String(input.ssoUrl) : null,
    entityId: protocol === "saml" ? String(input.entityId) : null,
    certificateFingerprint: protocol === "saml" ? sha256(String(input.certificate).replace(/\s+/g, "")) : null,
    enforceSso: input.enforceSso === true,
    defaultRole: ROLE_PERMISSIONS[String(input.defaultRole || "viewer").toLowerCase()] ? String(input.defaultRole || "viewer").toLowerCase() : "viewer"
  });
}

function authenticateEnterprisePrincipal(config, assertion, context) {
  config = config || {};
  assertion = assertion || {};
  context = context || {};
  if (context.signatureVerified !== true) throw new Error("governance: identity assertion signature must be verified by the protocol adapter");
  const nowSeconds = Math.floor(new Date(context.now || Date.now()).getTime() / 1000);
  let email;
  let subject;
  if (config.protocol === "oidc") {
    if (assertion.iss !== config.issuer) throw new Error("governance: OIDC issuer mismatch");
    const audiences = Array.isArray(assertion.aud) ? assertion.aud.map(String) : [String(assertion.aud || "")];
    if (!audiences.includes(config.clientId)) throw new Error("governance: OIDC audience mismatch");
    if (!assertion.exp || Number(assertion.exp) <= nowSeconds) throw new Error("governance: OIDC token expired");
    if (context.nonce && assertion.nonce !== context.nonce) throw new Error("governance: OIDC nonce mismatch");
    if (assertion.email_verified !== true) throw new Error("governance: OIDC email is not verified");
    email = String(assertion.email || "").toLowerCase();
    subject = String(assertion.sub || "");
  } else if (config.protocol === "saml") {
    if (String(assertion.issuer || "") !== config.entityId) throw new Error("governance: SAML issuer mismatch");
    if (context.audience && String(assertion.audience || "") !== String(context.audience)) throw new Error("governance: SAML audience mismatch");
    const nowMs = nowSeconds * 1000;
    if (assertion.notBefore && nowMs < new Date(assertion.notBefore).getTime()) throw new Error("governance: SAML assertion is not active");
    if (!assertion.notOnOrAfter || nowMs >= new Date(assertion.notOnOrAfter).getTime()) throw new Error("governance: SAML assertion expired");
    email = String(assertion.email || assertion.nameId || "").toLowerCase();
    subject = String(assertion.nameId || assertion.subject || "");
  } else {
    throw new Error("governance: validated enterprise identity configuration is required");
  }
  const domain = email.indexOf("@") > 0 ? email.split("@").pop() : "";
  if (!subject || !email || !config.domains.includes(domain)) throw new Error("governance: identity is outside the verified organization domains");
  return Object.freeze({ subject, email, domain, role: config.defaultRole, protocol: config.protocol });
}

function createOrganizationDirectory(config) {
  config = config || {};
  const organizationId = String(config.organizationId || "");
  if (!organizationId) throw new Error("governance: organizationId is required");
  const users = new Map();
  let sequence = 0;

  function normalizeUser(input, existing) {
    input = input || {};
    const id = String(input.id || (existing && existing.id) || "");
    const userName = String(input.userName || (existing && existing.userName) || "").trim().toLowerCase();
    if (!id || !userName || userName.indexOf("@") < 1) throw new Error("governance: SCIM user id and email-shaped userName are required");
    const role = String(input.role || (existing && existing.role) || "viewer").toLowerCase();
    if (!ROLE_PERMISSIONS[role]) throw new Error("governance: unknown role '" + role + "'");
    sequence++;
    return Object.freeze({
      schemas: Object.freeze(["urn:ietf:params:scim:schemas:core:2.0:User"]),
      id,
      userName,
      displayName: String(input.displayName || (existing && existing.displayName) || userName),
      role,
      active: input.active !== false,
      organizationId,
      externalId: input.externalId == null ? (existing && existing.externalId) || null : String(input.externalId),
      meta: Object.freeze({ resourceType: "User", version: 'W/"' + sequence + '"' })
    });
  }

  function upsertUser(input) {
    input = input || {};
    const id = String(input.id || (typeof crypto.randomUUID === "function" ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex")));
    const existing = id ? users.get(id) : null;
    const normalized = normalizeUser(Object.assign({}, input, { id }), existing);
    for (const user of users.values()) {
      if (user.id !== normalized.id && user.userName === normalized.userName) throw new Error("governance: SCIM userName already exists");
    }
    users.set(normalized.id, normalized);
    return normalized;
  }

  function patchUser(id, operations) {
    const existing = users.get(String(id));
    if (!existing) return null;
    const next = Object.assign({}, existing);
    for (const operation of operations || []) {
      if (String(operation.op || "").toLowerCase() !== "replace") throw new Error("governance: only SCIM replace operations are supported");
      const path = String(operation.path || "");
      if (!["active", "displayName", "role", "userName"].includes(path)) throw new Error("governance: unsupported SCIM patch path '" + path + "'");
      next[path] = operation.value;
    }
    return upsertUser(next);
  }

  function deactivateUser(id) {
    return patchUser(id, [{ op: "replace", path: "active", value: false }]);
  }

  function listUsers(filter) {
    let result = Array.from(users.values());
    const match = /^\s*(userName|externalId)\s+eq\s+"([^"]+)"\s*$/i.exec(String(filter || ""));
    if (filter && !match) throw new Error("governance: unsupported SCIM filter");
    if (match) result = result.filter((user) => String(user[match[1]] || "").toLowerCase() === match[2].toLowerCase());
    return { schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: result.length, startIndex: 1, itemsPerPage: result.length, Resources: result };
  }

  for (const user of config.users || []) upsertUser(user);
  return { organizationId, upsertUser, patchUser, deactivateUser, getUser: (id) => users.get(String(id)) || null, listUsers };
}

function createScimService(config) {
  config = config || {};
  const directory = config.directory || createOrganizationDirectory(config);
  const tokenHash = sha256(String(config.bearerToken || ""));
  if (!config.bearerToken || String(config.bearerToken).length < 24) throw new Error("governance: SCIM bearer token must be at least 24 characters");

  function response(status, body) { return { status, headers: { "content-type": "application/scim+json" }, body }; }
  function handle(request) {
    request = request || {};
    const auth = String((request.headers && (request.headers.authorization || request.headers.Authorization)) || "");
    const supplied = auth.replace(/^Bearer\s+/i, "");
    const expectedBuffer = Buffer.from(tokenHash, "hex");
    const suppliedBuffer = Buffer.from(sha256(supplied), "hex");
    if (!supplied || !crypto.timingSafeEqual(expectedBuffer, suppliedBuffer)) return response(401, { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "401", detail: "invalid bearer token" });
    const method = String(request.method || "GET").toUpperCase();
    const parsed = new URL(String(request.url || "/Users"), "https://scim.invalid");
    const userMatch = /^\/Users(?:\/([^/]+))?$/.exec(parsed.pathname);
    if (!userMatch) return response(404, { status: "404", detail: "resource not found" });
    const id = userMatch[1] ? decodeURIComponent(userMatch[1]) : null;
    try {
      if (method === "GET" && !id) return response(200, directory.listUsers(parsed.searchParams.get("filter")));
      if (method === "GET" && id) { const user = directory.getUser(id); return user ? response(200, user) : response(404, { status: "404", detail: "user not found" }); }
      if (method === "POST" && !id) return response(201, directory.upsertUser(request.body));
      if ((method === "PUT" || method === "PATCH") && id) {
        const body = request.body || {};
        const user = method === "PATCH" ? directory.patchUser(id, body.Operations || body.operations) : directory.upsertUser(Object.assign({}, body, { id }));
        return user ? response(200, user) : response(404, { status: "404", detail: "user not found" });
      }
      if (method === "DELETE" && id) return directory.deactivateUser(id) ? response(204, null) : response(404, { status: "404", detail: "user not found" });
      return response(405, { status: "405", detail: "method not allowed" });
    } catch (error) {
      return response(400, { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "400", detail: error.message });
    }
  }
  return { handle, directory };
}

module.exports = {
  ROLE_PERMISSIONS,
  TOKEN_SCOPES,
  createGovernancePolicy,
  createTokenDescriptor,
  authorizeToken,
  createAuditTrail,
  validateEnterpriseIdentityConfig,
  authenticateEnterprisePrincipal,
  createOrganizationDirectory,
  createScimService
};
