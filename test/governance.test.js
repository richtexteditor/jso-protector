"use strict";

const test = require("node:test");
const assert = require("node:assert");
const governance = require("../governance");

test("RBAC separates owner, developer, reviewer, and viewer capabilities", function () {
  const policy = governance.createGovernancePolicy({ members: [
    { id: "o", role: "owner" },
    { id: "d", role: "developer" },
    { id: "r", role: "reviewer" },
    { id: "v", role: "viewer" }
  ] });
  assert.equal(policy.authorize("o", "manage_billing").allowed, true);
  assert.equal(policy.authorize("d", "protect").allowed, true);
  assert.equal(policy.authorize("d", "manage_members").allowed, false);
  assert.equal(policy.authorize("r", "view_audit").allowed, true);
  assert.equal(policy.authorize("v", "export_evidence").allowed, false);
});

test("scoped token descriptors enforce expiry, revocation, and scope", function () {
  const token = governance.createTokenDescriptor({ id: "ci-1", createdBy: "o", scopes: ["protect"], expiresAt: "2030-01-01T00:00:00Z" });
  assert.equal(governance.authorizeToken(token, "protect", "2029-01-01T00:00:00Z").allowed, true);
  assert.equal(governance.authorizeToken(token, "audit:read", "2029-01-01T00:00:00Z").allowed, false);
  assert.equal(governance.authorizeToken(token, "protect", "2031-01-01T00:00:00Z").reason, "expired-token");
});

test("audit trail is hash chained and detects changed evidence", function () {
  const trail = governance.createAuditTrail({ organizationId: "org-1" });
  trail.append({ actorId: "d", action: "protect", target: "release-1", occurredAt: "2026-07-13T12:00:00Z" });
  trail.append({ actorId: "r", action: "export_evidence", target: "release-1", occurredAt: "2026-07-13T12:05:00Z" });
  assert.equal(trail.verify(), true);
  const changed = trail.events().map((row) => Object.assign({}, row));
  changed[0].outcome = "denied";
  assert.equal(trail.verify(changed), false);
});

test("enterprise identity configuration validates OIDC and SAML trust inputs", function () {
  const oidc = governance.validateEnterpriseIdentityConfig({ protocol: "oidc", domains: ["Example.com"], issuer: "https://login.example.com/", clientId: "jso", enforceSso: true, defaultRole: "developer" });
  assert.equal(oidc.issuer, "https://login.example.com");
  assert.deepEqual(oidc.domains, ["example.com"]);
  assert.equal(oidc.defaultRole, "developer");
  const saml = governance.validateEnterpriseIdentityConfig({ protocol: "saml", domains: ["example.com"], ssoUrl: "https://idp.example.com/sso", entityId: "jso", certificate: "CERTIFICATE" });
  assert.equal(saml.certificateFingerprint.length, 64);
  assert.throws(() => governance.validateEnterpriseIdentityConfig({ protocol: "oidc", domains: ["example.com"], issuer: "http://insecure", clientId: "jso" }), /https/);
});

test("enterprise principal mapping enforces signature issuer audience nonce expiry and domain", function () {
  const config = governance.validateEnterpriseIdentityConfig({ protocol: "oidc", domains: ["example.com"], issuer: "https://login.example.com", clientId: "jso", defaultRole: "reviewer" });
  const assertion = { iss: config.issuer, aud: "jso", sub: "idp-42", email: "Reviewer@Example.com", email_verified: true, nonce: "n-1", exp: 1893456000 };
  const principal = governance.authenticateEnterprisePrincipal(config, assertion, { signatureVerified: true, nonce: "n-1", now: "2029-01-01T00:00:00Z" });
  assert.equal(principal.email, "reviewer@example.com");
  assert.equal(principal.role, "reviewer");
  assert.throws(() => governance.authenticateEnterprisePrincipal(config, assertion, { signatureVerified: false }), /signature/);
  assert.throws(() => governance.authenticateEnterprisePrincipal(config, Object.assign({}, assertion, { email: "attacker@evil.example" }), { signatureVerified: true, nonce: "n-1", now: "2029-01-01T00:00:00Z" }), /domains/);
});

test("SCIM service provisions filters patches and deactivates organization users", function () {
  const token = "0123456789abcdef0123456789abcdef";
  const service = governance.createScimService({ organizationId: "org-1", bearerToken: token });
  const headers = { authorization: "Bearer " + token };
  assert.equal(service.handle({ method: "GET", url: "/Users", headers: { authorization: "Bearer wrong" } }).status, 401);
  const created = service.handle({ method: "POST", url: "/Users", headers, body: { userName: "Dev@Example.com", displayName: "Dev", role: "developer" } });
  assert.equal(created.status, 201);
  assert.equal(created.body.userName, "dev@example.com");
  const userId = created.body.id;
  const filtered = service.handle({ method: "GET", url: "/Users?filter=userName%20eq%20%22dev%40example.com%22", headers });
  assert.equal(filtered.body.totalResults, 1);
  const patched = service.handle({ method: "PATCH", url: "/Users/" + userId, headers, body: { Operations: [{ op: "replace", path: "role", value: "reviewer" }] } });
  assert.equal(patched.body.role, "reviewer");
  assert.equal(service.handle({ method: "DELETE", url: "/Users/" + userId, headers }).status, 204);
  assert.equal(service.directory.getUser(userId).active, false);
});
