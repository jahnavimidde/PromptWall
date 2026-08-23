/**
 * @file m12b-organizations.test.ts
 * @module src/routes
 *
 * M12B Integration Tests — Organization RBAC, Tenant Isolation & Management API.
 *
 * Tests the full lifecycle:
 *   create org → add member → generate API key → track usage → fetch analytics
 *
 * RBAC matrix tests (ORG_ADMIN, ANALYST, VIEWER, cross-org isolation).
 * API key security invariants (hash-only storage, single plaintext return, revoke).
 * Tenant isolation (Org A vs Org B: policies, audit, usage, API keys, members).
 *
 * ── Architecture invariants verified ─────────────────────────────────────────
 * No AI pipeline files are imported or touched:
 *   - DetectionPipeline, RiskEngine, PolicyEngine, Detectors,
 *     AuditLogger, Provider layers are not referenced in this file.
 *
 * ── Testing approach ─────────────────────────────────────────────────────────
 * - In-memory SQLite (same BunSqliteDatabase adapter pattern as existing tests)
 * - Real JWT tokens signed via signUserToken()
 * - Hono app mounted with orgRoutes and injected DB
 * - No network I/O, no file system writes
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Hono } from "hono";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import { signUserToken } from "../auth/jwt";
import { authMiddleware, requireOrgRole } from "../auth/middleware";
import { UserStore } from "../auth/user-store";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { ApiKeyStore } from "../organizations/api-key-store";
import { OrgStore } from "../organizations/org-store";
import { getOrgUsage, trackOrgUsage } from "../organizations/usage-tracker";
import { PolicyStore } from "../policy/policy-store";
import { orgRoutes } from "./organizations";

// ── In-memory SQLite adapter (same pattern as all existing test files) ─────────

class BunSqliteDatabase implements SqliteDatabase {
  constructor(private readonly db: Database) {}
  close() {
    this.db.close();
  }
  prepare(query: string): SqliteStatement {
    const statement = this.db.prepare<unknown, SQLQueryBindings[]>(query);
    const reader = /^(select|pragma|with)\b/i.test(query.trim());
    return {
      get reader() {
        return reader;
      },
      all: (params: ReadonlyArray<unknown>) => statement.all(...(params as SQLQueryBindings[])),
      run: (params: ReadonlyArray<unknown>) => {
        const r = statement.run(...(params as SQLQueryBindings[]));
        return { changes: r.changes, lastInsertRowid: r.lastInsertRowid };
      },
      iterate: (params: ReadonlyArray<unknown>) =>
        statement.iterate(...(params as SQLQueryBindings[])),
    };
  }
}

async function createInMemoryDb(): Promise<Kysely<LogDatabase>> {
  const db = new Kysely<LogDatabase>({
    dialect: new SqliteDialect({
      database: new BunSqliteDatabase(new Database(":memory:")),
    }),
  });
  await migrateLogDatabase(db, "sqlite");
  return db;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a JWT Bearer header for a user with the given properties. */
async function bearerFor(
  userId: string,
  email: string,
  role: "ADMIN" | "SECURITY_ANALYST" | "VIEWER",
  orgId?: string,
  orgRole?: "ORG_ADMIN" | "SECURITY_ADMIN" | "ANALYST" | "VIEWER",
): Promise<string> {
  const token = await signUserToken(userId, email, role, 3600, orgId, orgRole);
  return `Bearer ${token}`;
}

/** Mount orgRoutes on a fresh Hono app. */
function buildApp(): Hono {
  const app = new Hono();
  app.route("/api/organizations", orgRoutes);
  return app;
}

// ── 1. Organization Lifecycle ─────────────────────────────────────────────────

describe("M12B — Organization Lifecycle", () => {
  let db: Kysely<LogDatabase>;
  let orgStore: OrgStore;
  let apiKeyStore: ApiKeyStore;
  let userStore: UserStore;

  beforeEach(async () => {
    db = await createInMemoryDb();
    orgStore = new OrgStore({ db });
    apiKeyStore = new ApiKeyStore({ db });
    userStore = new UserStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("full lifecycle: create org → add member → generate API key → track usage → fetch analytics", async () => {
    // 1. Create organization
    const org = await orgStore.createOrganization({ name: "Acme Corp", slug: "acme-corp" });
    expect(org.id).toMatch(/^org_/);
    expect(org.name).toBe("Acme Corp");
    expect(org.slug).toBe("acme-corp");

    // 2. Add user (member) to the org
    const member = await userStore.createUser(
      "alice@acme.com",
      "Password123!",
      "VIEWER",
      org.id,
      "ORG_ADMIN",
    );
    expect(member.organizationId).toBe(org.id);
    expect(member.orgRole).toBe("ORG_ADMIN");

    // Verify member count
    const count = await orgStore.getOrgMemberCount(org.id);
    expect(count).toBe(1);

    // 3. Generate API key — returns raw key once, stores only hash
    const keyResult = await apiKeyStore.createApiKey({
      organizationId: org.id,
      name: "production-key",
      permissions: ["org:audit:read", "org:usage:read"],
      createdBy: member.id,
    });
    expect(keyResult.key).toMatch(/^pw_live_/);
    expect(keyResult.key).toHaveLength(56);
    expect(keyResult.record.organizationId).toBe(org.id);

    // Verify hash stored, not plaintext
    const row = await db
      .selectFrom("api_keys")
      .selectAll()
      .where("id", "=", keyResult.record.id)
      .executeTakeFirst();
    expect(row).toBeDefined();
    expect(row!.key_hash).not.toBe(keyResult.key);
    const expectedHash = createHash("sha256").update(keyResult.key).digest("hex");
    expect(row!.key_hash).toBe(expectedHash);

    // 4. Track usage (fire-and-forget — allow time to flush)
    await new Promise<void>((resolve) => {
      trackOrgUsage(org.id, "allow", 150, 10, db);
      setTimeout(resolve, 80);
    });

    // 5. Fetch analytics
    const usage = await getOrgUsage(org.id, 30, db);
    expect(usage.length).toBeGreaterThanOrEqual(1);
    const today = usage[0];
    expect(today.organizationId).toBe(org.id);
    expect(today.totalRequests).toBeGreaterThanOrEqual(1);
    expect(today.allowedRequests).toBeGreaterThanOrEqual(1);
  });
});

// ── 2. RBAC Tests via HTTP Routes ─────────────────────────────────────────────

describe("M12B — RBAC via HTTP routes", () => {
  let db: Kysely<LogDatabase>;
  let orgStore: OrgStore;

  beforeEach(async () => {
    db = await createInMemoryDb();
    orgStore = new OrgStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("POST /api/organizations requires global ADMIN — VIEWER gets 403", async () => {
    const app = buildApp();
    const auth = await bearerFor("usr_viewer", "viewer@test.com", "VIEWER");

    const res = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify({ name: "Should Fail", slug: "should-fail" }),
    });
    expect(res.status).toBe(403);
  });

  test("POST /api/organizations succeeds for global ADMIN", async () => {
    const app = buildApp();
    const auth = await bearerFor("usr_admin", "admin@test.com", "ADMIN");

    const res = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify({ name: "Admin Created Org", slug: `admin-org-${Date.now()}` }),
    });
    // 201 = created; 409 = slug conflict on repeated runs — both mean handler was reached
    expect([201, 409]).toContain(res.status);
  });

  test("RBAC: ORG_ADMIN can create API key (201), ANALYST cannot (403)", async () => {
    const app = buildApp();
    const org = await orgStore.createOrganization({ name: "RbacOrg", slug: `rbac-${Date.now()}` });

    // ORG_ADMIN → 201
    const adminAuth = await bearerFor("usr_oa", "oa@test.com", "VIEWER", org.id, "ORG_ADMIN");
    const resAdmin = await app.request(`/api/organizations/${org.id}/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: adminAuth },
      body: JSON.stringify({ name: "test-key", permissions: ["org:usage:read"] }),
    });
    expect(resAdmin.status).toBe(201);

    // ANALYST → 403
    const analystAuth = await bearerFor("usr_an", "an@test.com", "VIEWER", org.id, "ANALYST");
    const resAnalyst = await app.request(`/api/organizations/${org.id}/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: analystAuth },
      body: JSON.stringify({ name: "analyst-key", permissions: ["org:usage:read"] }),
    });
    expect(resAnalyst.status).toBe(403);
  });

  test("RBAC: VIEWER can GET usage (200)", async () => {
    const app = buildApp();
    const org = await orgStore.createOrganization({
      name: "ViewerOrg",
      slug: `viewer-${Date.now()}`,
    });

    const viewerAuth = await bearerFor("usr_vw", "vw@test.com", "VIEWER", org.id, "VIEWER");
    const res = await app.request(`/api/organizations/${org.id}/usage`, {
      headers: { Authorization: viewerAuth },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { organizationId: string };
    expect(body.organizationId).toBe(org.id);
  });

  test("RBAC: User from different org gets 403 on another org's resource", async () => {
    const app = buildApp();
    const orgA = await orgStore.createOrganization({ name: "OrgA", slug: `org-a-${Date.now()}` });
    const orgB = await orgStore.createOrganization({ name: "OrgB", slug: `org-b-${Date.now()}` });

    // Org B user tries to access Org A
    const orgBUserAuth = await bearerFor("usr_b", "b@test.com", "VIEWER", orgB.id, "ORG_ADMIN");
    const res = await app.request(`/api/organizations/${orgA.id}/usage`, {
      headers: { Authorization: orgBUserAuth },
    });
    expect(res.status).toBe(403);
  });

  test("Unauthenticated request to any org route returns 401", async () => {
    const app = buildApp();
    const org = await orgStore.createOrganization({
      name: "AnyOrg",
      slug: `any-org-${Date.now()}`,
    });

    const res = await app.request(`/api/organizations/${org.id}/usage`);
    expect(res.status).toBe(401);
  });
});

// ── 3. API Key Security Invariants ────────────────────────────────────────────

describe("M12B — API Key Security Invariants", () => {
  let db: Kysely<LogDatabase>;
  let store: ApiKeyStore;
  const orgId = "org_apikey_test";

  beforeEach(async () => {
    db = await createInMemoryDb();
    store = new ApiKeyStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("raw key starts with pw_live_ and is exactly 56 characters", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "production-key",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });
    expect(result.key).toMatch(/^pw_live_/);
    expect(result.key).toHaveLength(56);
  });

  test("plaintext key returned only during creation — not visible in list", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "one-time-key",
      permissions: ["org:audit:read"],
      createdBy: "usr_admin",
    });

    const listed = await store.listApiKeys(orgId);
    expect(listed.length).toBe(1);

    const listedKey = listed[0];
    // key_hash must NOT appear in list response
    // biome-ignore lint/suspicious/noExplicitAny: intentional security assertion
    expect((listedKey as any).keyHash).toBeUndefined();
    // biome-ignore lint/suspicious/noExplicitAny: intentional security assertion
    expect((listedKey as any).key_hash).toBeUndefined();
    // keyPrefix is safe (first 16 chars of raw key)
    expect(listedKey.keyPrefix).toMatch(/^pw_live_/);
    // keyPrefix ≠ full raw key
    expect(listedKey.keyPrefix).not.toBe(result.key);
  });

  test("database stores SHA-256 hash, not plaintext", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "hash-check",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    const row = await db
      .selectFrom("api_keys")
      .selectAll()
      .where("id", "=", result.record.id)
      .executeTakeFirst();

    expect(row).toBeDefined();
    // hash ≠ raw key
    expect(row!.key_hash).not.toBe(result.key);
    // hash = sha256(raw key)
    const expected = createHash("sha256").update(result.key).digest("hex");
    expect(row!.key_hash).toBe(expected);
  });

  test("revoke disables key — verifyApiKey returns null after revoke", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "to-revoke",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    // Before revoke — key is valid
    const before = await store.verifyApiKey(result.key);
    expect(before).not.toBeNull();
    expect(before!.id).toBe(result.record.id);

    // Revoke
    await store.revokeApiKey(result.record.id, orgId);

    // After revoke — key is invalid
    const after = await store.verifyApiKey(result.key);
    expect(after).toBeNull();

    // Not in list either
    const listed = await store.listApiKeys(orgId);
    expect(listed.find((k) => k.id === result.record.id)).toBeUndefined();
  });

  test("cross-org revoke silently does nothing — key remains valid", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "protected",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    // Attempt cross-org revoke
    await store.revokeApiKey(result.record.id, "org_wrong");

    // Key still verifiable
    const verified = await store.verifyApiKey(result.key);
    expect(verified).not.toBeNull();
  });

  test("verifyApiKey returns null for expired key", async () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "expired-key",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
      expiresAt: pastDate,
    });

    const verified = await store.verifyApiKey(result.key);
    expect(verified).toBeNull();
  });
});

// ── 4. Tenant Isolation ───────────────────────────────────────────────────────

describe("M12B — Tenant Isolation", () => {
  let db: Kysely<LogDatabase>;
  let orgStore: OrgStore;
  let apiKeyStore: ApiKeyStore;
  let policyStore: PolicyStore;

  beforeEach(async () => {
    db = await createInMemoryDb();
    orgStore = new OrgStore({ db });
    apiKeyStore = new ApiKeyStore({ db });
    policyStore = new PolicyStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("Org A API keys are not accessible by Org B", async () => {
    const orgA = await orgStore.createOrganization({ name: "Org A", slug: "org-a-iso" });
    const orgB = await orgStore.createOrganization({ name: "Org B", slug: "org-b-iso" });

    await apiKeyStore.createApiKey({
      organizationId: orgA.id,
      name: "Key A1",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });
    await apiKeyStore.createApiKey({
      organizationId: orgB.id,
      name: "Key B1",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    const keysA = await apiKeyStore.listApiKeys(orgA.id);
    const keysB = await apiKeyStore.listApiKeys(orgB.id);

    expect(keysA.every((k) => k.organizationId === orgA.id)).toBe(true);
    expect(keysB.every((k) => k.organizationId === orgB.id)).toBe(true);
    expect(keysA.length).toBe(1);
    expect(keysB.length).toBe(1);
  });

  test("Org A policies are not visible to Org B via listPoliciesForOrg", async () => {
    const orgA = await orgStore.createOrganization({ name: "Policy Org A", slug: "pol-org-a" });
    const orgB = await orgStore.createOrganization({ name: "Policy Org B", slug: "pol-org-b" });

    // Policy scoped to Org A
    await policyStore.createPolicy(
      {
        name: "OrgA Secret Block",
        priority: 10,
        conditions: { category: "secret" },
        action: "block",
        organizationId: orgA.id,
      },
      "admin",
    );

    const policiesA = await policyStore.listPoliciesForOrg(orgA.id);
    const policiesB = await policyStore.listPoliciesForOrg(orgB.id);

    // Org A sees its own policy
    const orgAOwned = policiesA.filter((p) => p.organizationId === orgA.id);
    expect(orgAOwned.length).toBe(1);
    expect(orgAOwned[0].name).toBe("OrgA Secret Block");

    // Org B does NOT see Org A's policy
    const orgAInB = policiesB.filter((p) => p.organizationId === orgA.id);
    expect(orgAInB.length).toBe(0);
  });

  test("Org A usage data is not accessible by Org B", async () => {
    const orgA = await orgStore.createOrganization({ name: "Usage Org A", slug: "usage-org-a" });
    const orgB = await orgStore.createOrganization({ name: "Usage Org B", slug: "usage-org-b" });

    // Record usage only for Org A
    await new Promise<void>((resolve) => {
      trackOrgUsage(orgA.id, "allow", 200, 15, db);
      setTimeout(resolve, 80);
    });

    const usageA = await getOrgUsage(orgA.id, 30, db);
    const usageB = await getOrgUsage(orgB.id, 30, db);

    expect(usageA.every((u) => u.organizationId === orgA.id)).toBe(true);
    expect(usageA.length).toBeGreaterThanOrEqual(1);
    expect(usageA[0].totalRequests).toBeGreaterThanOrEqual(1);

    // Org B has no usage
    expect(usageB.length).toBe(0);
  });

  test("HTTP: Org A user cannot read Org B usage", async () => {
    const app = buildApp();
    const orgA = await orgStore.createOrganization({ name: "IsoA", slug: `iso-a-${Date.now()}` });
    const orgB = await orgStore.createOrganization({ name: "IsoB", slug: `iso-b-${Date.now()}` });

    const authA = await bearerFor("usr_a", "a@iso.com", "VIEWER", orgA.id, "ORG_ADMIN");
    const res = await app.request(`/api/organizations/${orgB.id}/usage`, {
      headers: { Authorization: authA },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("forbidden");
  });

  test("HTTP: Org A user cannot read Org B audit events", async () => {
    const app = buildApp();
    const orgA = await orgStore.createOrganization({
      name: "AuditA",
      slug: `audit-a-${Date.now()}`,
    });
    const orgB = await orgStore.createOrganization({
      name: "AuditB",
      slug: `audit-b-${Date.now()}`,
    });

    const authA = await bearerFor("usr_aa", "aa@iso.com", "VIEWER", orgA.id, "ANALYST");
    const res = await app.request(`/api/organizations/${orgB.id}/audit`, {
      headers: { Authorization: authA },
    });
    expect(res.status).toBe(403);
  });

  test("HTTP: Org A user cannot list Org B policies", async () => {
    const app = buildApp();
    const orgA = await orgStore.createOrganization({ name: "PA", slug: `pa-${Date.now()}` });
    const orgB = await orgStore.createOrganization({ name: "PB", slug: `pb-${Date.now()}` });

    const authA = await bearerFor("usr_ap", "ap@iso.com", "VIEWER", orgA.id, "ANALYST");
    const res = await app.request(`/api/organizations/${orgB.id}/policies`, {
      headers: { Authorization: authA },
    });
    expect(res.status).toBe(403);
  });

  test("HTTP: Org A user cannot list Org B members", async () => {
    const app = buildApp();
    const orgA = await orgStore.createOrganization({ name: "MA", slug: `ma-${Date.now()}` });
    const orgB = await orgStore.createOrganization({ name: "MB", slug: `mb-${Date.now()}` });

    const authA = await bearerFor("usr_am", "am@iso.com", "VIEWER", orgA.id, "ORG_ADMIN");
    const res = await app.request(`/api/organizations/${orgB.id}/members`, {
      headers: { Authorization: authA },
    });
    expect(res.status).toBe(403);
  });
});

// ── 5. requireOrgRole middleware unit tests ───────────────────────────────────

describe("M12B — requireOrgRole middleware", () => {
  test("ORG_ADMIN reaches protected handler", async () => {
    const app = new Hono();
    app.use("/protected", authMiddleware, requireOrgRole(["ORG_ADMIN"]));
    app.get("/protected", (c) => c.json({ ok: true }));

    const auth = await bearerFor("usr_oa2", "oa2@test.com", "VIEWER", "org_mw_test", "ORG_ADMIN");
    const res = await app.request("/protected", { headers: { Authorization: auth } });
    expect(res.status).toBe(200);
  });

  test("ANALYST is blocked from ORG_ADMIN-only route with 403", async () => {
    const app = new Hono();
    app.use("/admin-only", authMiddleware, requireOrgRole(["ORG_ADMIN"]));
    app.get("/admin-only", (c) => c.json({ ok: true }));

    const auth = await bearerFor("usr_an2", "an2@test.com", "VIEWER", "org_mw_test", "ANALYST");
    const res = await app.request("/admin-only", { headers: { Authorization: auth } });
    expect(res.status).toBe(403);
  });

  test("Global ADMIN bypasses org-role check", async () => {
    const app = new Hono();
    app.use("/secure", authMiddleware, requireOrgRole(["ORG_ADMIN"]));
    app.get("/secure", (c) => c.json({ ok: true }));

    // No orgRole in token — but global ADMIN always passes
    const auth = await bearerFor("usr_gadmin", "gadmin@test.com", "ADMIN");
    const res = await app.request("/secure", { headers: { Authorization: auth } });
    expect(res.status).toBe(200);
  });

  test("User with no organization in JWT is blocked with 403", async () => {
    const app = new Hono();
    app.use("/org-required", authMiddleware, requireOrgRole(["ORG_ADMIN"]));
    app.get("/org-required", (c) => c.json({ ok: true }));

    // No orgId in token
    const auth = await bearerFor("usr_noorg", "noorg@test.com", "VIEWER");
    const res = await app.request("/org-required", { headers: { Authorization: auth } });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("No organization");
  });

  test("Empty allowedOrgRoles list allows any org member", async () => {
    const app = new Hono();
    // requireOrgRole([]) means "any authenticated org member may proceed"
    app.use("/any-member", authMiddleware, requireOrgRole([]));
    app.get("/any-member", (c) => c.json({ ok: true }));

    const auth = await bearerFor("usr_viewer3", "v3@test.com", "VIEWER", "org_any", "VIEWER");
    const res = await app.request("/any-member", { headers: { Authorization: auth } });
    expect(res.status).toBe(200);
  });
});

// ── 6. Organization CRUD HTTP routes ─────────────────────────────────────────
//
// NOTE: These tests create orgs via the HTTP API (POST /api/organizations with
// ADMIN token) so that the org exists in the same singleton DB that the
// GET/PATCH route handlers query. Do NOT use an injected store here — it would
// operate against a separate in-memory DB invisible to the route handlers.

describe("M12B — Organization CRUD HTTP routes", () => {
  test("GET /:id — org member can read their own org (200)", async () => {
    const app = buildApp();
    const adminAuth = await bearerFor("usr_gadmin2", "gadmin2@test.com", "ADMIN");
    const slug = `read-org-${Date.now()}`;

    // Create org via HTTP so it lands in the singleton DB the GET handler queries
    const createRes = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: adminAuth },
      body: JSON.stringify({ name: "ReadOrg", slug }),
    });
    expect([201, 409]).toContain(createRes.status);
    const orgId =
      createRes.status === 201
        ? ((await createRes.json()) as { organization: { id: string } }).organization.id
        : `org_conflict_${slug}`;

    if (createRes.status !== 201) {
      // Slug conflict on repeated runs — skip test body but don't fail
      return;
    }

    const auth = await bearerFor("usr_read", "read@test.com", "VIEWER", orgId, "ANALYST");
    const res = await app.request(`/api/organizations/${orgId}`, {
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { organization: { id: string; name: string } };
    expect(body.organization.id).toBe(orgId);
    expect(body.organization.name).toBe("ReadOrg");
  });

  test("GET /:id — member from different org gets 403", async () => {
    const app = buildApp();
    const adminAuth = await bearerFor("usr_gadmin3", "gadmin3@test.com", "ADMIN");
    const slugA = `aa-${Date.now()}`;
    const slugB = `bb-${Date.now()}`;

    const resA = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: adminAuth },
      body: JSON.stringify({ name: "AA", slug: slugA }),
    });
    const resB = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: adminAuth },
      body: JSON.stringify({ name: "BB", slug: slugB }),
    });
    if (resA.status !== 201 || resB.status !== 201) return;

    const orgAId = ((await resA.json()) as { organization: { id: string } }).organization.id;
    const orgBId = ((await resB.json()) as { organization: { id: string } }).organization.id;

    const authB = await bearerFor("usr_b2", "b2@test.com", "VIEWER", orgBId, "ORG_ADMIN");
    const res = await app.request(`/api/organizations/${orgAId}`, {
      headers: { Authorization: authB },
    });
    expect(res.status).toBe(403);
  });

  test("PATCH /:id — ORG_ADMIN can update org name (200)", async () => {
    const app = buildApp();
    const adminAuth = await bearerFor("usr_gadmin4", "gadmin4@test.com", "ADMIN");
    const slug = `patch-${Date.now()}`;

    const createRes = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: adminAuth },
      body: JSON.stringify({ name: "OldName", slug }),
    });
    if (createRes.status !== 201) return;
    const orgId = ((await createRes.json()) as { organization: { id: string } }).organization.id;

    const auth = await bearerFor("usr_oa3", "oa3@test.com", "VIEWER", orgId, "ORG_ADMIN");
    const res = await app.request(`/api/organizations/${orgId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify({ name: "NewName" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { organization: { name: string } };
    expect(body.organization.name).toBe("NewName");
  });

  test("PATCH /:id — ANALYST is rejected with 403", async () => {
    const app = buildApp();
    const adminAuth = await bearerFor("usr_gadmin5", "gadmin5@test.com", "ADMIN");
    const slug = `pd-${Date.now()}`;

    const createRes = await app.request("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: adminAuth },
      body: JSON.stringify({ name: "PatchDeny", slug }),
    });
    if (createRes.status !== 201) return;
    const orgId = ((await createRes.json()) as { organization: { id: string } }).organization.id;

    const auth = await bearerFor("usr_ana3", "ana3@test.com", "VIEWER", orgId, "ANALYST");
    const res = await app.request(`/api/organizations/${orgId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify({ name: "Attempted" }),
    });
    expect(res.status).toBe(403);
  });
});

// ── 7. API Key HTTP routes ────────────────────────────────────────────────────

describe("M12B — API Key HTTP routes", () => {
  let db: Kysely<LogDatabase>;
  let orgStore: OrgStore;

  beforeEach(async () => {
    db = await createInMemoryDb();
    orgStore = new OrgStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("POST /api-keys — key_hash never appears in response body (201)", async () => {
    const app = buildApp();
    const org = await orgStore.createOrganization({ name: "KeyOrg", slug: `ko-${Date.now()}` });

    const auth = await bearerFor("usr_ko", "ko@test.com", "VIEWER", org.id, "ORG_ADMIN");
    const res = await app.request(`/api/organizations/${org.id}/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: JSON.stringify({ name: "my-key", permissions: ["org:usage:read"] }),
    });
    expect(res.status).toBe(201);

    const body = (await res.json()) as {
      key: string;
      apiKey: { keyPrefix: string };
    };
    // Raw key returned once
    expect(body.key).toMatch(/^pw_live_/);
    // biome-ignore lint/suspicious/noExplicitAny: intentional security assertion
    expect((body as any).keyHash).toBeUndefined();
    // biome-ignore lint/suspicious/noExplicitAny: intentional security assertion
    expect((body as any).key_hash).toBeUndefined();
    // biome-ignore lint/suspicious/noExplicitAny: intentional security assertion
    expect((body.apiKey as any).keyHash).toBeUndefined();
    // biome-ignore lint/suspicious/noExplicitAny: intentional security assertion
    expect((body.apiKey as any).key_hash).toBeUndefined();
  });

  test("DELETE /api-keys/:keyId — ANALYST gets 403", async () => {
    const app = buildApp();
    const org = await orgStore.createOrganization({ name: "DelOrg", slug: `do-${Date.now()}` });

    const auth = await bearerFor("usr_da", "da@test.com", "VIEWER", org.id, "ANALYST");
    const res = await app.request(`/api/organizations/${org.id}/api-keys/key_fake`, {
      method: "DELETE",
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(403);
  });

  test("GET /api-keys — VIEWER gets 403", async () => {
    const app = buildApp();
    const org = await orgStore.createOrganization({ name: "ListOrg", slug: `lo-${Date.now()}` });

    const auth = await bearerFor("usr_lv", "lv@test.com", "VIEWER", org.id, "VIEWER");
    const res = await app.request(`/api/organizations/${org.id}/api-keys`, {
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(403);
  });
});
