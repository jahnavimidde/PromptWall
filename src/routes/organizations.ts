/**
 * @file organizations.ts
 * @module src/routes
 *
 * REST API routes for multi-tenant organization management (M12E).
 *
 * ── Endpoint map ──────────────────────────────────────────────────────────────
 *
 * Organizations (ADMIN only for create/list/delete; org members for read/update):
 *   POST   /api/organizations            Create org
 *   GET    /api/organizations            List all orgs
 *   GET    /api/organizations/:id        Get org details
 *   PATCH  /api/organizations/:id        Update org
 *   DELETE /api/organizations/:id        Delete org
 *
 * Members (ORG_ADMIN, SECURITY_ADMIN):
 *   GET    /api/organizations/:id/members           List org users
 *   POST   /api/organizations/:id/members           Add user to org
 *   DELETE /api/organizations/:id/members/:userId   Remove user
 *
 * API Keys (ORG_ADMIN, SECURITY_ADMIN):
 *   POST   /api/organizations/:id/api-keys           Create key (returns raw once)
 *   GET    /api/organizations/:id/api-keys           List keys (no raw key returned)
 *   DELETE /api/organizations/:id/api-keys/:keyId    Revoke key
 *
 * Policies (ANALYST+):
 *   GET    /api/organizations/:id/policies           List org + global policies
 *
 * Audit (ANALYST+):
 *   GET    /api/organizations/:id/audit              Query org-scoped audit events
 *
 * Usage (all org members):
 *   GET    /api/organizations/:id/usage              Daily usage analytics
 *
 * ── Security invariants ───────────────────────────────────────────────────────
 * 1. Global ADMIN bypasses org-role checks but is still scoped by :id param.
 * 2. Non-ADMIN callers must belong to the org in :id (validated via JWT orgId).
 * 3. key_hash is NEVER returned in any response.
 * 4. Usage endpoint returns only aggregate counts — no raw content.
 */

import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import type { JwtUserPayload } from "../auth/jwt";
import { authMiddleware, requireRole } from "../auth/middleware";
import type { OrgRole } from "../auth/permissions";
import { UserStore } from "../auth/user-store";
import { getConfig } from "../config";
import { querySecurityEvents } from "../logging/audit-query";
import { createLogDatabase, migrateLogDatabase } from "../logging/db";
import { ApiKeyStore } from "../organizations/api-key-store";
import { OrgStore } from "../organizations/org-store";
import { getOrgUsage } from "../organizations/usage-tracker";
import { PolicyStore } from "../policy/policy-store";

export const orgRoutes = new Hono();

// ── Schemas ───────────────────────────────────────────────────────────────────

const CreateOrgSchema = z.object({
  name: z.string().trim().min(1, "Name is required"),
  slug: z
    .string()
    .trim()
    .min(1, "Slug is required")
    .regex(/^[a-z0-9-]+$/, "Slug must be lowercase alphanumeric with hyphens only"),
});

const UpdateOrgSchema = z.object({
  name: z.string().trim().min(1).optional(),
  slug: z
    .string()
    .trim()
    .regex(/^[a-z0-9-]+$/, "Slug must be lowercase alphanumeric with hyphens only")
    .optional(),
});

const AddMemberSchema = z.object({
  email: z.string().trim().email("Valid email required"),
  orgRole: z.enum(["ORG_ADMIN", "SECURITY_ADMIN", "ANALYST", "VIEWER"] as const),
});

const CreateApiKeySchema = z.object({
  name: z.string().trim().min(1, "Key name is required"),
  permissions: z
    .array(
      z.enum([
        "org:manage",
        "org:members:manage",
        "org:policies:manage",
        "org:policies:read",
        "org:audit:read",
        "org:audit:export",
        "org:apikeys:manage",
        "org:usage:read",
      ] as const),
    )
    .min(1, "At least one permission is required"),
  expiresAt: z.string().datetime().optional(),
});

const OrgAuditQuerySchema = z.object({
  action: z.enum(["allow", "mask", "block"]).optional(),
  riskLevel: z.enum(["low", "medium", "high", "critical"]).optional(),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  maxRiskScore: z.coerce.number().min(0).max(100).optional(),
  provider: z.string().optional(),
  model: z.string().optional(),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  limit: z.coerce.number().min(1).max(500).default(50),
  offset: z.coerce.number().min(0).default(0),
  sortBy: z.enum(["timestamp", "riskScore", "latencyMs"]).default("timestamp"),
  sortOrder: z.enum(["asc", "desc"]).default("desc"),
});

const UsageQuerySchema = z.object({
  days: z.coerce.number().min(1).max(90).default(30),
});

// ── Guard helpers ─────────────────────────────────────────────────────────────

/** Returns true if caller is global ADMIN or belongs to the given org. */
function callerCanAccessOrg(user: JwtUserPayload | undefined, orgId: string): boolean {
  if (!user) return false;
  if (user.role === "ADMIN") return true;
  return user.organizationId === orgId;
}

/** Return a DB instance for inline admin queries (member management). */
async function getAdminDb() {
  const config = getConfig();
  const { db, driver } = createLogDatabase(config);
  await migrateLogDatabase(db, driver);
  return db;
}

// ── Organizations CRUD ────────────────────────────────────────────────────────

/**
 * POST /api/organizations
 * Create a new organization. ADMIN only.
 */
orgRoutes.post(
  "/",
  authMiddleware,
  requireRole(["ADMIN"]),
  zValidator("json", CreateOrgSchema),
  async (c) => {
    const { name, slug } = c.req.valid("json");
    const store = new OrgStore();

    try {
      const org = await store.createOrganization({ name, slug });
      return c.json({ organization: org }, 201);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      if (msg.includes("already exists")) {
        return c.json({ error: { message: msg, type: "conflict" } }, 409);
      }
      throw err;
    }
  },
);

/**
 * GET /api/organizations
 * List all organizations. ADMIN only.
 */
orgRoutes.get("/", authMiddleware, requireRole(["ADMIN"]), async (c) => {
  const store = new OrgStore();
  const organizations = await store.listOrganizations();
  return c.json({ organizations });
});

/**
 * GET /api/organizations/:id
 * Get org details. ADMIN or org member.
 */
orgRoutes.get("/:id", authMiddleware, async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json(
      { error: { message: "Access denied to this organization.", type: "forbidden" } },
      403,
    );
  }

  const store = new OrgStore();
  const org = await store.getOrganization(orgId);
  if (!org) {
    return c.json({ error: { message: "Organization not found.", type: "not_found" } }, 404);
  }

  return c.json({ organization: org });
});

/**
 * PATCH /api/organizations/:id
 * Update org. ADMIN or ORG_ADMIN.
 */
orgRoutes.patch("/:id", authMiddleware, zValidator("json", UpdateOrgSchema), async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json(
      { error: { message: "Access denied to this organization.", type: "forbidden" } },
      403,
    );
  }

  const isAdmin = user?.role === "ADMIN";
  const orgRole = user?.orgRole as OrgRole | undefined;
  if (!isAdmin && orgRole !== "ORG_ADMIN") {
    return c.json(
      {
        error: {
          message: "Requires ORG_ADMIN role to update organization.",
          type: "forbidden",
        },
      },
      403,
    );
  }

  const input = c.req.valid("json");
  const store = new OrgStore();

  try {
    const org = await store.updateOrganization(orgId, input);
    return c.json({ organization: org });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    if (msg.includes("not found")) {
      return c.json({ error: { message: msg, type: "not_found" } }, 404);
    }
    if (msg.includes("already exists")) {
      return c.json({ error: { message: msg, type: "conflict" } }, 409);
    }
    throw err;
  }
});

/**
 * DELETE /api/organizations/:id
 * Delete org. ADMIN only. Rejects if org still has members.
 */
orgRoutes.delete("/:id", authMiddleware, requireRole(["ADMIN"]), async (c) => {
  const orgId = c.req.param("id");

  if (orgId === "org_system") {
    return c.json(
      { error: { message: "Cannot delete the system organization.", type: "forbidden" } },
      403,
    );
  }

  const store = new OrgStore();
  const org = await store.getOrganization(orgId);
  if (!org) {
    return c.json({ error: { message: "Organization not found.", type: "not_found" } }, 404);
  }

  const memberCount = await store.getOrgMemberCount(orgId);
  if (memberCount > 0) {
    return c.json(
      {
        error: {
          message: `Cannot delete organization with ${memberCount} active member(s). Remove members first.`,
          type: "conflict",
        },
      },
      409,
    );
  }

  await store.deleteOrganization(orgId);
  return c.json({ success: true });
});

// ── Members ───────────────────────────────────────────────────────────────────

/**
 * GET /api/organizations/:id/members
 * List users in the org. ORG_ADMIN or SECURITY_ADMIN (or global ADMIN).
 */
orgRoutes.get("/:id/members", authMiddleware, async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const orgRole = user?.orgRole as OrgRole | undefined;
  if (!isAdmin && orgRole !== "ORG_ADMIN" && orgRole !== "SECURITY_ADMIN") {
    return c.json(
      { error: { message: "Requires ORG_ADMIN or SECURITY_ADMIN.", type: "forbidden" } },
      403,
    );
  }

  const store = new OrgStore();
  const org = await store.getOrganization(orgId);
  if (!org) {
    return c.json({ error: { message: "Organization not found.", type: "not_found" } }, 404);
  }

  const db = await getAdminDb();
  const rows = await db
    .selectFrom("users")
    .select(["id", "email", "role", "org_role", "created_at"])
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "asc")
    .execute();

  const members = rows.map((row) => ({
    id: row.id,
    email: row.email,
    role: row.role,
    orgRole: row.org_role,
    joinedAt: row.created_at,
  }));

  return c.json({ members, total: members.length });
});

/**
 * POST /api/organizations/:id/members
 * Assign an existing user to this org. ORG_ADMIN only.
 */
orgRoutes.post("/:id/members", authMiddleware, zValidator("json", AddMemberSchema), async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;
  const { email, orgRole } = c.req.valid("json");

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const callerOrgRole = user?.orgRole as OrgRole | undefined;
  if (!isAdmin && callerOrgRole !== "ORG_ADMIN") {
    return c.json(
      { error: { message: "Requires ORG_ADMIN to add members.", type: "forbidden" } },
      403,
    );
  }

  const store = new OrgStore();
  const org = await store.getOrganization(orgId);
  if (!org) {
    return c.json({ error: { message: "Organization not found.", type: "not_found" } }, 404);
  }

  const userStore = new UserStore();
  const existingUser = await userStore.findUserByEmail(email);
  if (!existingUser) {
    return c.json(
      { error: { message: `No user found with email '${email}'.`, type: "not_found" } },
      404,
    );
  }

  const db = await getAdminDb();
  await db
    .updateTable("users")
    .set({ organization_id: orgId, org_role: orgRole })
    .where("id", "=", existingUser.id)
    .execute();

  return c.json({
    member: {
      id: existingUser.id,
      email: existingUser.email,
      role: existingUser.role,
      orgRole,
      organizationId: orgId,
    },
  });
});

/**
 * DELETE /api/organizations/:id/members/:userId
 * Remove a user from the org. ORG_ADMIN only.
 */
orgRoutes.delete("/:id/members/:userId", authMiddleware, async (c) => {
  const orgId = c.req.param("id");
  const userId = c.req.param("userId");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const callerOrgRole = user?.orgRole as OrgRole | undefined;
  if (!isAdmin && callerOrgRole !== "ORG_ADMIN") {
    return c.json(
      { error: { message: "Requires ORG_ADMIN to remove members.", type: "forbidden" } },
      403,
    );
  }

  if (user?.sub === userId) {
    return c.json(
      { error: { message: "Cannot remove yourself from the organization.", type: "conflict" } },
      409,
    );
  }

  const db = await getAdminDb();
  await db
    .updateTable("users")
    .set({ organization_id: null, org_role: null })
    .where("id", "=", userId)
    .where("organization_id", "=", orgId)
    .execute();

  return c.json({ success: true });
});

// ── API Keys ──────────────────────────────────────────────────────────────────

/**
 * POST /api/organizations/:id/api-keys
 * Create an API key. Returns raw key ONCE.
 * ORG_ADMIN or SECURITY_ADMIN (or global ADMIN).
 */
orgRoutes.post(
  "/:id/api-keys",
  authMiddleware,
  zValidator("json", CreateApiKeySchema),
  async (c) => {
    const orgId = c.req.param("id");
    const user = c.get("user") as JwtUserPayload | undefined;

    if (!callerCanAccessOrg(user, orgId)) {
      return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
    }

    const isAdmin = user?.role === "ADMIN";
    const orgRole = user?.orgRole as OrgRole | undefined;
    if (!isAdmin && orgRole !== "ORG_ADMIN" && orgRole !== "SECURITY_ADMIN") {
      return c.json(
        { error: { message: "Requires ORG_ADMIN or SECURITY_ADMIN.", type: "forbidden" } },
        403,
      );
    }

    const { name, permissions, expiresAt } = c.req.valid("json");
    const store = new ApiKeyStore();

    const result = await store.createApiKey({
      organizationId: orgId,
      name,
      permissions,
      createdBy: user?.sub ?? "unknown",
      expiresAt,
    });

    // The raw key is returned ONCE here — caller must store it securely.
    return c.json({ key: result.key, apiKey: result.record }, 201);
  },
);

/**
 * GET /api/organizations/:id/api-keys
 * List API keys. key_hash is NEVER returned.
 */
orgRoutes.get("/:id/api-keys", authMiddleware, async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const orgRole = user?.orgRole as OrgRole | undefined;
  if (!isAdmin && orgRole !== "ORG_ADMIN" && orgRole !== "SECURITY_ADMIN") {
    return c.json(
      { error: { message: "Requires ORG_ADMIN or SECURITY_ADMIN.", type: "forbidden" } },
      403,
    );
  }

  const store = new ApiKeyStore();
  const apiKeys = await store.listApiKeys(orgId);
  return c.json({ apiKeys });
});

/**
 * DELETE /api/organizations/:id/api-keys/:keyId
 * Revoke an API key. ORG_ADMIN or SECURITY_ADMIN.
 */
orgRoutes.delete("/:id/api-keys/:keyId", authMiddleware, async (c) => {
  const orgId = c.req.param("id");
  const keyId = c.req.param("keyId");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const orgRole = user?.orgRole as OrgRole | undefined;
  if (!isAdmin && orgRole !== "ORG_ADMIN" && orgRole !== "SECURITY_ADMIN") {
    return c.json(
      { error: { message: "Requires ORG_ADMIN or SECURITY_ADMIN.", type: "forbidden" } },
      403,
    );
  }

  const store = new ApiKeyStore();
  await store.revokeApiKey(keyId, orgId);
  return c.json({ success: true });
});

// ── Policies (org-scoped view) ────────────────────────────────────────────────

/**
 * GET /api/organizations/:id/policies
 * List org-specific + global policies. ANALYST, SECURITY_ADMIN, ORG_ADMIN, ADMIN.
 */
orgRoutes.get("/:id/policies", authMiddleware, async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const orgRole = user?.orgRole as OrgRole | undefined;
  if (
    !isAdmin &&
    orgRole !== "ORG_ADMIN" &&
    orgRole !== "SECURITY_ADMIN" &&
    orgRole !== "ANALYST"
  ) {
    return c.json({ error: { message: "Requires ANALYST or higher.", type: "forbidden" } }, 403);
  }

  const store = new PolicyStore();
  const policies = await store.listPoliciesForOrg(orgId);
  return c.json({ policies, organizationId: orgId });
});

// ── Audit (org-scoped) ────────────────────────────────────────────────────────

/**
 * GET /api/organizations/:id/audit
 * Query org-scoped security events. ANALYST+.
 */
orgRoutes.get("/:id/audit", authMiddleware, zValidator("query", OrgAuditQuerySchema), async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const isAdmin = user?.role === "ADMIN";
  const orgRole = user?.orgRole as OrgRole | undefined;
  if (
    !isAdmin &&
    orgRole !== "ORG_ADMIN" &&
    orgRole !== "SECURITY_ADMIN" &&
    orgRole !== "ANALYST"
  ) {
    return c.json({ error: { message: "Requires ANALYST or higher.", type: "forbidden" } }, 403);
  }

  const filter = c.req.valid("query");

  // Inject organization_id — non-ADMIN callers cannot bypass this filter
  const result = await querySecurityEvents({ ...filter, organizationId: orgId });
  return c.json(result);
});

// ── Usage Analytics ───────────────────────────────────────────────────────────

/**
 * GET /api/organizations/:id/usage
 * Daily usage analytics (aggregate counts only — no raw content).
 * All org members.
 */
orgRoutes.get("/:id/usage", authMiddleware, zValidator("query", UsageQuerySchema), async (c) => {
  const orgId = c.req.param("id");
  const user = c.get("user") as JwtUserPayload | undefined;

  if (!callerCanAccessOrg(user, orgId)) {
    return c.json({ error: { message: "Access denied.", type: "forbidden" } }, 403);
  }

  const { days } = c.req.valid("query");
  const usage = await getOrgUsage(orgId, days);
  return c.json({ organizationId: orgId, days, usage });
});
