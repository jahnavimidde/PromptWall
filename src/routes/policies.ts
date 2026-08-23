/**
 * @file policies.ts
 * @module src/routes
 *
 * REST API routes for enterprise security policy management (M7A/M7B).
 * Protected by ADMIN role authorization. Emits audit logs on modifications
 * and invalidates runtime policy cache.
 */

import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import type { JwtUserPayload } from "../auth/jwt";
import { authMiddleware, requireRole } from "../auth/middleware";
import type { StoredPolicyVersion } from "../policy/policy-store";
import { PolicyStore } from "../policy/policy-store";
import { invalidatePolicyCache } from "../policy/runtime";

export const policyRoutes = new Hono();

// Enforce auth & ADMIN role across all policy management routes
policyRoutes.use("*", authMiddleware, requireRole(["ADMIN"]));

// ── Validation Schemas ───────────────────────────────────────────────────────

const PolicyConditionsSchema = z.object({
  riskLevel: z.enum(["low", "medium", "high", "critical"]).optional(),
  minRiskScore: z.number().min(0).max(100).optional(),
  category: z.enum(["pii", "secret", "sensitive", "malicious", "custom"]).optional(),
  subtype: z.string().optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  detector: z.string().optional(),
  provider: z.string().optional(),
});

const CreatePolicySchema = z.object({
  name: z.string().trim().min(1, "Name is required"),
  description: z.string().optional(),
  priority: z.number().int().min(0, "Priority must be non-negative integer"),
  enabled: z.boolean().default(true),
  conditions: PolicyConditionsSchema.default({}),
  action: z.enum(["allow", "mask", "block"]),
  reason: z.string().optional(),
});

const UpdatePolicySchema = z.object({
  name: z.string().trim().min(1).optional(),
  description: z.string().optional(),
  priority: z.number().int().min(0).optional(),
  enabled: z.boolean().optional(),
  conditions: PolicyConditionsSchema.optional(),
  action: z.enum(["allow", "mask", "block"]).optional(),
  reason: z.string().optional(),
});

const PolicyStatusSchema = z.object({
  enabled: z.boolean(),
});

// ── Handlers ─────────────────────────────────────────────────────────────────

/**
 * GET /api/policies - List all policies
 */
policyRoutes.get("/", async (c) => {
  const store = new PolicyStore();
  const policies = await store.listPolicies();
  return c.json({ policies });
});

/**
 * GET /api/policies/:id - Get policy details
 */
policyRoutes.get("/:id", async (c) => {
  const id = c.req.param("id");
  const store = new PolicyStore();
  const policy = await store.getPolicy(id);

  if (!policy) {
    return c.json(
      {
        error: {
          message: `Policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  return c.json({ policy });
});

/**
 * POST /api/policies - Create a new policy
 */
policyRoutes.post("/", zValidator("json", CreatePolicySchema), async (c) => {
  const input = c.req.valid("json");
  const user = c.get("user") as JwtUserPayload;
  const store = new PolicyStore();

  const policy = await store.createPolicy(input, user.email);
  invalidatePolicyCache();

  return c.json({ policy }, 201);
});

/**
 * PUT /api/policies/:id - Update an existing policy
 */
policyRoutes.put("/:id", zValidator("json", UpdatePolicySchema), async (c) => {
  const id = c.req.param("id");
  const input = c.req.valid("json");
  const user = c.get("user") as JwtUserPayload;
  const store = new PolicyStore();

  const updated = await store.updatePolicy(id, input, user.email);
  if (!updated) {
    return c.json(
      {
        error: {
          message: `Policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  invalidatePolicyCache();
  return c.json({ policy: updated });
});

/**
 * DELETE /api/policies/:id - Delete a policy
 */
policyRoutes.delete("/:id", async (c) => {
  const id = c.req.param("id");
  const user = c.get("user") as JwtUserPayload;
  const store = new PolicyStore();

  const deleted = await store.deletePolicy(id, user.email);
  if (!deleted) {
    return c.json(
      {
        error: {
          message: `Policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  invalidatePolicyCache();
  return c.json({ success: true, id });
});

/**
 * PATCH /api/policies/:id/status - Enable or disable a policy
 */
policyRoutes.patch("/:id/status", zValidator("json", PolicyStatusSchema), async (c) => {
  const id = c.req.param("id");
  const { enabled } = c.req.valid("json");
  const user = c.get("user") as JwtUserPayload;
  const store = new PolicyStore();

  const policy = await store.togglePolicyStatus(id, enabled, user.email);
  if (!policy) {
    return c.json(
      {
        error: {
          message: `Policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  invalidatePolicyCache();
  return c.json({ policy });
});

// ── Versioning Routes (M8B) ─────────────────────────────────────────────────

const RollbackSchema = z.object({
  version: z.number().int().positive("Version must be a positive integer"),
});

/**
 * GET /api/policies/:id/versions - List all immutable version snapshots for a policy
 */
policyRoutes.get("/:id/versions", async (c) => {
  const id = c.req.param("id");
  const store = new PolicyStore();

  // Ensure the policy itself exists (history may exist even after deletion)
  const policy = await store.getPolicy(id);
  if (!policy) {
    return c.json(
      {
        error: {
          message: `Policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  const versions: StoredPolicyVersion[] = await store.getPolicyVersions(id);
  return c.json({ policyId: id, versions });
});

/**
 * GET /api/policies/:id/versions/:version - Get a single version snapshot
 */
policyRoutes.get("/:id/versions/:version", async (c) => {
  const id = c.req.param("id");
  const versionParam = Number(c.req.param("version"));

  if (!Number.isInteger(versionParam) || versionParam < 1) {
    return c.json(
      {
        error: {
          message: "Version must be a positive integer",
          type: "validation_error",
        },
      },
      400,
    );
  }

  const store = new PolicyStore();
  const version: StoredPolicyVersion | null = await store.getPolicyVersion(id, versionParam);

  if (!version) {
    return c.json(
      {
        error: {
          message: `Version ${versionParam} of policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  return c.json({ version });
});

/**
 * POST /api/policies/:id/rollback - Roll back a policy to a specific historical version
 *
 * Rollback creates a NEW version snapshot copied from the target version, then
 * overwrites the live policy row. History is never deleted or rewritten.
 *
 * Body: { "version": <positive integer> }
 * Response: { policy, version } — the restored live state and its new version number.
 */
policyRoutes.post("/:id/rollback", zValidator("json", RollbackSchema), async (c) => {
  const id = c.req.param("id");
  const { version: targetVersion } = c.req.valid("json");
  const user = c.get("user") as JwtUserPayload;
  const store = new PolicyStore();

  const restored = await store.rollbackPolicy(id, targetVersion, user.email);

  if (!restored) {
    // Policy doesn't exist or target version doesn't exist
    const policy = await store.getPolicy(id);
    if (!policy) {
      return c.json(
        {
          error: {
            message: `Policy '${id}' not found`,
            type: "not_found",
          },
        },
        404,
      );
    }
    return c.json(
      {
        error: {
          message: `Version ${targetVersion} of policy '${id}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  // Retrieve the newly created version number (the rollback snapshot)
  const versions = await store.getPolicyVersions(id);
  const newVersion = versions.at(-1)?.version ?? null;

  invalidatePolicyCache();
  return c.json({ policy: restored, rolledBackFrom: targetVersion, version: newVersion });
});
