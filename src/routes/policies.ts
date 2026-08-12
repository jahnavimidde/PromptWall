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
import { authMiddleware, requireRole } from "../auth/middleware";
import type { JwtUserPayload } from "../auth/jwt";
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
