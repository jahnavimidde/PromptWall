/**
 * @file policies.test.ts
 * @module src/routes
 *
 * M7A/M7B Route Integration Tests for Policy Management APIs (/api/policies/*).
 */

import { describe, expect, test, afterAll } from "bun:test";
import { Hono } from "hono";
import { signUserToken } from "../auth/jwt";
import { getAuditLogger } from "../logging/audit-logger";
import { PolicyStore } from "../policy/policy-store";
import { invalidatePolicyCache } from "../policy/runtime";
import { policyRoutes } from "./policies";

describe("M7A & M7B — Policy Management REST API Routes (/api/policies/*)", () => {
  const app = new Hono();
  app.route("/api/policies", policyRoutes);

  afterAll(async () => {
    const store = new PolicyStore();
    const policies = await store.listPolicies();
    for (const p of policies) {
      await store.deletePolicy(p.id, "test-cleanup");
    }
    invalidatePolicyCache();
  });

  test("unauthenticated requests return 401 Unauthorized", async () => {
    const res = await app.request("/api/policies");
    expect(res.status).toBe(401);
  });

  test("non-ADMIN roles return 403 Forbidden", async () => {
    const analystToken = await signUserToken("usr_analyst", "analyst@promptwall.com", "SECURITY_ANALYST");
    const res = await app.request("/api/policies", {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    expect(res.status).toBe(403);
  });

  test("ADMIN role can list, create, update, toggle status, and delete policies", async () => {
    const adminToken = await signUserToken("usr_admin", "admin@promptwall.com", "ADMIN");
    const authHeader = { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" };

    // 1. GET /api/policies initially empty or populated
    const resList = await app.request("/api/policies", { headers: authHeader });
    expect(resList.status).toBe(200);

    // 2. POST /api/policies - Create Policy
    const resCreate = await app.request("/api/policies", {
      method: "POST",
      headers: authHeader,
      body: JSON.stringify({
        name: "Block Dynamic Secrets",
        description: "Block critical AWS access keys",
        priority: 1,
        enabled: true,
        action: "block",
        conditions: {
          subtype: "AWS_ACCESS_KEY",
          severity: "critical",
        },
      }),
    });
    expect(resCreate.status).toBe(201);

    const bodyCreate = (await resCreate.json()) as { policy: { id: string; name: string; priority: number } };
    const policyId = bodyCreate.policy.id;
    expect(policyId).toMatch(/^pol_/);
    expect(bodyCreate.policy.name).toBe("Block Dynamic Secrets");
    expect(bodyCreate.policy.priority).toBe(1);

    // 3. GET /api/policies/:id
    const resGet = await app.request(`/api/policies/${policyId}`, { headers: authHeader });
    expect(resGet.status).toBe(200);

    // 4. PUT /api/policies/:id - Update Policy
    const resUpdate = await app.request(`/api/policies/${policyId}`, {
      method: "PUT",
      headers: authHeader,
      body: JSON.stringify({
        name: "Block Dynamic Secrets Updated",
        priority: 2,
      }),
    });
    expect(resUpdate.status).toBe(200);
    const bodyUpdate = (await resUpdate.json()) as { policy: { name: string; priority: number } };
    expect(bodyUpdate.policy.name).toBe("Block Dynamic Secrets Updated");
    expect(bodyUpdate.policy.priority).toBe(2);

    // 5. PATCH /api/policies/:id/status - Toggle Status
    const resToggle = await app.request(`/api/policies/${policyId}/status`, {
      method: "PATCH",
      headers: authHeader,
      body: JSON.stringify({ enabled: false }),
    });
    expect(resToggle.status).toBe(200);
    const bodyToggle = (await resToggle.json()) as { policy: { enabled: boolean } };
    expect(bodyToggle.policy.enabled).toBe(false);

    // 6. DELETE /api/policies/:id
    const resDelete = await app.request(`/api/policies/${policyId}`, {
      method: "DELETE",
      headers: authHeader,
    });
    expect(resDelete.status).toBe(200);

    // 7. Audit Log Verification — verify policy_update audit event was recorded
    const auditLogger = getAuditLogger();
    const events = await auditLogger.getRecentEvents(10, 0);
    const updateEvent = events.find((e) => e.action === "policy_update");
    expect(updateEvent).toBeDefined();
    expect(updateEvent?.source).toBe("promptwall");
  });

  test("POST /api/policies validates payload via Zod", async () => {
    const adminToken = await signUserToken("usr_admin", "admin@promptwall.com", "ADMIN");

    // Invalid action
    const resBadAction = await app.request("/api/policies", {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Test Bad Action",
        priority: 1,
        action: "INVALID_ACTION",
      }),
    });
    expect(resBadAction.status).toBe(400);

    // Negative priority
    const resBadPriority = await app.request("/api/policies", {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Test Bad Priority",
        priority: -5,
        action: "block",
      }),
    });
    expect(resBadPriority.status).toBe(400);
  });
});
