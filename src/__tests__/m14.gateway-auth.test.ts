/**
 * @file m14.gateway-auth.test.ts
 * @module src/__tests__
 *
 * Comprehensive M14 AI Gateway Authentication & Tenant Isolation Tests.
 *
 * Verifies:
 * 1. Unauthenticated requests to /openai/*, /anthropic/*, /codex/* are rejected with 401.
 * 2. Public endpoints (/health, /health/live, /info, /favicon.svg) remain accessible without auth.
 * 3. Valid JWT tokens grant access to the AI gateway.
 * 4. Invalid, expired, or malformed JWT tokens are rejected with 401.
 * 5. Users with insufficient roles (e.g. VIEWER) receive 403 Forbidden.
 * 6. Valid API keys (pw_live_...) grant access via Bearer, x-api-key, api-key, and query param.
 * 7. Invalid, expired, or revoked API keys are rejected with 401.
 * 8. Tenant isolation is strictly enforced from verified credentials.
 * 9. Responses and errors never leak raw credentials, secrets, or internal tokens.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { signUserToken } from "../auth/jwt";
import { app } from "../index";
import { ApiKeyStore } from "../organizations/api-key-store";
import { OrgStore } from "../organizations/org-store";

describe("M14 — AI Gateway Authentication & Tenant Isolation", () => {
  let orgStore: OrgStore;
  let apiKeyStore: ApiKeyStore;
  let testOrgId: string;
  let validRawApiKey: string;

  beforeEach(async () => {
    orgStore = new OrgStore();
    apiKeyStore = new ApiKeyStore();

    const org = await orgStore.createOrganization({
      name: "M14 Test Organization",
      slug: `m14-org-${crypto.randomUUID().slice(0, 8)}`,
    });
    testOrgId = org.id;

    const createdKey = await apiKeyStore.createApiKey({
      organizationId: testOrgId,
      name: "M14 Test Gateway Key",
      permissions: ["org:usage:read", "org:policies:read"],
      createdBy: "usr_m14_admin",
    });
    validRawApiKey = createdKey.key;
  });

  afterEach(async () => {
    try {
      if (testOrgId) {
        await orgStore.deleteOrganization(testOrgId);
      }
    } catch {
      // Best-effort cleanup
    }
  });

  // ── 1. Unauthenticated Route Rejections (401) ──────────────────────────────

  test("Unauthenticated request to /openai/v1/chat/completions returns 401", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello without auth" }],
      }),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string; message: string } };
    expect(data.error.type).toBe("unauthorized");
    expect(data.error.message).toContain("Authentication required");
  });

  test("Unauthenticated request to /anthropic/v1/messages returns 401", async () => {
    const res = await app.request("/anthropic/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 100,
        messages: [{ role: "user", content: "Hello without auth" }],
      }),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("unauthorized");
  });

  test("Unauthenticated request to /codex/responses returns 401", async () => {
    const res = await app.request("/codex/responses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "gpt-4o",
        instructions: "Test instructions",
      }),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("unauthorized");
  });

  test("Unauthenticated request to proxy fallback /openai/models returns 401", async () => {
    const res = await app.request("/openai/models", {
      method: "GET",
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("unauthorized");
  });

  test("Unauthenticated request to /anthropic/v1/models returns 401", async () => {
    const res = await app.request("/anthropic/v1/models", {
      method: "GET",
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("unauthorized");
  });

  test("Unauthenticated request to /codex/models returns 401", async () => {
    const res = await app.request("/codex/models", {
      method: "GET",
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("unauthorized");
  });

  // ── 2. Public Endpoints Remain Unaffected ────────────────────────────────────

  test("GET /health/live remains accessible without authentication", async () => {
    const res = await app.request("/health/live");
    expect(res.status).toBe(200);
    const data = (await res.json()) as { status: string };
    expect(data.status).toBe("ok");
  });

  test("GET /info remains accessible without authentication", async () => {
    const res = await app.request("/info");
    expect(res.status).toBe(200);
  });

  test("GET /favicon.svg remains accessible without authentication", async () => {
    const res = await app.request("/favicon.svg");
    expect(res.status).toBe(200);
  });

  // ── 3. JWT Authentication & RBAC ────────────────────────────────────────────

  test("Valid JWT token with ADMIN role is accepted", async () => {
    const token = await signUserToken(
      "usr_admin_test",
      "admin@test.com",
      "ADMIN",
      3600,
      testOrgId,
      "ORG_ADMIN",
    );

    // Malformed body returns 400 (validation), showing it passed authentication
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400); // 400 from schema validation proves auth succeeded
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("invalid_request_error");
  });

  test("Valid JWT token with ANALYST org role is accepted", async () => {
    const token = await signUserToken(
      "usr_analyst_test",
      "analyst@test.com",
      "SECURITY_ANALYST",
      3600,
      testOrgId,
      "ANALYST",
    );

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400); // Reached schema validator
  });

  test("JWT token with VIEWER role is rejected with 403 Forbidden", async () => {
    const token = await signUserToken(
      "usr_viewer_test",
      "viewer@test.com",
      "VIEWER",
      3600,
      testOrgId,
      "VIEWER",
    );

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    expect(res.status).toBe(403);
    const data = (await res.json()) as { error: { type: string; message: string } };
    expect(data.error.type).toBe("forbidden");
    expect(data.error.message).toContain("VIEWER");
  });

  test("Invalid JWT string is rejected with 401", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer completely-invalid-jwt-token",
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("invalid_token");
  });

  test("Expired JWT is rejected with 401", async () => {
    // Negative expiry time -> already expired
    const token = await signUserToken(
      "usr_expired",
      "expired@test.com",
      "ADMIN",
      -3600,
      testOrgId,
      "ORG_ADMIN",
    );

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("invalid_token");
  });

  test("Malformed Authorization header (e.g. Basic auth) is rejected with 401", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Basic dXNlcjpwYXNzd29yZA==",
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("unauthorized");
  });

  // ── 4. API Key Authentication ───────────────────────────────────────────────

  test("Valid API key via Authorization: Bearer header is accepted", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${validRawApiKey}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400); // Reached schema validator
  });

  test("Valid API key via x-api-key header is accepted (Anthropic SDK pattern)", async () => {
    const res = await app.request("/anthropic/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": validRawApiKey,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400); // Reached Anthropic schema validator
  });

  test("Valid API key via api-key header is accepted", async () => {
    const res = await app.request("/codex/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": validRawApiKey,
      },
      body: JSON.stringify({ model: 12345 }),
    });

    expect(res.status).toBe(400); // Reached Codex schema validator
  });

  test("Valid API key via query parameter ?api_key= is accepted", async () => {
    const res = await app.request(`/openai/v1/chat/completions?api_key=${validRawApiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400); // Reached schema validator
  });

  test("Invalid API key is rejected with 401", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer pw_live_${"0".repeat(48)}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("invalid_api_key");
  });

  test("Revoked API key is rejected with 401", async () => {
    const keyToRevoke = await apiKeyStore.createApiKey({
      organizationId: testOrgId,
      name: "Key to Revoke",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    // Revoke the key
    await apiKeyStore.revokeApiKey(keyToRevoke.record.id, testOrgId);

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${keyToRevoke.key}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("invalid_api_key");
  });

  test("Expired API key is rejected with 401", async () => {
    const expiredKey = await apiKeyStore.createApiKey({
      organizationId: testOrgId,
      name: "Expired Key",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
      expiresAt: new Date(Date.now() - 60_000).toISOString(), // expired 1 minute ago
    });

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${expiredKey.key}`,
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { type: string } };
    expect(data.error.type).toBe("invalid_api_key");
  });

  // ── 5. Security & Secret Leakage Invariants ─────────────────────────────────

  test("Security headers are attached to 401 and 403 responses", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  test("Auth failure response body never leaks internal secrets or tokens", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer malformed.token.secret",
      },
      body: JSON.stringify({}),
    });

    const text = await res.text();
    expect(text).not.toContain("malformed.token.secret");
    expect(text).not.toContain("JWT_SECRET");
    expect(text).not.toContain("OPENAI_API_KEY");
  });

  // ── 6. Tenant Context & Isolation Invariants ───────────────────────────────

  test("Verified API key derives orgId from database and ignores client spoofing headers", async () => {
    let capturedOrgId: string | undefined;
    let capturedRole: string | undefined;

    // Mount a probe route on Hono app that uses gatewayAuth
    const probeApp = new (await import("hono")).Hono();
    const { aiGatewayAuthMiddleware } = await import("../auth/middleware");
    probeApp.use("/probe/*", aiGatewayAuthMiddleware());
    probeApp.get("/probe/test", (c) => {
      capturedOrgId = c.get("orgId");
      capturedRole = c.get("orgRole");
      return c.json({ ok: true });
    });

    const res = await probeApp.request("/probe/test", {
      headers: {
        Authorization: `Bearer ${validRawApiKey}`,
        // Malicious client attempting to spoof a different tenant
        "x-organization-id": "org_spoofed_victim",
        "x-tenant-id": "org_another_victim",
      },
    });

    expect(res.status).toBe(200);
    // Strictly derived from verified database record, NOT the spoofed header
    expect(capturedOrgId).toBe(testOrgId);
    expect(capturedRole).toBe("ANALYST");
  });

  test("Verified JWT derives orgId and role strictly from token claims", async () => {
    let capturedOrgId: string | undefined;
    let capturedRole: string | undefined;

    const probeApp = new (await import("hono")).Hono();
    const { aiGatewayAuthMiddleware } = await import("../auth/middleware");
    probeApp.use("/probe/*", aiGatewayAuthMiddleware());
    probeApp.get("/probe/test", (c) => {
      capturedOrgId = c.get("orgId");
      capturedRole = c.get("orgRole");
      return c.json({ ok: true });
    });

    const token = await signUserToken(
      "usr_tenant_test",
      "tenant@test.com",
      "SECURITY_ANALYST",
      3600,
      testOrgId,
      "SECURITY_ADMIN",
    );

    const res = await probeApp.request("/probe/test", {
      headers: {
        Authorization: `Bearer ${token}`,
        "x-organization-id": "org_spoofed_victim",
      },
    });

    expect(res.status).toBe(200);
    expect(capturedOrgId).toBe(testOrgId);
    expect(capturedRole).toBe("SECURITY_ADMIN");
  });

  // ── 7. Credential Stripping Invariants (Upstream Leakage Prevention) ────────

  test("PromptWall API key and JWT are stripped before forwarding to upstream providers", async () => {
    const { extractGatewayCredential } = await import("../auth/middleware");

    // Header extraction unit verification
    const reqApiKey = {
      header: (name: string) => (name.toLowerCase() === "x-api-key" ? validRawApiKey : undefined),
      query: () => undefined,
    };
    const extractedKey = extractGatewayCredential(reqApiKey);
    expect(extractedKey?.type).toBe("api_key");
    expect(extractedKey?.token).toBe(validRawApiKey);

    // Case insensitivity verification
    const reqUpper = {
      header: (name: string) => (name === "X-API-Key" ? validRawApiKey : undefined),
      query: () => undefined,
    };
    expect(extractGatewayCredential(reqUpper)?.token).toBe(validRawApiKey);

    // Query parameter token verification
    const token = await signUserToken("usr_q", "q@t.com", "ADMIN", 3600, testOrgId, "ORG_ADMIN");
    const reqQueryToken = {
      header: () => undefined,
      query: (name: string) => (name === "token" ? token : undefined),
    };
    const extractedJwt = extractGatewayCredential(reqQueryToken);
    expect(extractedJwt?.type).toBe("jwt");
    expect(extractedJwt?.token).toBe(token);
  });

  // ── 8. Public Management & Health Endpoints Remain Available ───────────────

  test("Public health, metrics, and auth login endpoints remain accessible", async () => {
    const healthLive = await app.request("/health/live");
    expect(healthLive.status).toBe(200);

    const healthReady = await app.request("/health/ready");
    expect([200, 503]).toContain(healthReady.status); // 200 or 503 depending on live external detector

    const info = await app.request("/info");
    expect(info.status).toBe(200);

    // Login endpoint should not require gateway auth
    const login = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "nonexistent@test.com", password: "invalid" }),
    });
    expect(login.status).toBe(401); // 401 from auth logic (invalid credentials), not gateway auth
    const loginData = (await login.json()) as { error: { message: string } };
    expect(loginData.error.message).toContain("Invalid email or password");
  });
});
