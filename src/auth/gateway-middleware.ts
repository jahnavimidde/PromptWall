/**
 * @file gateway-middleware.ts
 * @module src/auth
 *
 * Authentication & Tenant Isolation middleware for AI Gateway endpoints (M14).
 * Protects /openai/*, /anthropic/*, /codex/* from unauthenticated access.
 *
 * Supported credential formats:
 * - API keys (pw_live_...) via Authorization: Bearer, x-api-key, api-key, or query param
 * - JWT tokens via Authorization: Bearer or query param
 *
 * Security invariants:
 * 1. Derives tenant organization ID strictly from verified credentials (never client headers).
 * 2. Rejects unauthenticated requests with HTTP 401.
 * 3. Rejects invalid, revoked, or expired credentials with HTTP 401.
 * 4. Rejects callers with unauthorized roles (e.g. VIEWER) with HTTP 403.
 * 5. Never exposes API keys, JWT secrets, or raw Authorization headers in logs or responses.
 */

import type { Context, MiddlewareHandler } from "hono";
import { logRequest } from "../logging/logger";
import { ApiKeyStore, type StoredApiKey } from "../organizations/api-key-store";
import { createLogData } from "../routes/utils";
import { type JwtUserPayload, verifyUserToken } from "./jwt";
import type { OrgRole, Role } from "./permissions";

declare module "hono" {
  interface ContextVariableMap {
    user?: JwtUserPayload;
    /** M12/M14: resolved organization id from verified JWT or API key context */
    orgId?: string;
    /** M12/M14: caller's org-scoped role for the current request */
    orgRole?: OrgRole;
    /** M14: verified API key record if authenticated via API key */
    apiKey?: StoredApiKey;
  }
}

export interface GatewayAuthOptions {
  /** Optional custom ApiKeyStore instance (used for test dependency injection) */
  apiKeyStore?: ApiKeyStore;
  /** Allowed organization roles. Default: ORG_ADMIN, SECURITY_ADMIN, ANALYST */
  allowedOrgRoles?: OrgRole[];
  /** Allowed global roles. Default: ADMIN, SECURITY_ANALYST */
  allowedGlobalRoles?: Role[];
}

export type ExtractedCredential = {
  token: string;
  type: "api_key" | "jwt";
};

/**
 * Extract credential token from incoming request headers or query params.
 */
export function extractGatewayCredential(req: {
  header: (name: string) => string | undefined;
  query: (name: string) => string | undefined;
}): ExtractedCredential | null {
  // 1. Check dedicated API key headers (x-api-key, api-key)
  const xApiKey =
    req.header("x-api-key") ||
    req.header("X-API-Key") ||
    req.header("api-key") ||
    req.header("API-Key");
  if (xApiKey?.trim()) {
    return { token: xApiKey.trim(), type: "api_key" };
  }

  // 2. Check Authorization header (Bearer <token_or_key>)
  const authHeader = req.header("Authorization") || req.header("authorization");
  if (authHeader) {
    const trimmed = authHeader.trim();
    if (trimmed.toLowerCase().startsWith("bearer ")) {
      const val = trimmed.slice(7).trim();
      if (val) {
        if (val.startsWith("pw_live_")) {
          return { token: val, type: "api_key" };
        }
        return { token: val, type: "jwt" };
      }
    }
  }

  // 3. Check query parameters (for SSE streams or webhooks)
  const apiKeyQuery = req.query("api_key");
  if (apiKeyQuery?.trim()) {
    return { token: apiKeyQuery.trim(), type: "api_key" };
  }

  const tokenQuery = req.query("token");
  if (tokenQuery?.trim()) {
    const val = tokenQuery.trim();
    if (val.startsWith("pw_live_")) {
      return { token: val, type: "api_key" };
    }
    return { token: val, type: "jwt" };
  }

  return null;
}

/**
 * Safe audit log for authentication failures — NEVER logs raw credentials.
 */
function logAuthFailure(c: Context, statusCode: number, reason: string): void {
  try {
    logRequest(
      createLogData({
        provider: "api",
        model: "ai-gateway-auth",
        startTime: Date.now(),
        statusCode,
        errorMessage: `Authentication failure: ${reason}`,
      }),
      c.req.header("User-Agent") || null,
    );
  } catch {
    // Non-blocking
  }
}

/**
 * AI Gateway Authentication Middleware.
 * Enforces authentication and tenant isolation on provider routes.
 */
export function aiGatewayAuthMiddleware(options: GatewayAuthOptions = {}): MiddlewareHandler {
  const defaultStore = options.apiKeyStore ?? new ApiKeyStore();
  const allowedGlobal = options.allowedGlobalRoles ?? ["ADMIN", "SECURITY_ANALYST"];
  const allowedOrg = options.allowedOrgRoles ?? ["ORG_ADMIN", "SECURITY_ADMIN", "ANALYST"];

  return async (c, next) => {
    const cred = extractGatewayCredential(c.req);

    if (!cred) {
      logAuthFailure(c, 401, "missing_credentials");
      return c.json(
        {
          error: {
            message:
              "Authentication required. Provide a valid API key or Bearer token in request headers.",
            type: "unauthorized",
          },
        },
        401,
      );
    }

    if (cred.type === "api_key") {
      try {
        const apiKeyRecord = await defaultStore.verifyApiKey(cred.token);

        if (!apiKeyRecord) {
          logAuthFailure(c, 401, "invalid_or_expired_api_key");
          return c.json(
            {
              error: {
                message: "Invalid, revoked, or expired API key.",
                type: "invalid_api_key",
              },
            },
            401,
          );
        }

        // Enforce tenant context strictly from verified database record
        c.set("orgId", apiKeyRecord.organizationId);
        c.set("apiKey", apiKeyRecord);
        c.set("orgRole", "ANALYST");
        c.set("user", {
          sub: apiKeyRecord.id,
          email: `${apiKeyRecord.name}@apikey.local`,
          role: "SECURITY_ANALYST",
          organizationId: apiKeyRecord.organizationId,
          orgRole: "ANALYST",
          exp: apiKeyRecord.expiresAt
            ? Math.floor(new Date(apiKeyRecord.expiresAt).getTime() / 1000)
            : 0,
        });

        await next();
        return;
      } catch (_err) {
        logAuthFailure(c, 500, "api_key_verification_error");
        return c.json(
          {
            error: {
              message: "Internal authentication error.",
              type: "internal_error",
            },
          },
          500,
        );
      }
    }

    // JWT verification path
    const payload = await verifyUserToken(cred.token);
    if (!payload) {
      logAuthFailure(c, 401, "invalid_or_expired_jwt");
      return c.json(
        {
          error: {
            message: "Invalid or expired authentication token.",
            type: "invalid_token",
          },
        },
        401,
      );
    }

    // RBAC Authorization check
    // Global ADMIN always bypasses role restrictions
    if (payload.role !== "ADMIN") {
      if (payload.orgRole && !allowedOrg.includes(payload.orgRole)) {
        logAuthFailure(c, 403, `insufficient_org_role:${payload.orgRole}`);
        return c.json(
          {
            error: {
              message: `Forbidden. Role '${payload.orgRole}' is not authorized to invoke AI gateway models.`,
              type: "forbidden",
            },
          },
          403,
        );
      }

      if (!allowedGlobal.includes(payload.role) && !payload.orgRole) {
        logAuthFailure(c, 403, `insufficient_global_role:${payload.role}`);
        return c.json(
          {
            error: {
              message: `Forbidden. Role '${payload.role}' is not authorized to invoke AI gateway models.`,
              type: "forbidden",
            },
          },
          403,
        );
      }
    }

    // Derive tenant identity strictly from verified token
    c.set("user", payload);
    c.set("orgId", payload.organizationId ?? "org_system");
    if (payload.orgRole) {
      c.set("orgRole", payload.orgRole);
    }

    await next();
  };
}
