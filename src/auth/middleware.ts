/**
 * @file middleware.ts
 * @module src/auth
 *
 * Authentication & RBAC middleware for Hono routes (M7B).
 */

import type { MiddlewareHandler } from "hono";
import type { JwtUserPayload } from "./jwt";
import { verifyUserToken } from "./jwt";
import type { OrgPermission, OrgRole, Role } from "./permissions";
import { hasOrgPermission } from "./permissions";

declare module "hono" {
  interface ContextVariableMap {
    user?: JwtUserPayload;
    /** M12: resolved organization id from JWT or API key context */
    orgId?: string;
    /** M12: caller's org-scoped role for the current request */
    orgRole?: OrgRole;
  }
}

/**
 * Extract Bearer token from Authorization header or query parameter.
 */
function extractToken(req: {
  header: (name: string) => string | undefined;
  query: (name: string) => string | undefined;
}): string | null {
  const authHeader = req.header("Authorization") || req.header("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  const tokenQuery = req.query("token");
  if (tokenQuery) {
    return tokenQuery.trim();
  }
  return null;
}

/**
 * Enforce valid JWT authentication on routes.
 * Sets `c.var.user` on success, or returns HTTP 401 Unauthorized.
 */
export const authMiddleware: MiddlewareHandler = async (c, next) => {
  const token = extractToken(c.req);
  if (!token) {
    return c.json(
      {
        error: {
          message: "Authentication required. Missing Bearer token in Authorization header.",
          type: "unauthorized",
        },
      },
      401,
    );
  }

  const payload = await verifyUserToken(token);
  if (!payload) {
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

  c.set("user", payload);
  await next();
};

/**
 * Optional authentication middleware.
 * Attaches user to Context if valid token is provided, but allows request to proceed if absent.
 */
export const optionalAuthMiddleware: MiddlewareHandler = async (c, next) => {
  const token = extractToken(c.req);
  if (token) {
    const payload = await verifyUserToken(token);
    if (payload) {
      c.set("user", payload);
    }
  }
  await next();
};

/**
 * Enforce Role-Based Access Control (RBAC) permissions.
 *
 * @param allowedRoles - List of acceptable roles (e.g. `["ADMIN"]` or `["ADMIN", "SECURITY_ANALYST"]`).
 */
export function requireRole(allowedRoles: Role[]): MiddlewareHandler {
  return async (c, next) => {
    const user = c.get("user") as JwtUserPayload | undefined;

    if (!user) {
      return c.json(
        {
          error: {
            message: "Authentication required.",
            type: "unauthorized",
          },
        },
        401,
      );
    }

    if (!allowedRoles.includes(user.role)) {
      return c.json(
        {
          error: {
            message: `Forbidden. Role '${user.role}' is not authorized to access this resource. Requires one of: ${allowedRoles.join(", ")}`,
            type: "forbidden",
          },
        },
        403,
      );
    }

    await next();
  };
}

// ── M12: Organization-Scoped Middleware ──────────────────────────────────────────

/**
 * Enforce org-scoped RBAC.
 *
 * Prerequisites: run after `authMiddleware`.
 *
 * Behaviour:
 * - Global ADMIN bypasses org-role check (cross-org superadmin access).
 * - Otherwise validates that the JWT `orgRole` is in `allowedOrgRoles`.
 * - Injects `c.var.orgId` and `c.var.orgRole` for downstream handlers.
 *
 * @param allowedOrgRoles - Required org roles. Empty list → any org member passes.
 */
export function requireOrgRole(allowedOrgRoles: OrgRole[]): MiddlewareHandler {
  return async (c, next) => {
    const user = c.get("user") as JwtUserPayload | undefined;

    if (!user) {
      return c.json({ error: { message: "Authentication required.", type: "unauthorized" } }, 401);
    }

    // Global ADMIN is superadmin — always allowed regardless of org role
    if (user.role === "ADMIN") {
      c.set("orgId", user.organizationId ?? "org_system");
      c.set("orgRole", (user.orgRole ?? "ORG_ADMIN") as OrgRole);
      await next();
      return;
    }

    if (!user.organizationId) {
      return c.json(
        { error: { message: "No organization associated with this account.", type: "forbidden" } },
        403,
      );
    }

    if (!user.orgRole) {
      return c.json(
        { error: { message: "No organization role assigned.", type: "forbidden" } },
        403,
      );
    }

    if (allowedOrgRoles.length > 0 && !allowedOrgRoles.includes(user.orgRole as OrgRole)) {
      return c.json(
        {
          error: {
            message: `Forbidden. Org role '${user.orgRole}' is not authorized. Requires one of: ${allowedOrgRoles.join(", ")}`,
            type: "forbidden",
          },
        },
        403,
      );
    }

    c.set("orgId", user.organizationId);
    c.set("orgRole", user.orgRole as OrgRole);
    await next();
  };
}

/**
 * Require a specific org-level permission.
 * Global ADMIN always passes.
 *
 * Must run after `authMiddleware` + `requireOrgRole`.
 */
export function requireOrgPermission(permission: OrgPermission): MiddlewareHandler {
  return async (c, next) => {
    const user = c.get("user") as JwtUserPayload | undefined;

    if (user?.role === "ADMIN") {
      await next();
      return;
    }

    const orgRole = c.get("orgRole") as OrgRole | undefined;
    if (!orgRole || !hasOrgPermission(orgRole, permission)) {
      return c.json(
        {
          error: {
            message: `Forbidden. Missing permission: ${permission}`,
            type: "forbidden",
          },
        },
        403,
      );
    }

    await next();
  };
}
