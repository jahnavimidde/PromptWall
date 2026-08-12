/**
 * @file middleware.ts
 * @module src/auth
 *
 * Authentication & RBAC middleware for Hono routes (M7B).
 */

import type { MiddlewareHandler } from "hono";
import type { JwtUserPayload } from "./jwt";
import { verifyUserToken } from "./jwt";
import type { Role } from "./permissions";

declare module "hono" {
  interface ContextVariableMap {
    user?: JwtUserPayload;
  }
}

/**
 * Extract Bearer token from Authorization header or query parameter.
 */
function extractToken(req: { header: (name: string) => string | undefined; query: (name: string) => string | undefined }): string | null {
  const authHeader = req.header("Authorization") || req.header("authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
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
