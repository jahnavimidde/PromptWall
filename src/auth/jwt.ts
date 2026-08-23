/**
 * @file jwt.ts
 * @module src/auth
 *
 * JWT Token signing & verification utilities (M7B).
 */

import { sign, verify } from "hono/jwt";
import type { OrgRole, Role } from "./permissions";

const DEFAULT_JWT_SECRET = "promptwall-enterprise-jwt-secret-key-change-in-prod";

export interface JwtUserPayload {
  sub: string;
  email: string;
  role: Role;
  exp: number;
  /** M12: tenant org the user belongs to. Absent for legacy/system tokens. */
  organizationId?: string;
  /** M12: org-scoped role within the user's organization. */
  orgRole?: OrgRole;
  /** Allow arbitrary additional JWT claims (required by hono/jwt JWTPayload) */
  [key: string]: unknown;
}

function getJwtSecret(): string {
  return process.env.JWT_SECRET || process.env.PROMPTWALL_JWT_SECRET || DEFAULT_JWT_SECRET;
}

/**
 * Sign a new JWT token for a user. Expires in 24 hours by default.
 */
export async function signUserToken(
  userId: string,
  email: string,
  role: Role,
  expiresInSeconds = 24 * 60 * 60,
  organizationId?: string,
  orgRole?: OrgRole,
): Promise<string> {
  const secret = getJwtSecret();
  const payload: JwtUserPayload = {
    sub: userId,
    email,
    role,
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
    ...(organizationId ? { organizationId } : {}),
    ...(orgRole ? { orgRole } : {}),
  };
  return await sign(payload, secret, "HS256");
}

/**
 * Verify and decode a JWT token string.
 */
export async function verifyUserToken(token: string): Promise<JwtUserPayload | null> {
  try {
    const secret = getJwtSecret();
    const payload = (await verify(token, secret, "HS256")) as unknown as JwtUserPayload;
    if (!payload?.sub || !payload.role) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}
