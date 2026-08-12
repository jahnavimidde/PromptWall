/**
 * @file jwt.ts
 * @module src/auth
 *
 * JWT Token signing & verification utilities (M7B).
 */

import { sign, verify } from "hono/jwt";
import type { Role } from "./permissions";

const DEFAULT_JWT_SECRET = "promptwall-enterprise-jwt-secret-key-change-in-prod";

export interface JwtUserPayload {
  sub: string;
  email: string;
  role: Role;
  exp: number;
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
): Promise<string> {
  const secret = getJwtSecret();
  const payload = {
    sub: userId,
    email,
    role,
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
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
    if (!payload || !payload.sub || !payload.role) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}
