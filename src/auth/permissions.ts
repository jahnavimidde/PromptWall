/**
 * @file permissions.ts
 * @module src/auth
 *
 * Centralized Role-Based Access Control (RBAC) definitions (M7B).
 * Defines enterprise roles (ADMIN, SECURITY_ANALYST, VIEWER) and permission checks.
 */

export type Role = "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export type Permission =
  | "policies:manage"
  | "audit:cleanup"
  | "users:manage"
  | "audit:export"
  | "audit:read"
  | "dashboard:read";

const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  ADMIN: [
    "policies:manage",
    "audit:cleanup",
    "users:manage",
    "audit:export",
    "audit:read",
    "dashboard:read",
  ],
  SECURITY_ANALYST: [
    "audit:export",
    "audit:read",
    "dashboard:read",
  ],
  VIEWER: [
    "audit:read",
    "dashboard:read",
  ],
};

/**
 * Check if a role possesses a specific permission.
 */
export function hasPermission(role: Role, permission: Permission): boolean {
  const allowed = ROLE_PERMISSIONS[role];
  return allowed ? allowed.includes(permission) : false;
}

/**
 * Validate whether a string is a valid Role.
 */
export function isValidRole(role: string): role is Role {
  return role === "ADMIN" || role === "SECURITY_ANALYST" || role === "VIEWER";
}
