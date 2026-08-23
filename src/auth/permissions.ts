/**
 * @file permissions.ts
 * @module src/auth
 *
 * Centralized Role-Based Access Control (RBAC) definitions (M7B).
 * Defines enterprise roles (ADMIN, SECURITY_ANALYST, VIEWER) and permission checks.
 *
 * M12: Extended with organization-scoped roles (OrgRole) and permissions (OrgPermission).
 * Global roles are unchanged — OrgRole applies within a tenant boundary.
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
  SECURITY_ANALYST: ["audit:export", "audit:read", "dashboard:read"],
  VIEWER: ["audit:read", "dashboard:read"],
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

// ── M12: Organization-Scoped RBAC ───────────────────────────────────────────────

/**
 * Organization-scoped role. Applies within a single tenant boundary.
 * Global `ADMIN` role retains cross-org superadmin access regardless of OrgRole.
 */
export type OrgRole = "ORG_ADMIN" | "SECURITY_ADMIN" | "ANALYST" | "VIEWER";

/**
 * Permissions that apply within an organization's boundary.
 */
export type OrgPermission =
  | "org:manage" // rename org, update settings
  | "org:members:manage" // invite / remove users from the org
  | "org:policies:manage" // create / edit / delete org-scoped policies
  | "org:policies:read" // list and view org-scoped policies
  | "org:audit:read" // view org-scoped audit events
  | "org:audit:export" // export org audit CSV / JSON
  | "org:apikeys:manage" // create / revoke org API keys
  | "org:usage:read"; // view org usage analytics

const ORG_ROLE_PERMISSIONS: Record<OrgRole, readonly OrgPermission[]> = {
  ORG_ADMIN: [
    "org:manage",
    "org:members:manage",
    "org:policies:manage",
    "org:policies:read",
    "org:audit:read",
    "org:audit:export",
    "org:apikeys:manage",
    "org:usage:read",
  ],
  SECURITY_ADMIN: [
    "org:policies:manage",
    "org:policies:read",
    "org:audit:read",
    "org:audit:export",
    "org:apikeys:manage",
    "org:usage:read",
  ],
  ANALYST: ["org:policies:read", "org:audit:read", "org:usage:read"],
  VIEWER: ["org:usage:read"],
};

/**
 * Check if an org-scoped role possesses a specific org permission.
 */
export function hasOrgPermission(orgRole: OrgRole, permission: OrgPermission): boolean {
  const allowed = ORG_ROLE_PERMISSIONS[orgRole];
  return allowed ? allowed.includes(permission) : false;
}

/**
 * Validate whether a string is a valid OrgRole.
 */
export function isValidOrgRole(role: string): role is OrgRole {
  return (
    role === "ORG_ADMIN" || role === "SECURITY_ADMIN" || role === "ANALYST" || role === "VIEWER"
  );
}
