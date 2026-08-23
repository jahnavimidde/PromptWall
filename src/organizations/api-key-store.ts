/**
 * @file api-key-store.ts
 * @module src/organizations
 *
 * API key management for tenant organizations (M12D).
 *
 * ── Security invariants ───────────────────────────────────────────────────────
 * 1. Plaintext keys are generated once and returned to the caller.
 *    They are NEVER stored in the database.
 * 2. Only the SHA-256 hex digest (key_hash) is persisted.
 * 3. List operations never return key_hash — only id, name, key_prefix,
 *    permissions, last_used_at, expires_at, created_at.
 * 4. All queries are scoped by organization_id — no cross-tenant access.
 */

import { createHash, randomBytes } from "node:crypto";
import type { OrgPermission } from "../auth/permissions";
import { getConfig } from "../config";
import { createLogDatabase, type LogKysely, migrateLogDatabase } from "../logging/db";

// ── Types ─────────────────────────────────────────────────────────────────────

/** Public representation of an API key — key_hash is never included. */
export interface StoredApiKey {
  id: string;
  organizationId: string;
  name: string;
  /** First 16 chars of the raw key for display (e.g. "pw_live_a1b2c3d4") */
  keyPrefix: string;
  permissions: OrgPermission[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  createdBy: string;
  createdAt: string;
}

export interface CreateApiKeyInput {
  organizationId: string;
  name: string;
  permissions: OrgPermission[];
  createdBy: string;
  /** ISO-8601 expiry datetime. Omit for non-expiring keys. */
  expiresAt?: string;
}

/** Returned only from createApiKey — the raw key is shown exactly once. */
export interface CreatedApiKeyResult {
  /** Raw key shown to the caller ONCE. Never stored. */
  key: string;
  record: StoredApiKey;
}

// ── Singleton (mirrors UserStore / OrgStore pattern) ─────────────────────────

let defaultDbInstance: LogKysely | null = null;
let defaultDbReady: Promise<void> | null = null;

function getDb(customDb?: LogKysely): { db: LogKysely; ready: Promise<void> } {
  if (customDb) {
    return { db: customDb, ready: Promise.resolve() };
  }
  if (!defaultDbInstance) {
    const config = getConfig();
    const { db, driver } = createLogDatabase(config);
    defaultDbInstance = db;
    defaultDbReady = migrateLogDatabase(db, driver);
  }
  return { db: defaultDbInstance, ready: defaultDbReady! };
}

// ── Key generation ────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically secure API key.
 * Format: pw_live_<48 hex chars> (total 56 chars).
 *
 * @returns { rawKey, keyHash, keyPrefix }
 */
function generateApiKey(): { rawKey: string; keyHash: string; keyPrefix: string } {
  const rawKey = `pw_live_${randomBytes(24).toString("hex")}`;
  const keyHash = createHash("sha256").update(rawKey).digest("hex");
  const keyPrefix = rawKey.slice(0, 16); // "pw_live_XXXXXXXX"
  return { rawKey, keyHash, keyPrefix };
}

/**
 * Hash a raw API key for lookup.
 */
export function hashApiKey(rawKey: string): string {
  return createHash("sha256").update(rawKey).digest("hex");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function rowToStoredApiKey(row: {
  id: string;
  organization_id: string;
  name: string;
  key_prefix: string;
  permissions: string;
  last_used_at: string | null;
  expires_at: string | null;
  created_by: string;
  created_at: string | null;
}): StoredApiKey {
  let permissions: OrgPermission[] = [];
  try {
    permissions = JSON.parse(row.permissions) as OrgPermission[];
  } catch {
    // Malformed JSON — treat as empty
  }

  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    keyPrefix: row.key_prefix,
    permissions,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
    createdBy: row.created_by,
    createdAt: row.created_at ?? new Date().toISOString(),
  };
}

// ── ApiKeyStore ───────────────────────────────────────────────────────────────

export class ApiKeyStore {
  private readonly db: LogKysely;
  private readonly ready: Promise<void>;

  constructor(options: { db?: LogKysely } = {}) {
    const { db, ready } = getDb(options.db);
    this.db = db;
    this.ready = ready;
  }

  /**
   * Create a new API key for the given organization.
   *
   * Returns { key, record } where `key` is the plaintext key shown ONCE.
   * The raw key is not stored — only its SHA-256 hash is persisted.
   */
  async createApiKey(input: CreateApiKeyInput): Promise<CreatedApiKeyResult> {
    await this.ready;

    const { rawKey, keyHash, keyPrefix } = generateApiKey();
    const id = `key_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const now = new Date().toISOString();

    await this.db
      .insertInto("api_keys")
      .values({
        id,
        organization_id: input.organizationId,
        name: input.name,
        key_hash: keyHash,
        key_prefix: keyPrefix,
        permissions: JSON.stringify(input.permissions),
        last_used_at: null,
        expires_at: input.expiresAt ?? null,
        created_by: input.createdBy,
        created_at: now,
      })
      .execute();

    const record: StoredApiKey = {
      id,
      organizationId: input.organizationId,
      name: input.name,
      keyPrefix,
      permissions: input.permissions,
      lastUsedAt: null,
      expiresAt: input.expiresAt ?? null,
      createdBy: input.createdBy,
      createdAt: now,
    };

    return { key: rawKey, record };
  }

  /**
   * Verify an incoming raw API key.
   *
   * Hashes the raw key and looks up the hash in the database.
   * Returns the key record if found and not expired, null otherwise.
   * Automatically updates `last_used_at` on successful verification (fire-and-forget).
   */
  async verifyApiKey(rawKey: string): Promise<StoredApiKey | null> {
    await this.ready;

    const keyHash = hashApiKey(rawKey);

    const row = await this.db
      .selectFrom("api_keys")
      .selectAll()
      .where("key_hash", "=", keyHash)
      .executeTakeFirst();

    if (!row) return null;

    // Check expiry
    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return null;
    }

    // Fire-and-forget: update last_used_at
    this.updateLastUsed(row.id).catch(() => {});

    return rowToStoredApiKey(row);
  }

  /**
   * List all API keys for an organization.
   *
   * Security: key_hash is excluded from the SELECT — it is never returned.
   * Only keyPrefix is exposed for display purposes.
   */
  async listApiKeys(organizationId: string): Promise<StoredApiKey[]> {
    await this.ready;

    const rows = await this.db
      .selectFrom("api_keys")
      .select([
        "id",
        "organization_id",
        "name",
        "key_prefix",
        "permissions",
        "last_used_at",
        "expires_at",
        "created_by",
        "created_at",
      ])
      .where("organization_id", "=", organizationId)
      .orderBy("created_at", "desc")
      .execute();

    return rows.map(rowToStoredApiKey);
  }

  /**
   * Revoke (hard-delete) an API key by id.
   * Scoped to the organization — cannot revoke keys from other orgs.
   */
  async revokeApiKey(id: string, organizationId: string): Promise<void> {
    await this.ready;

    await this.db
      .deleteFrom("api_keys")
      .where("id", "=", id)
      .where("organization_id", "=", organizationId)
      .execute();
  }

  /**
   * Update the last_used_at timestamp for a key.
   * Internal helper — not exposed via the public API.
   */
  async updateLastUsed(id: string): Promise<void> {
    await this.ready;

    await this.db
      .updateTable("api_keys")
      .set({ last_used_at: new Date().toISOString() })
      .where("id", "=", id)
      .execute();
  }
}
