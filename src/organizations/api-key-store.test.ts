/**
 * @file api-key-store.test.ts
 * @module src/organizations
 *
 * Unit tests for ApiKeyStore (M12D).
 *
 * Verifies the core security invariants:
 * - Raw key is returned once and only once (at creation)
 * - key_hash is never returned from list operations
 * - Verify round-trips correctly via SHA-256
 * - Expired keys are rejected by verifyApiKey
 * - Cross-org revocation is rejected
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { ApiKeyStore, hashApiKey } from "./api-key-store";

// ── In-memory SQLite helper ───────────────────────────────────────────────────

class BunSqliteDatabase implements SqliteDatabase {
  constructor(private readonly db: Database) {}
  close() {
    this.db.close();
  }
  prepare(query: string): SqliteStatement {
    const statement = this.db.prepare<unknown, SQLQueryBindings[]>(query);
    const reader = /^(select|pragma|with)\b/i.test(query.trim());
    return {
      get reader() {
        return reader;
      },
      all: (params: ReadonlyArray<unknown>) => statement.all(...(params as SQLQueryBindings[])),
      run: (params: ReadonlyArray<unknown>) => {
        const r = statement.run(...(params as SQLQueryBindings[]));
        return { changes: r.changes, lastInsertRowid: r.lastInsertRowid };
      },
      iterate: (params: ReadonlyArray<unknown>) =>
        statement.iterate(...(params as SQLQueryBindings[])),
    };
  }
}

async function createInMemoryDb(): Promise<Kysely<LogDatabase>> {
  const db = new Kysely<LogDatabase>({
    dialect: new SqliteDialect({
      database: new BunSqliteDatabase(new Database(":memory:")),
    }),
  });
  await migrateLogDatabase(db, "sqlite");
  return db;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("ApiKeyStore", () => {
  let db: Kysely<LogDatabase>;
  let store: ApiKeyStore;
  const orgId = "org_test123";

  beforeEach(async () => {
    db = await createInMemoryDb();
    store = new ApiKeyStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("createApiKey returns raw key and record", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "CI/CD Key",
      permissions: ["org:audit:read"],
      createdBy: "usr_admin",
    });

    expect(result.key).toMatch(/^pw_live_/);
    expect(result.key).toHaveLength(56); // "pw_live_" (8) + 48 hex chars
    expect(result.record.id).toMatch(/^key_/);
    expect(result.record.organizationId).toBe(orgId);
    expect(result.record.name).toBe("CI/CD Key");
    expect(result.record.permissions).toEqual(["org:audit:read"]);
  });

  test("security: raw key is not stored in the database", async () => {
    const result = await store.createApiKey({
      organizationId: orgId,
      name: "Stored Check",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    // Directly check the DB row — key_hash must differ from the raw key
    const row = await db
      .selectFrom("api_keys")
      .selectAll()
      .where("id", "=", result.record.id)
      .executeTakeFirst();

    expect(row).toBeDefined();
    expect(row!.key_hash).not.toBe(result.key);
    // key_hash should be the SHA-256 of the raw key
    const expectedHash = createHash("sha256").update(result.key).digest("hex");
    expect(row!.key_hash).toBe(expectedHash);
  });

  test("hashApiKey helper produces correct SHA-256", () => {
    const raw = "pw_live_testkey123456789012345678901234567890";
    const hash = hashApiKey(raw);
    const expected = createHash("sha256").update(raw).digest("hex");
    expect(hash).toBe(expected);
  });

  test("verifyApiKey returns record for valid key", async () => {
    const created = await store.createApiKey({
      organizationId: orgId,
      name: "Verify Test",
      permissions: ["org:policies:read"],
      createdBy: "usr_admin",
    });

    const verified = await store.verifyApiKey(created.key);
    expect(verified).not.toBeNull();
    expect(verified!.id).toBe(created.record.id);
    expect(verified!.organizationId).toBe(orgId);
  });

  test("verifyApiKey returns null for unknown key", async () => {
    const result = await store.verifyApiKey(`pw_live_${"0".repeat(48)}`);
    expect(result).toBeNull();
  });

  test("verifyApiKey returns null for expired key", async () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const created = await store.createApiKey({
      organizationId: orgId,
      name: "Expired Key",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
      expiresAt: pastDate,
    });

    const result = await store.verifyApiKey(created.key);
    expect(result).toBeNull();
  });

  test("listApiKeys never returns key_hash", async () => {
    await store.createApiKey({
      organizationId: orgId,
      name: "Listed Key",
      permissions: ["org:audit:read"],
      createdBy: "usr_admin",
    });

    const keys = await store.listApiKeys(orgId);
    expect(keys.length).toBe(1);

    const key = keys[0];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((key as any).keyHash).toBeUndefined();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((key as any).key_hash).toBeUndefined();
    expect(key.keyPrefix).toMatch(/^pw_live_/);
  });

  test("listApiKeys is scoped to organization", async () => {
    const orgA = "org_aaa";
    const orgB = "org_bbb";

    await store.createApiKey({
      organizationId: orgA,
      name: "Key A",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });
    await store.createApiKey({
      organizationId: orgB,
      name: "Key B",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    const keysA = await store.listApiKeys(orgA);
    const keysB = await store.listApiKeys(orgB);

    expect(keysA.every((k) => k.organizationId === orgA)).toBe(true);
    expect(keysB.every((k) => k.organizationId === orgB)).toBe(true);
    expect(keysA.length).toBe(1);
    expect(keysB.length).toBe(1);
  });

  test("revokeApiKey removes the key", async () => {
    const created = await store.createApiKey({
      organizationId: orgId,
      name: "Revoke Me",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    await store.revokeApiKey(created.record.id, orgId);

    const remaining = await store.listApiKeys(orgId);
    expect(remaining.find((k) => k.id === created.record.id)).toBeUndefined();

    const verified = await store.verifyApiKey(created.key);
    expect(verified).toBeNull();
  });

  test("revokeApiKey is scoped: cannot revoke key from wrong org", async () => {
    const created = await store.createApiKey({
      organizationId: orgId,
      name: "Protected Key",
      permissions: ["org:usage:read"],
      createdBy: "usr_admin",
    });

    // Attempt to revoke from a different org — should silently do nothing
    await store.revokeApiKey(created.record.id, "org_different");

    // Key should still exist in original org
    const remaining = await store.listApiKeys(orgId);
    expect(remaining.find((k) => k.id === created.record.id)).toBeDefined();
  });
});
