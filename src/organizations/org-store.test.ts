/**
 * @file org-store.test.ts
 * @module src/organizations
 *
 * Unit tests for OrgStore (M12B).
 * Uses an in-memory SQLite database — no external dependencies.
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { OrgStore } from "./org-store";

// ── In-memory SQLite helper (same pattern as policy-store.test.ts) ─────────────

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

describe("OrgStore", () => {
  let db: Kysely<LogDatabase>;
  let store: OrgStore;

  beforeEach(async () => {
    db = await createInMemoryDb();
    store = new OrgStore({ db });
  });

  afterEach(() => {
    db.destroy();
  });

  test("creates an organization", async () => {
    const org = await store.createOrganization({ name: "Acme Corp", slug: "acme-corp" });
    expect(org.id).toMatch(/^org_/);
    expect(org.name).toBe("Acme Corp");
    expect(org.slug).toBe("acme-corp");
    expect(org.createdAt).toBeTruthy();
  });

  test("getOrganization returns correct org", async () => {
    const created = await store.createOrganization({ name: "Beta Inc", slug: "beta-inc" });
    const fetched = await store.getOrganization(created.id);
    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("Beta Inc");
  });

  test("getOrganization returns null for unknown id", async () => {
    const result = await store.getOrganization("org_nonexistent");
    expect(result).toBeNull();
  });

  test("getOrganizationBySlug returns correct org", async () => {
    await store.createOrganization({ name: "Gamma Ltd", slug: "gamma-ltd" });
    const fetched = await store.getOrganizationBySlug("gamma-ltd");
    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("Gamma Ltd");
  });

  test("getOrganizationBySlug returns null for unknown slug", async () => {
    const result = await store.getOrganizationBySlug("no-such-slug");
    expect(result).toBeNull();
  });

  test("createOrganization rejects duplicate slug", async () => {
    await store.createOrganization({ name: "First", slug: "same-slug" });
    await expect(store.createOrganization({ name: "Second", slug: "same-slug" })).rejects.toThrow(
      "already exists",
    );
  });

  test("listOrganizations returns all orgs including org_system", async () => {
    await store.createOrganization({ name: "Alpha", slug: "alpha" });
    await store.createOrganization({ name: "Beta", slug: "beta" });

    const orgs = await store.listOrganizations();
    const slugs = orgs.map((o) => o.slug);
    expect(slugs).toContain("alpha");
    expect(slugs).toContain("beta");
    expect(slugs).toContain("system"); // created by migration 0007
  });

  test("updateOrganization changes name and slug", async () => {
    const created = await store.createOrganization({ name: "Old Name", slug: "old-slug" });
    const updated = await store.updateOrganization(created.id, {
      name: "New Name",
      slug: "new-slug",
    });
    expect(updated.name).toBe("New Name");
    expect(updated.slug).toBe("new-slug");
  });

  test("updateOrganization rejects slug conflict with other org", async () => {
    await store.createOrganization({ name: "Org A", slug: "org-a" });
    const orgB = await store.createOrganization({ name: "Org B", slug: "org-b" });
    await expect(store.updateOrganization(orgB.id, { slug: "org-a" })).rejects.toThrow(
      "already exists",
    );
  });

  test("deleteOrganization removes org", async () => {
    const org = await store.createOrganization({ name: "ToDelete", slug: "to-delete" });
    await store.deleteOrganization(org.id);
    const result = await store.getOrganization(org.id);
    expect(result).toBeNull();
  });

  test("getOrgMemberCount returns 0 for empty org", async () => {
    const org = await store.createOrganization({ name: "Empty", slug: "empty-org" });
    const count = await store.getOrgMemberCount(org.id);
    expect(count).toBe(0);
  });
});
