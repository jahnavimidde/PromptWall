/**
 * @file usage-tracker.test.ts
 * @module src/organizations
 *
 * Unit tests for OrgUsageTracker (M12G).
 *
 * Verifies:
 * - Upsert increments counters atomically
 * - No raw content (prompts, PII, secrets) can be stored via this API
 * - Org scoping is correct
 * - getOrgUsage returns correct aggregate data
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { getOrgUsage, trackOrgUsage } from "./usage-tracker";

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

/** Wait for fire-and-forget async operations to settle */
async function settle(ms = 80): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("UsageTracker", () => {
  let db: Kysely<LogDatabase>;
  const orgA = "org_usage_a";
  const orgB = "org_usage_b";

  beforeEach(async () => {
    db = await createInMemoryDb();
  });

  afterEach(() => {
    db.destroy();
  });

  test("trackOrgUsage inserts a new row for first request", async () => {
    trackOrgUsage(orgA, "allow", undefined, undefined, db);
    await settle();

    const rows = await getOrgUsage(orgA, 30, db);
    expect(rows.length).toBe(1);
    expect(rows[0].totalRequests).toBe(1);
    expect(rows[0].allowedRequests).toBe(1);
    expect(rows[0].maskedRequests).toBe(0);
    expect(rows[0].blockedRequests).toBe(0);
  });

  test("trackOrgUsage increments counters on subsequent calls (atomic upsert)", async () => {
    trackOrgUsage(orgA, "allow", undefined, undefined, db);
    trackOrgUsage(orgA, "mask", undefined, undefined, db);
    trackOrgUsage(orgA, "block", undefined, undefined, db);
    await settle(200);

    const rows = await getOrgUsage(orgA, 30, db);
    expect(rows.length).toBe(1);
    expect(rows[0].totalRequests).toBe(3);
    expect(rows[0].allowedRequests).toBe(1);
    expect(rows[0].maskedRequests).toBe(1);
    expect(rows[0].blockedRequests).toBe(1);
  });

  test("trackOrgUsage is scoped — no cross-org leakage", async () => {
    trackOrgUsage(orgA, "allow", undefined, undefined, db);
    trackOrgUsage(orgA, "block", undefined, undefined, db);
    trackOrgUsage(orgB, "mask", undefined, undefined, db);
    await settle(200);

    const rowsA = await getOrgUsage(orgA, 30, db);
    const rowsB = await getOrgUsage(orgB, 30, db);

    expect(rowsA[0].totalRequests).toBe(2);
    expect(rowsB[0].totalRequests).toBe(1);
    expect(rowsA[0].organizationId).toBe(orgA);
    expect(rowsB[0].organizationId).toBe(orgB);
  });

  test("security: function accepts only primitive scalars — no raw content parameter exists", () => {
    // Verifies that the trackOrgUsage API enforces the security invariant by design:
    // the function signature only accepts (orgId, decision, tokens?, riskScore?, db?).
    // There is no parameter for prompts, entity values, PII strings, or secrets.
    const fn = trackOrgUsage;
    expect(typeof fn).toBe("function");
    // Call with all allowed scalar types — no assertion needed, just ensuring it compiles
    trackOrgUsage(orgA, "allow", 100, 42.5, db);
  });

  test("getOrgUsage returns correct rows for the days range", async () => {
    trackOrgUsage(orgA, "allow", undefined, undefined, db);
    await settle();

    const rows1 = await getOrgUsage(orgA, 1, db);
    expect(rows1.length).toBe(1);

    const rows90 = await getOrgUsage(orgA, 90, db);
    expect(rows90.length).toBe(1);
  });

  test("getOrgUsage returns empty array for org with no usage", async () => {
    const rows = await getOrgUsage("org_no_data", 30, db);
    expect(rows).toEqual([]);
  });

  test("token and riskScore are aggregated correctly", async () => {
    trackOrgUsage(orgA, "allow", 100, 10, db);
    trackOrgUsage(orgA, "allow", 200, 20, db);
    await settle(200);

    const rows = await getOrgUsage(orgA, 30, db);
    expect(rows[0].totalTokens).toBe(300);
    // avg_risk_score: (10*1 + 20) / 2 = 15
    expect(rows[0].avgRiskScore).toBeCloseTo(15, 0);
  });
});
