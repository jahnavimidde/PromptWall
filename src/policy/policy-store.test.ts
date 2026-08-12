/**
 * @file policy-store.test.ts
 * @module src/policy
 *
 * M7A Unit Tests for PolicyStore, Policy Runtime & Adapter.
 */

import { describe, expect, test, afterAll } from "bun:test";
import { Database, type SQLQueryBindings } from "bun:sqlite";
import { Kysely, SqliteDialect, type SqliteDatabase, type SqliteStatement } from "kysely";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { PolicyStore } from "./policy-store";
import { getPolicyEngine, invalidatePolicyCache } from "./runtime";
import { toPolicyRule, toPolicyRules } from "./adapter";

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

describe("M7A — Dynamic Policy Store & Runtime", () => {
  afterAll(() => {
    invalidatePolicyCache();
  });
  test("creates, reads, updates, disables, and deletes dynamic policies", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    // 1. Create Policy
    const policy = await store.createPolicy(
      {
        name: "Block Critical AWS Keys",
        description: "Strict blocking for AWS access key detection",
        priority: 5,
        enabled: true,
        action: "block",
        conditions: {
          subtype: "AWS_ACCESS_KEY",
          severity: "critical",
        },
      },
      "admin@promptwall.com",
    );

    expect(policy).toBeDefined();
    expect(policy.id).toMatch(/^pol_/);
    expect(policy.name).toBe("Block Critical AWS Keys");
    expect(policy.priority).toBe(5);
    expect(policy.enabled).toBe(true);
    expect(policy.action).toBe("block");
    expect(policy.conditions.subtype).toBe("AWS_ACCESS_KEY");

    // 2. Read Policy
    const read = await store.getPolicy(policy.id);
    expect(read).toBeDefined();
    expect(read?.id).toBe(policy.id);

    // 3. Update Policy
    const updated = await store.updatePolicy(
      policy.id,
      {
        name: "Updated AWS Key Policy",
        priority: 2,
      },
      "admin@promptwall.com",
    );

    expect(updated?.name).toBe("Updated AWS Key Policy");
    expect(updated?.priority).toBe(2);

    // 4. Disable Policy
    const toggled = await store.togglePolicyStatus(policy.id, false, "admin@promptwall.com");
    expect(toggled?.enabled).toBe(false);

    // 5. Verify getActivePolicyRules filters out disabled policy
    let activeRules = await store.getActivePolicyRules();
    expect(activeRules).toHaveLength(0);

    // Re-enable policy
    await store.togglePolicyStatus(policy.id, true);
    activeRules = await store.getActivePolicyRules();
    expect(activeRules).toHaveLength(1);
    expect(activeRules[0].id).toBe(policy.id);
    expect(activeRules[0].priority).toBe(2);

    // 6. Delete Policy
    const deleted = await store.deletePolicy(policy.id, "admin@promptwall.com");
    expect(deleted).toBe(true);

    const checkDeleted = await store.getPolicy(policy.id);
    expect(checkDeleted).toBeNull();
  });

  test("policy adapter transforms stored policies to PolicyRule[]", () => {
    const stored = {
      id: "pol_test_1",
      name: "Test Policy",
      description: "Desc",
      priority: 10,
      enabled: true,
      action: "mask" as const,
      reason: "Custom reason",
      conditions: {
        category: "secret" as const,
        subtype: "OPENAI_API_KEY",
        minRiskScore: 60,
      },
      createdBy: "admin",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const rule = toPolicyRule(stored);
    expect(rule.id).toBe("pol_test_1");
    expect(rule.priority).toBe(10);
    expect(rule.action).toBe("mask");
    expect(rule.category).toBe("secret");
    expect(rule.subtype).toBe("OPENAI_API_KEY");
    expect(rule.minRiskScore).toBe(60);

    const rules = toPolicyRules([stored, { ...stored, id: "pol_disabled", enabled: false }]);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("pol_test_1");
  });

  test("runtime manages PolicyEngine caching and invalidation", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    invalidatePolicyCache();

    // Cache miss — loads from store (which is empty), falls back to default rules
    const engine1 = await getPolicyEngine(store);
    expect(engine1).toBeDefined();

    // Cache hit — returns exact same instance
    const engine2 = await getPolicyEngine(store);
    expect(engine2).toBe(engine1);

    // Invalidate cache
    invalidatePolicyCache();

    // Add a policy to store
    await store.createPolicy({
      name: "Dynamic Policy",
      priority: 1,
      action: "block",
      conditions: { category: "secret" },
    });

    // Cache miss after invalidation — loads updated active rules
    const engine3 = await getPolicyEngine(store);
    expect(engine3).not.toBe(engine1);
  });
});
