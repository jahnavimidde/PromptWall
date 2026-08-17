/**
 * @file policy-store.test.ts
 * @module src/policy
 *
 * M7A Unit Tests for PolicyStore, Policy Runtime & Adapter.
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { toPolicyRule, toPolicyRules } from "./adapter";
import { PolicyStore } from "./policy-store";
import { getPolicyEngine, invalidatePolicyCache } from "./runtime";

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

describe("M8B — Policy Versioning & Rollback", () => {
  test("createPolicy produces version 1 snapshot", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    const policy = await store.createPolicy(
      {
        name: "Version Test Policy",
        priority: 10,
        action: "mask",
        conditions: { category: "pii" },
      },
      "admin@promptwall.com",
    );

    const versions = await store.getPolicyVersions(policy.id);
    expect(versions).toHaveLength(1);
    expect(versions[0].version).toBe(1);
    expect(versions[0].policyId).toBe(policy.id);
    expect(versions[0].name).toBe("Version Test Policy");
    expect(versions[0].action).toBe("mask");
    expect(versions[0].enabled).toBe(true);
    expect(versions[0].createdBy).toBe("admin@promptwall.com");
  });

  test("updatePolicy increments version, preserves version 1", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    const policy = await store.createPolicy(
      { name: "Initial Name", priority: 5, action: "block", conditions: {} },
      "admin@promptwall.com",
    );

    await store.updatePolicy(
      policy.id,
      { name: "Updated Name", priority: 3 },
      "admin@promptwall.com",
    );

    const versions = await store.getPolicyVersions(policy.id);
    expect(versions).toHaveLength(2);

    // Version 1 preserves original state
    expect(versions[0].version).toBe(1);
    expect(versions[0].name).toBe("Initial Name");
    expect(versions[0].priority).toBe(5);

    // Version 2 reflects the update
    expect(versions[1].version).toBe(2);
    expect(versions[1].name).toBe("Updated Name");
    expect(versions[1].priority).toBe(3);
  });

  test("togglePolicyStatus creates a new version snapshot", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    const policy = await store.createPolicy(
      { name: "Toggle Test", priority: 1, action: "allow", conditions: {} },
      "admin@promptwall.com",
    );

    await store.togglePolicyStatus(policy.id, false, "admin@promptwall.com");

    const versions = await store.getPolicyVersions(policy.id);
    expect(versions).toHaveLength(2);

    expect(versions[0].enabled).toBe(true); // version 1: enabled
    expect(versions[1].enabled).toBe(false); // version 2: disabled
    expect(versions[1].version).toBe(2);
  });

  test("rollbackPolicy creates a new version copied from target version", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    // Create → v1 (action: mask)
    const policy = await store.createPolicy(
      { name: "Rollback Test", priority: 10, action: "mask", conditions: { category: "secret" } },
      "admin@promptwall.com",
    );

    // Update → v2 (action: block)
    await store.updatePolicy(policy.id, { action: "block" }, "admin@promptwall.com");

    // Rollback to v1 → should create v3 with mask action
    const restored = await store.rollbackPolicy(policy.id, 1, "admin@promptwall.com");

    expect(restored).not.toBeNull();
    expect(restored?.action).toBe("mask"); // restored to v1 state
    expect(restored?.id).toBe(policy.id); // same policy id

    const versions = await store.getPolicyVersions(policy.id);
    expect(versions).toHaveLength(3);

    // v3 should be a copy of v1 state
    expect(versions[2].version).toBe(3);
    expect(versions[2].action).toBe("mask");
    expect(versions[2].name).toBe("Rollback Test");
  });

  test("getPolicyVersion returns correct snapshot for (policyId, version) pair", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    const policy = await store.createPolicy(
      { name: "Snapshot Test", priority: 1, action: "allow", conditions: {} },
      "admin@promptwall.com",
    );
    await store.updatePolicy(policy.id, { name: "Snapshot Updated" }, "admin@promptwall.com");

    const v1 = await store.getPolicyVersion(policy.id, 1);
    expect(v1).not.toBeNull();
    expect(v1?.version).toBe(1);
    expect(v1?.name).toBe("Snapshot Test");

    const v2 = await store.getPolicyVersion(policy.id, 2);
    expect(v2).not.toBeNull();
    expect(v2?.version).toBe(2);
    expect(v2?.name).toBe("Snapshot Updated");
  });

  test("rollbackPolicy to non-existent version returns null", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    const policy = await store.createPolicy(
      { name: "No Such Version", priority: 1, action: "block", conditions: {} },
      "admin@promptwall.com",
    );

    const result = await store.rollbackPolicy(policy.id, 999, "admin@promptwall.com");
    expect(result).toBeNull();

    // History should be unchanged (only v1 exists)
    const versions = await store.getPolicyVersions(policy.id);
    expect(versions).toHaveLength(1);
  });

  test("rollbackPolicy on non-existent policy returns null", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    const result = await store.rollbackPolicy("pol_does_not_exist", 1, "admin@promptwall.com");
    expect(result).toBeNull();
  });

  test("getPolicyVersions returns empty array for policy with no versions", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    // Query versions for an ID that was never created
    const versions = await store.getPolicyVersions("pol_ghost");
    expect(versions).toHaveLength(0);
  });

  test("full lifecycle: create → update → toggle → rollback → 4 versions total", async () => {
    const db = await createInMemoryDb();
    const store = new PolicyStore({ db });

    // v1: create
    const policy = await store.createPolicy(
      { name: "Lifecycle", priority: 20, action: "allow", conditions: { riskLevel: "low" } },
      "admin@promptwall.com",
    );

    // v2: update
    await store.updatePolicy(policy.id, { priority: 15 }, "admin@promptwall.com");

    // v3: toggle
    await store.togglePolicyStatus(policy.id, false, "admin@promptwall.com");

    // v4: rollback to v1
    const rolled = await store.rollbackPolicy(policy.id, 1, "admin@promptwall.com");
    expect(rolled?.priority).toBe(20);
    expect(rolled?.enabled).toBe(true);

    const versions = await store.getPolicyVersions(policy.id);
    expect(versions).toHaveLength(4);
    expect(versions.map((v) => v.version)).toEqual([1, 2, 3, 4]);
  });
});
