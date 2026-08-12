/**
 * @file policy-store.ts
 * @module src/policy
 *
 * Database persistence layer for dynamic security policies (M7A).
 * CRUD management for `security_policies` table with audit log emissions
 * on every policy modification.
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 * Policies contain purely matching metadata (category, subtype, severity,
 * risk level, score thresholds). Raw content, secrets, PII strings, or
 * prompts are NEVER accepted or stored.
 */

import type { CandidateCategory, PolicyAction, PolicyRule, RiskLevel, Severity } from "@promptwall/engine";
import { getAuditLogger } from "../logging/audit-logger";
import type { LogKysely, SecurityPoliciesTable } from "../logging/db";
import { createLogDatabase, migrateLogDatabase } from "../logging/db";
import { getConfig } from "../config";

export interface PolicyConditions {
  riskLevel?: RiskLevel;
  minRiskScore?: number;
  category?: CandidateCategory;
  subtype?: string;
  severity?: Severity;
  detector?: string;
  provider?: string;
}

export interface CreatePolicyInput {
  name: string;
  description?: string;
  priority: number;
  enabled?: boolean;
  conditions: PolicyConditions;
  action: PolicyAction;
  reason?: string;
}

export interface UpdatePolicyInput {
  name?: string;
  description?: string;
  priority?: number;
  enabled?: boolean;
  conditions?: PolicyConditions;
  action?: PolicyAction;
  reason?: string;
}

export interface StoredPolicy {
  id: string;
  name: string;
  description: string | null;
  priority: number;
  enabled: boolean;
  conditions: PolicyConditions;
  action: PolicyAction;
  reason: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

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

export class PolicyStore {
  private readonly db: LogKysely;
  private readonly ready: Promise<void>;

  constructor(options: { db?: LogKysely } = {}) {
    const { db, ready } = getDb(options.db);
    this.db = db;
    this.ready = ready;
  }

  /**
   * Emit an audit event for policy mutation.
   */
  private async auditMutation(
    mutationType: "created" | "updated" | "deleted" | "status_toggled",
    policyId: string,
    actor: string,
  ): Promise<void> {
    try {
      const auditLogger = getAuditLogger();
      await auditLogger.log({
        eventId: crypto.randomUUID(),
        requestId: `policy-${mutationType}-${Date.now()}`,
        timestamp: new Date().toISOString(),
        source: "promptwall",
        provider: "system",
        model: "policy-engine",
        riskScore: 0,
        riskLevel: "low",
        action: "policy_update",
        decisionReason: `Policy '${policyId}' ${mutationType} by ${actor}`,
        candidates: [],
        detectorsTriggered: [],
        matchedRuleIds: [policyId],
        latencyMs: 0,
      });
    } catch (err) {
      console.error("[PolicyAudit] Failed to record policy mutation audit event:", err);
    }
  }

  async createPolicy(input: CreatePolicyInput, actor = "admin"): Promise<StoredPolicy> {
    await this.ready;

    const id = `pol_${crypto.randomUUID().slice(0, 8)}`;
    const now = new Date().toISOString();
    const enabledNum = input.enabled === false ? 0 : 1;

    await this.db
      .insertInto("security_policies")
      .values({
        id,
        name: input.name,
        description: input.description ?? null,
        priority: input.priority,
        enabled: enabledNum,
        conditions: JSON.stringify(input.conditions ?? {}),
        action: input.action,
        reason: input.reason ?? null,
        created_by: actor,
        created_at: now,
        updated_at: now,
      })
      .execute();

    await this.auditMutation("created", id, actor);
    return this.getPolicy(id) as Promise<StoredPolicy>;
  }

  async getPolicy(id: string): Promise<StoredPolicy | null> {
    await this.ready;

    const row = await this.db
      .selectFrom("security_policies")
      .selectAll()
      .where("id", "=", id)
      .executeTakeFirst();

    if (!row) return null;

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      priority: Number(row.priority),
      enabled: Number(row.enabled) === 1,
      conditions: JSON.parse(row.conditions) as PolicyConditions,
      action: row.action as PolicyAction,
      reason: row.reason,
      createdBy: row.created_by,
      createdAt: row.created_at ?? new Date().toISOString(),
      updatedAt: row.updated_at ?? new Date().toISOString(),
    };
  }

  async listPolicies(): Promise<StoredPolicy[]> {
    await this.ready;

    const rows = await this.db
      .selectFrom("security_policies")
      .selectAll()
      .orderBy("priority", "asc")
      .execute();

    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      priority: Number(row.priority),
      enabled: Number(row.enabled) === 1,
      conditions: JSON.parse(row.conditions) as PolicyConditions,
      action: row.action as PolicyAction,
      reason: row.reason,
      createdBy: row.created_by,
      createdAt: row.created_at ?? new Date().toISOString(),
      updatedAt: row.updated_at ?? new Date().toISOString(),
    }));
  }

  async updatePolicy(id: string, input: UpdatePolicyInput, actor = "admin"): Promise<StoredPolicy | null> {
    await this.ready;

    const existing = await this.getPolicy(id);
    if (!existing) return null;

    const updates: {
      name?: string;
      description?: string | null;
      priority?: number;
      enabled?: number;
      conditions?: string;
      action?: string;
      reason?: string | null;
      updated_at: string;
    } = {
      updated_at: new Date().toISOString(),
    };

    if (input.name !== undefined) updates.name = input.name;
    if (input.description !== undefined) updates.description = input.description;
    if (input.priority !== undefined) updates.priority = input.priority;
    if (input.enabled !== undefined) updates.enabled = input.enabled ? 1 : 0;
    if (input.conditions !== undefined) updates.conditions = JSON.stringify(input.conditions);
    if (input.action !== undefined) updates.action = input.action;
    if (input.reason !== undefined) updates.reason = input.reason;

    await this.db
      .updateTable("security_policies")
      .set(updates)
      .where("id", "=", id)
      .execute();

    await this.auditMutation("updated", id, actor);
    return this.getPolicy(id);
  }

  async deletePolicy(id: string, actor = "admin"): Promise<boolean> {
    await this.ready;

    const existing = await this.getPolicy(id);
    if (!existing) return false;

    await this.db.deleteFrom("security_policies").where("id", "=", id).execute();
    await this.auditMutation("deleted", id, actor);
    return true;
  }

  async togglePolicyStatus(id: string, enabled: boolean, actor = "admin"): Promise<StoredPolicy | null> {
    await this.ready;

    const existing = await this.getPolicy(id);
    if (!existing) return null;

    await this.db
      .updateTable("security_policies")
      .set({
        enabled: enabled ? 1 : 0,
        updated_at: new Date().toISOString(),
      })
      .where("id", "=", id)
      .execute();

    await this.auditMutation("status_toggled", id, actor);
    return this.getPolicy(id);
  }

  /**
   * Convert all enabled security policies into PolicyRule[] for engine evaluation.
   */
  async getActivePolicyRules(): Promise<PolicyRule[]> {
    await this.ready;

    const rows = await this.db
      .selectFrom("security_policies")
      .selectAll()
      .where("enabled", "=", 1)
      .orderBy("priority", "asc")
      .execute();

    return rows.map((row) => {
      const cond = JSON.parse(row.conditions) as PolicyConditions;
      return {
        id: row.id,
        priority: Number(row.priority),
        action: row.action as PolicyAction,
        reason: row.reason ?? `Policy '${row.name}' triggered action ${row.action}`,
        category: cond.category,
        subtype: cond.subtype,
        severity: cond.severity,
        riskLevel: cond.riskLevel,
        minRiskScore: cond.minRiskScore,
        detector: cond.detector,
        provider: cond.provider,
      };
    });
  }
}
