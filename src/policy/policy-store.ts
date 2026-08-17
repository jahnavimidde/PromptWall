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

import type {
  CandidateCategory,
  PolicyAction,
  PolicyRule,
  RiskLevel,
  Severity,
} from "@promptwall/engine";
import { getConfig } from "../config";
import { getAuditLogger } from "../logging/audit-logger";
import type { LogKysely } from "../logging/db";
import { createLogDatabase, migrateLogDatabase } from "../logging/db";

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

/**
 * A single immutable snapshot of a policy's state at a given version number.
 * Rows in `security_policy_versions` are never modified or deleted.
 */
export interface StoredPolicyVersion {
  /** UUID row identifier for this version entry. */
  id: string;
  /** The policy this version belongs to. */
  policyId: string;
  /** 1-based, monotonically increasing per policyId. */
  version: number;
  name: string;
  description: string | null;
  priority: number;
  enabled: boolean;
  conditions: PolicyConditions;
  action: PolicyAction;
  reason: string | null;
  createdBy: string;
  createdAt: string;
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
    mutationType: "created" | "updated" | "deleted" | "status_toggled" | "rolled_back",
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

    const created = await this.getPolicy(id);
    if (!created) throw new Error(`[PolicyStore] Failed to read back created policy '${id}'`);

    // Snapshot version 1 for the newly created policy
    await this.snapshotVersion(created, actor);

    return created;
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

  async updatePolicy(
    id: string,
    input: UpdatePolicyInput,
    actor = "admin",
  ): Promise<StoredPolicy | null> {
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

    await this.db.updateTable("security_policies").set(updates).where("id", "=", id).execute();

    await this.auditMutation("updated", id, actor);

    const updated = await this.getPolicy(id);
    if (!updated) return null;

    // Snapshot new version after the live row has been updated
    await this.snapshotVersion(updated, actor);

    return updated;
  }

  async deletePolicy(id: string, actor = "admin"): Promise<boolean> {
    await this.ready;

    const existing = await this.getPolicy(id);
    if (!existing) return false;

    await this.db.deleteFrom("security_policies").where("id", "=", id).execute();
    await this.auditMutation("deleted", id, actor);
    return true;
  }

  async togglePolicyStatus(
    id: string,
    enabled: boolean,
    actor = "admin",
  ): Promise<StoredPolicy | null> {
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

    const toggled = await this.getPolicy(id);
    if (!toggled) return null;

    // Snapshot new version after toggle so enable/disable changes are versioned
    await this.snapshotVersion(toggled, actor);

    return toggled;
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

  // ── Version history ───────────────────────────────────────────────────────

  /**
   * Insert a new immutable snapshot of `policy` into `security_policy_versions`.
   *
   * The version number is computed as: MAX(version) for this policy_id + 1,
   * defaulting to 1 for brand-new policies.
   *
   * This method is called by every mutating operation (create, update, toggle,
   * rollback) after the live `security_policies` row has been written.
   */
  private async snapshotVersion(policy: StoredPolicy, actor: string): Promise<void> {
    // Determine next version number for this policy
    const result = await this.db
      .selectFrom("security_policy_versions")
      .select((eb) => eb.fn.max("version").as("max_version"))
      .where("policy_id", "=", policy.id)
      .executeTakeFirst();

    const nextVersion = result?.max_version != null ? Number(result.max_version) + 1 : 1;

    await this.db
      .insertInto("security_policy_versions")
      .values({
        id: crypto.randomUUID(),
        policy_id: policy.id,
        version: nextVersion,
        name: policy.name,
        description: policy.description,
        priority: policy.priority,
        enabled: policy.enabled ? 1 : 0,
        conditions: JSON.stringify(policy.conditions),
        action: policy.action,
        reason: policy.reason,
        created_by: actor,
        created_at: new Date().toISOString(),
      })
      .execute();
  }

  /**
   * Retrieve all version snapshots for a given policy, ordered by version ASC.
   *
   * History is preserved even after the policy row is deleted from
   * `security_policies`, so this may return rows for deleted policies.
   *
   * @returns Empty array if no versions exist for the given policyId.
   */
  async getPolicyVersions(policyId: string): Promise<StoredPolicyVersion[]> {
    await this.ready;

    const rows = await this.db
      .selectFrom("security_policy_versions")
      .selectAll()
      .where("policy_id", "=", policyId)
      .orderBy("version", "asc")
      .execute();

    return rows.map((row) => ({
      id: row.id,
      policyId: row.policy_id,
      version: Number(row.version),
      name: row.name,
      description: row.description,
      priority: Number(row.priority),
      enabled: Number(row.enabled) === 1,
      conditions: JSON.parse(row.conditions) as PolicyConditions,
      action: row.action as PolicyAction,
      reason: row.reason,
      createdBy: row.created_by,
      createdAt: row.created_at ?? new Date().toISOString(),
    }));
  }

  /**
   * Retrieve a single version snapshot for a given policy.
   *
   * @returns `null` if the (policyId, version) pair does not exist.
   */
  async getPolicyVersion(policyId: string, version: number): Promise<StoredPolicyVersion | null> {
    await this.ready;

    const row = await this.db
      .selectFrom("security_policy_versions")
      .selectAll()
      .where("policy_id", "=", policyId)
      .where("version", "=", version)
      .executeTakeFirst();

    if (!row) return null;

    return {
      id: row.id,
      policyId: row.policy_id,
      version: Number(row.version),
      name: row.name,
      description: row.description,
      priority: Number(row.priority),
      enabled: Number(row.enabled) === 1,
      conditions: JSON.parse(row.conditions) as PolicyConditions,
      action: row.action as PolicyAction,
      reason: row.reason,
      createdBy: row.created_by,
      createdAt: row.created_at ?? new Date().toISOString(),
    };
  }

  /**
   * Rollback a policy to a specific historical version.
   *
   * Rollback creates a NEW version snapshot copied from `targetVersion` and
   * overwrites the live `security_policies` row with that state. History is
   * never deleted or rewritten — the rollback itself is versioned.
   *
   * @param policyId     - ID of the policy to roll back.
   * @param targetVersion - The version number to restore from.
   * @param actor        - Authenticated user performing the rollback.
   * @returns The restored `StoredPolicy` (reflecting the new live state),
   *          or `null` if the policy or target version does not exist.
   */
  async rollbackPolicy(
    policyId: string,
    targetVersion: number,
    actor = "admin",
  ): Promise<StoredPolicy | null> {
    await this.ready;

    // Verify the policy exists
    const existing = await this.getPolicy(policyId);
    if (!existing) return null;

    // Fetch the target version snapshot
    const snapshot = await this.getPolicyVersion(policyId, targetVersion);
    if (!snapshot) return null;

    const now = new Date().toISOString();

    // Overwrite the live policy row with the snapshot state
    await this.db
      .updateTable("security_policies")
      .set({
        name: snapshot.name,
        description: snapshot.description,
        priority: snapshot.priority,
        enabled: snapshot.enabled ? 1 : 0,
        conditions: JSON.stringify(snapshot.conditions),
        action: snapshot.action,
        reason: snapshot.reason,
        updated_at: now,
      })
      .where("id", "=", policyId)
      .execute();

    await this.auditMutation("rolled_back", policyId, actor);

    const restored = await this.getPolicy(policyId);
    if (!restored) return null;

    // Append a new version entry so the rollback itself is in the history
    await this.snapshotVersion(restored, actor);

    return restored;
  }
}
