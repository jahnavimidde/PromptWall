import { Database, type SQLQueryBindings } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  type ColumnType,
  type Generated,
  Kysely,
  PostgresDialect,
  type SqliteDatabase,
  SqliteDialect,
  type SqliteStatement,
  sql,
} from "kysely";
import { type Migration, type MigrationProvider, Migrator } from "kysely/migration";
import { Pool } from "pg";
import type { Config } from "../config";

export type LoggingDriver = "sqlite" | "postgres";

export interface RequestLogsTable {
  id: Generated<number>;
  timestamp: string;
  mode: string;
  provider: string;
  source: string | null;
  model: string;
  pii_detected: number;
  entities: string | null;
  latency_ms: number;
  scan_time_ms: number;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  user_agent: string | null;
  masked_content: string | null;
  secrets_detected: number | null;
  secrets_types: string | null;
  status_code: number | null;
  error_message: string | null;
  created_at: ColumnType<string | null, string | undefined, never>;
}

/**
 * Kysely table type for the `security_events` audit log table (M6A).
 *
 * Security invariant: `candidates` and `matched_rule_ids` are JSON-serialised
 * arrays that NEVER contain raw secret/PII values — only CandidateSummary
 * metadata (category, subtype, severity, confidence, detector id).
 */
export interface SecurityEventsTable {
  id: Generated<number>;
  event_id: string;
  request_id: string;
  timestamp: string;
  source: string;
  provider: string;
  model: string;
  risk_score: number;
  risk_level: string;
  action: string;
  decision_reason: string;
  candidates: string; // JSON: CandidateSummary[]
  detectors_triggered: string; // JSON: string[]
  matched_rule_ids: string; // JSON: string[]
  latency_ms: number;
  organization_id: string | null; // M12: tenant scope (null = legacy / org_system)
  created_at: ColumnType<string | null, string | undefined, never>;
}

export interface SecurityPoliciesTable {
  id: string;
  name: string;
  description: string | null;
  priority: number;
  enabled: number; // 1 = active, 0 = disabled
  conditions: string; // JSON: { riskLevel, minRiskScore, category, subtype, detector, provider, severity }
  action: string; // "allow" | "mask" | "block"
  reason: string | null;
  created_by: string;
  organization_id: string | null; // M12: tenant scope (null = global/system policy)
  created_at: ColumnType<string | null, string | undefined, never>;
  updated_at: ColumnType<string | null, string | undefined, string | undefined>;
}

/**
 * Kysely table type for the `security_policy_versions` immutable version history table (M8B).
 *
 * Every policy mutation (create / update / toggle / rollback) appends a row here.
 * Rows are never deleted — this is the permanent audit trail of every policy state.
 */
export interface SecurityPolicyVersionsTable {
  id: string; // UUID for this version row
  policy_id: string; // FK → security_policies.id (logical reference only)
  version: number; // 1-based, monotonically increasing per policy_id
  name: string;
  description: string | null;
  priority: number;
  enabled: number; // 1 = active, 0 = disabled
  conditions: string; // JSON: PolicyConditions
  action: string; // "allow" | "mask" | "block"
  reason: string | null;
  created_by: string;
  organization_id: string | null; // M12: mirrors parent security_policies.organization_id
  created_at: ColumnType<string | null, string | undefined, never>;
}

export interface UsersTable {
  id: string;
  email: string;
  password_hash: string;
  role: string; // "ADMIN" | "SECURITY_ANALYST" | "VIEWER"
  organization_id: string | null; // M12: org membership (null = system/legacy users)
  org_role: string | null; // M12: org-scoped role "ORG_ADMIN"|"SECURITY_ADMIN"|"ANALYST"|"VIEWER"
  created_at: ColumnType<string | null, string | undefined, never>;
  updated_at: ColumnType<string | null, string | undefined, never>;
}

// ── M12: Multi-Tenancy Tables ─────────────────────────────────────────────────

/**
 * Tenant root entity. Every user, policy, and audit event is scoped to an org.
 * The synthetic "org_system" org holds all pre-M12 (legacy) data.
 */
export interface OrganizationsTable {
  id: string; // "org_" prefix + UUID fragment
  name: string;
  slug: string; // UNIQUE, URL-safe label
  created_at: ColumnType<string | null, string | undefined, never>;
  updated_at: ColumnType<string | null, string | undefined, string | undefined>;
}

/**
 * Programmatic API credentials scoped to an organization.
 *
 * Security invariant: `key_hash` stores SHA-256 hex of the raw key.
 * The raw key is generated once and returned to the caller; it is NEVER
 * persisted or re-derivable from this table.
 */
export interface ApiKeysTable {
  id: string; // "key_" prefix + UUID fragment
  organization_id: string;
  name: string; // human label, e.g. "CI/CD Pipeline"
  key_hash: string; // SHA-256 hex of raw key — plaintext never stored
  key_prefix: string; // first 16 chars of raw key for display
  permissions: string; // JSON: OrgPermission[]
  last_used_at: string | null;
  expires_at: string | null;
  created_by: string; // user id
  created_at: ColumnType<string | null, string | undefined, never>;
}

/**
 * Daily aggregate usage metrics per organization.
 *
 * Security invariant: only counts and aggregate scores stored — no raw
 * prompts, entity values, PII, secrets, or detector evidence.
 */
export interface TenantUsageDailyTable {
  id: Generated<number>;
  organization_id: string;
  date: string; // YYYY-MM-DD UTC
  total_requests: number;
  allowed_requests: number;
  masked_requests: number;
  blocked_requests: number;
  total_tokens: number | null;
  avg_risk_score: number | null;
  created_at: ColumnType<string | null, string | undefined, never>;
  updated_at: ColumnType<string | null, string | undefined, string | undefined>;
}

export interface LogDatabase {
  request_logs: RequestLogsTable;
  security_events: SecurityEventsTable;
  security_policies: SecurityPoliciesTable;
  security_policy_versions: SecurityPolicyVersionsTable;
  users: UsersTable;
  // M12: Multi-tenancy tables
  organizations: OrganizationsTable;
  api_keys: ApiKeysTable;
  tenant_usage_daily: TenantUsageDailyTable;
}

interface MigrationDatabase extends LogDatabase {
  kysely_migration: {
    name: string;
    timestamp: string;
  };
}

export type LogKysely = Kysely<LogDatabase>;

class BunSqliteDatabase implements SqliteDatabase {
  constructor(private readonly db: Database) {}

  close(): void {
    this.db.close();
  }

  prepare(query: string): SqliteStatement {
    const statement = this.db.prepare<unknown, SQLQueryBindings[]>(query);
    const reader = /^(select|pragma|with)\b/i.test(query.trim());

    return {
      get reader() {
        return reader;
      },
      all(parameters: ReadonlyArray<unknown>) {
        return statement.all(...(parameters as SQLQueryBindings[]));
      },
      run(parameters: ReadonlyArray<unknown>) {
        const result = statement.run(...(parameters as SQLQueryBindings[]));
        return {
          changes: result.changes,
          lastInsertRowid: result.lastInsertRowid,
        };
      },
      iterate(parameters: ReadonlyArray<unknown>) {
        return statement.iterate(...(parameters as SQLQueryBindings[]));
      },
    };
  }
}

export function createLogDatabase(config: Config): { db: LogKysely; driver: LoggingDriver } {
  if (config.logging.driver === "postgres") {
    return {
      driver: "postgres",
      db: new Kysely<LogDatabase>({
        dialect: new PostgresDialect({
          pool: new Pool({ connectionString: config.logging.postgres_url! }),
        }),
      }),
    };
  }

  const dbPath = config.logging.database;
  const dir = dirname(dbPath);
  if (dir && dir !== ".") {
    mkdirSync(dir, { recursive: true });
  }

  return {
    driver: "sqlite",
    db: new Kysely<LogDatabase>({
      dialect: new SqliteDialect({
        database: new BunSqliteDatabase(new Database(dbPath)),
      }),
    }),
  };
}

export async function migrateLogDatabase(db: LogKysely, driver: LoggingDriver): Promise<void> {
  await baselineExistingRequestLogs(db);

  const migrator = new Migrator({
    db,
    provider: new InlineMigrationProvider({
      "0001_request_logs": createRequestLogsMigration(driver),
      "0002_security_events": createSecurityEventsMigration(driver),
      "0003_security_policies": createSecurityPoliciesMigration(driver),
      "0004_users": createUsersMigration(driver),
      "0005_policy_versions": createPolicyVersionsMigration(driver),
      "0006_organizations": createOrganizationsMigration(driver),
      "0007_tenant_isolation": createTenantIsolationMigration(driver),
    }),
  });

  const result = await migrator.migrateToLatest();
  if (result.error) {
    throw result.error;
  }
}

class InlineMigrationProvider implements MigrationProvider {
  constructor(private readonly migrations: Record<string, Migration>) {}

  async getMigrations(): Promise<Record<string, Migration>> {
    return this.migrations;
  }
}

function createRequestLogsMigration(driver: LoggingDriver): Migration {
  return {
    async up(db) {
      let createTable = db.schema.createTable("request_logs").ifNotExists();

      createTable =
        driver === "postgres"
          ? createTable.addColumn("id", "serial", (column) => column.primaryKey())
          : createTable.addColumn("id", "integer", (column) => column.primaryKey().autoIncrement());

      await createTable
        .addColumn("timestamp", "text", (column) => column.notNull())
        .addColumn("mode", "text", (column) => column.notNull().defaultTo("route"))
        .addColumn("provider", "text", (column) => column.notNull())
        .addColumn("source", "text")
        .addColumn("model", "text", (column) => column.notNull())
        .addColumn("pii_detected", "integer", (column) => column.notNull().defaultTo(0))
        .addColumn("entities", "text")
        .addColumn("latency_ms", "integer", (column) => column.notNull())
        .addColumn("scan_time_ms", "integer", (column) => column.notNull().defaultTo(0))
        .addColumn("prompt_tokens", "integer")
        .addColumn("completion_tokens", "integer")
        .addColumn("user_agent", "text")
        .addColumn("masked_content", "text")
        .addColumn("secrets_detected", "integer")
        .addColumn("secrets_types", "text")
        .addColumn("status_code", "integer")
        .addColumn("error_message", "text")
        .addColumn("created_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      await createRequestLogIndexes(db);
    },
  };
}

function createSecurityEventsMigration(driver: LoggingDriver): Migration {
  return {
    async up(db) {
      let createTable = db.schema.createTable("security_events").ifNotExists();

      createTable =
        driver === "postgres"
          ? createTable.addColumn("id", "serial", (column) => column.primaryKey())
          : createTable.addColumn("id", "integer", (column) => column.primaryKey().autoIncrement());

      await createTable
        .addColumn("event_id", "text", (column) => column.notNull())
        .addColumn("request_id", "text", (column) => column.notNull())
        .addColumn("timestamp", "text", (column) => column.notNull())
        .addColumn("source", "text", (column) => column.notNull().defaultTo("promptwall"))
        .addColumn("provider", "text", (column) => column.notNull())
        .addColumn("model", "text", (column) => column.notNull())
        .addColumn("risk_score", "real", (column) => column.notNull())
        .addColumn("risk_level", "text", (column) => column.notNull())
        .addColumn("action", "text", (column) => column.notNull())
        .addColumn("decision_reason", "text", (column) => column.notNull())
        .addColumn("candidates", "text", (column) => column.notNull().defaultTo("[]"))
        .addColumn("detectors_triggered", "text", (column) => column.notNull().defaultTo("[]"))
        .addColumn("matched_rule_ids", "text", (column) => column.notNull().defaultTo("[]"))
        .addColumn("latency_ms", "integer", (column) => column.notNull())
        .addColumn("created_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      await createSecurityEventIndexes(db);
    },
  };
}

function createSecurityPoliciesMigration(_driver: LoggingDriver): Migration {
  return {
    async up(db) {
      const createTable = db.schema.createTable("security_policies").ifNotExists();

      await createTable
        .addColumn("id", "text", (column) => column.primaryKey())
        .addColumn("name", "text", (column) => column.notNull())
        .addColumn("description", "text")
        .addColumn("priority", "integer", (column) => column.notNull().defaultTo(10))
        .addColumn("enabled", "integer", (column) => column.notNull().defaultTo(1))
        .addColumn("conditions", "text", (column) => column.notNull().defaultTo("{}"))
        .addColumn("action", "text", (column) => column.notNull())
        .addColumn("reason", "text")
        .addColumn("created_by", "text", (column) => column.notNull().defaultTo("system"))
        .addColumn("created_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .addColumn("updated_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      await db.schema
        .createIndex("idx_sp_enabled_priority")
        .ifNotExists()
        .on("security_policies")
        .columns(["enabled", "priority"])
        .execute();
    },
  };
}

function createPolicyVersionsMigration(_driver: LoggingDriver): Migration {
  return {
    async up(db) {
      await db.schema
        .createTable("security_policy_versions")
        .ifNotExists()
        .addColumn("id", "text", (column) => column.primaryKey())
        .addColumn("policy_id", "text", (column) => column.notNull())
        .addColumn("version", "integer", (column) => column.notNull())
        .addColumn("name", "text", (column) => column.notNull())
        .addColumn("description", "text")
        .addColumn("priority", "integer", (column) => column.notNull())
        .addColumn("enabled", "integer", (column) => column.notNull())
        .addColumn("conditions", "text", (column) => column.notNull())
        .addColumn("action", "text", (column) => column.notNull())
        .addColumn("reason", "text")
        .addColumn("created_by", "text", (column) => column.notNull())
        .addColumn("created_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      // Unique constraint: one row per (policy_id, version) pair
      await db.schema
        .createIndex("idx_spv_policy_version")
        .ifNotExists()
        .unique()
        .on("security_policy_versions")
        .columns(["policy_id", "version"])
        .execute();

      // Fast lookup of all versions for a given policy
      await db.schema
        .createIndex("idx_policy_versions_policy")
        .ifNotExists()
        .on("security_policy_versions")
        .column("policy_id")
        .execute();
    },
  };
}

function createUsersMigration(_driver: LoggingDriver): Migration {
  return {
    async up(db) {
      const createTable = db.schema.createTable("users").ifNotExists();

      await createTable
        .addColumn("id", "text", (column) => column.primaryKey())
        .addColumn("email", "text", (column) => column.notNull().unique())
        .addColumn("password_hash", "text", (column) => column.notNull())
        .addColumn("role", "text", (column) => column.notNull().defaultTo("VIEWER"))
        .addColumn("created_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .addColumn("updated_at", "text", (column) => column.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      await db.schema
        .createIndex("idx_users_email")
        .ifNotExists()
        .on("users")
        .column("email")
        .execute();
    },
  };
}

async function baselineExistingRequestLogs(db: LogKysely): Promise<void> {
  const tables = await db.introspection.getTables({ withInternalKyselyTables: true });
  const requestLogsTable = tables.find((table) => table.name === "request_logs");
  const migrationTable = tables.find((table) => table.name === "kysely_migration");

  if (!requestLogsTable || migrationTable) {
    return;
  }

  const columns = new Set(requestLogsTable.columns.map((column) => column.name));
  await addLegacyColumnIfMissing(db, columns, "source", "text");
  await addLegacyColumnIfMissing(db, columns, "secrets_detected", "integer");
  await addLegacyColumnIfMissing(db, columns, "secrets_types", "text");
  await addLegacyColumnIfMissing(db, columns, "status_code", "integer");
  await addLegacyColumnIfMissing(db, columns, "error_message", "text");

  await db
    .updateTable("request_logs")
    .set({ source: sql<string>`provider` })
    .where("source", "is", null)
    .execute();
  await createRequestLogIndexes(db);
  await createKyselyMigrationBaseline(db as unknown as Kysely<MigrationDatabase>);
}

async function addLegacyColumnIfMissing(
  db: LogKysely,
  columns: Set<string>,
  name: string,
  type: "integer" | "text",
): Promise<void> {
  if (columns.has(name)) {
    return;
  }

  await db.schema.alterTable("request_logs").addColumn(name, type).execute();
  columns.add(name);
}

async function createRequestLogIndexes(db: LogKysely): Promise<void> {
  await db.schema
    .createIndex("idx_timestamp")
    .ifNotExists()
    .on("request_logs")
    .column("timestamp")
    .execute();
  await db.schema
    .createIndex("idx_provider")
    .ifNotExists()
    .on("request_logs")
    .column("provider")
    .execute();
  await db.schema
    .createIndex("idx_pii_detected")
    .ifNotExists()
    .on("request_logs")
    .column("pii_detected")
    .execute();
}

async function createSecurityEventIndexes(db: LogKysely): Promise<void> {
  await db.schema
    .createIndex("idx_se_timestamp")
    .ifNotExists()
    .on("security_events")
    .column("timestamp")
    .execute();
  await db.schema
    .createIndex("idx_se_action")
    .ifNotExists()
    .on("security_events")
    .column("action")
    .execute();
  await db.schema
    .createIndex("idx_se_request_id")
    .ifNotExists()
    .on("security_events")
    .column("request_id")
    .execute();
}

async function createKyselyMigrationBaseline(db: Kysely<MigrationDatabase>): Promise<void> {
  await db.schema
    .createTable("kysely_migration")
    .ifNotExists()
    .addColumn("name", "varchar(255)", (column) => column.notNull().primaryKey())
    .addColumn("timestamp", "varchar(255)", (column) => column.notNull())
    .execute();

  await db
    .insertInto("kysely_migration")
    .values({
      name: "0001_request_logs",
      timestamp: new Date().toISOString(),
    })
    .execute();
}

// ── M12 Migrations ────────────────────────────────────────────────────────────

/**
 * Migration 0006: Create multi-tenancy tables.
 * Creates: organizations, api_keys, tenant_usage_daily
 */
function createOrganizationsMigration(_driver: LoggingDriver): Migration {
  return {
    async up(db) {
      // organizations — tenant root
      await db.schema
        .createTable("organizations")
        .ifNotExists()
        .addColumn("id", "text", (col) => col.primaryKey())
        .addColumn("name", "text", (col) => col.notNull())
        .addColumn("slug", "text", (col) => col.notNull().unique())
        .addColumn("created_at", "text", (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`))
        .addColumn("updated_at", "text", (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      // api_keys — hashed programmatic credentials
      await db.schema
        .createTable("api_keys")
        .ifNotExists()
        .addColumn("id", "text", (col) => col.primaryKey())
        .addColumn("organization_id", "text", (col) => col.notNull())
        .addColumn("name", "text", (col) => col.notNull())
        .addColumn("key_hash", "text", (col) => col.notNull().unique())
        .addColumn("key_prefix", "text", (col) => col.notNull())
        .addColumn("permissions", "text", (col) => col.notNull().defaultTo("[]"))
        .addColumn("last_used_at", "text")
        .addColumn("expires_at", "text")
        .addColumn("created_by", "text", (col) => col.notNull())
        .addColumn("created_at", "text", (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      await db.schema
        .createIndex("idx_api_keys_org")
        .ifNotExists()
        .on("api_keys")
        .column("organization_id")
        .execute();

      // tenant_usage_daily — aggregate per-org daily metrics (no raw content)
      await db.schema
        .createTable("tenant_usage_daily")
        .ifNotExists()
        .addColumn("id", "integer", (col) => col.primaryKey().autoIncrement())
        .addColumn("organization_id", "text", (col) => col.notNull())
        .addColumn("date", "text", (col) => col.notNull())
        .addColumn("total_requests", "integer", (col) => col.notNull().defaultTo(0))
        .addColumn("allowed_requests", "integer", (col) => col.notNull().defaultTo(0))
        .addColumn("masked_requests", "integer", (col) => col.notNull().defaultTo(0))
        .addColumn("blocked_requests", "integer", (col) => col.notNull().defaultTo(0))
        .addColumn("total_tokens", "integer")
        .addColumn("avg_risk_score", "real")
        .addColumn("created_at", "text", (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`))
        .addColumn("updated_at", "text", (col) => col.defaultTo(sql`CURRENT_TIMESTAMP`))
        .execute();

      // Unique index drives upsert ON CONFLICT (organization_id, date)
      await db.schema
        .createIndex("idx_usage_org_date")
        .ifNotExists()
        .unique()
        .on("tenant_usage_daily")
        .columns(["organization_id", "date"])
        .execute();
    },
  };
}

/**
 * Migration 0007: Add organization_id to all tenant-owned tables.
 *
 * 1. Inserts the synthetic "org_system" org (holds all pre-M12 legacy rows).
 * 2. Adds nullable organization_id column to users, security_policies,
 *    security_policy_versions, security_events.
 * 3. Adds nullable org_role column to users.
 * 4. Backfills all existing rows with "org_system".
 * 5. Creates covering indexes for tenant-scoped queries.
 *
 * SQLite limitation: ALTER TABLE can add nullable columns but cannot change
 * existing columns to NOT NULL. Application layer enforces not-null invariant.
 */
function createTenantIsolationMigration(_driver: LoggingDriver): Migration {
  return {
    async up(db) {
      const now = new Date().toISOString();

      // 1. Insert the default system org (idempotent: ignored if already exists)
      await sql`
        INSERT OR IGNORE INTO organizations (id, name, slug, created_at, updated_at)
        VALUES ('org_system', 'System', 'system', ${now}, ${now})
      `.execute(db);

      // 2. Add organization_id to tenant-owned tables
      const tenantTables = [
        "users",
        "security_policies",
        "security_policy_versions",
        "security_events",
      ] as const;

      for (const table of tenantTables) {
        // SQLite: ifNotExists not supported for ADD COLUMN; migration only runs once
        try {
          await sql`ALTER TABLE ${sql.table(table)} ADD COLUMN organization_id TEXT`.execute(db);
        } catch {
          // Column already exists — safe to ignore in idempotent re-runs
        }
      }

      // 3. Add org_role to users
      try {
        await sql`ALTER TABLE users ADD COLUMN org_role TEXT`.execute(db);
      } catch {
        // Already exists
      }

      // 4. Backfill legacy rows → org_system
      for (const table of tenantTables) {
        await sql`
          UPDATE ${sql.table(table)}
          SET organization_id = 'org_system'
          WHERE organization_id IS NULL
        `.execute(db);
      }

      // 5. Covering indexes for tenant-scoped queries
      await db.schema
        .createIndex("idx_users_org")
        .ifNotExists()
        .on("users")
        .column("organization_id")
        .execute();

      await db.schema
        .createIndex("idx_sp_org")
        .ifNotExists()
        .on("security_policies")
        .column("organization_id")
        .execute();

      await db.schema
        .createIndex("idx_se_org")
        .ifNotExists()
        .on("security_events")
        .column("organization_id")
        .execute();
    },
  };
}
