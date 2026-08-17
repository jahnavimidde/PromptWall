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
  created_at: ColumnType<string | null, string | undefined, never>;
}

export interface UsersTable {
  id: string;
  email: string;
  password_hash: string;
  role: string; // "ADMIN" | "SECURITY_ANALYST" | "VIEWER"
  created_at: ColumnType<string | null, string | undefined, never>;
  updated_at: ColumnType<string | null, string | undefined, never>;
}

export interface LogDatabase {
  request_logs: RequestLogsTable;
  security_events: SecurityEventsTable;
  security_policies: SecurityPoliciesTable;
  security_policy_versions: SecurityPolicyVersionsTable;
  users: UsersTable;
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
