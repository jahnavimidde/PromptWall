/**
 * @file org-store.ts
 * @module src/organizations
 *
 * Database persistence layer for tenant organizations (M12A).
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 * Every query that touches tenant-owned data (users, policies, audit events,
 * API keys) MUST include organization_id filtering. This store handles the
 * organizations table itself; tenant-scoped queries on other tables are in
 * their respective stores.
 */

import { getConfig } from "../config";
import { createLogDatabase, type LogKysely, migrateLogDatabase } from "../logging/db";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface StoredOrg {
  id: string;
  name: string;
  slug: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateOrgInput {
  name: string;
  /** URL-safe unique identifier, e.g. "acme-corp" */
  slug: string;
}

export interface UpdateOrgInput {
  name?: string;
  slug?: string;
}

// ── Singleton DB instance (mirrors UserStore / PolicyStore pattern) ────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateOrgId(): string {
  return `org_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

function rowToStoredOrg(row: {
  id: string;
  name: string;
  slug: string;
  created_at: string | null;
  updated_at: string | null;
}): StoredOrg {
  const now = new Date().toISOString();
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    createdAt: row.created_at ?? now,
    updatedAt: row.updated_at ?? now,
  };
}

// ── OrgStore ─────────────────────────────────────────────────────────────────

/**
 * CRUD store for the `organizations` table.
 *
 * Accepts an optional injected `db` for testing (same pattern as UserStore,
 * PolicyStore). In production, uses the module-level singleton.
 */
export class OrgStore {
  private readonly db: LogKysely;
  private readonly ready: Promise<void>;

  constructor(options: { db?: LogKysely } = {}) {
    const { db, ready } = getDb(options.db);
    this.db = db;
    this.ready = ready;
  }

  /**
   * Create a new organization.
   * Throws if the slug is already taken.
   */
  async createOrganization(input: CreateOrgInput): Promise<StoredOrg> {
    await this.ready;

    const existing = await this.getOrganizationBySlug(input.slug);
    if (existing) {
      throw new Error(`Organization with slug '${input.slug}' already exists`);
    }

    const id = generateOrgId();
    const now = new Date().toISOString();

    await this.db
      .insertInto("organizations")
      .values({
        id,
        name: input.name,
        slug: input.slug,
        created_at: now,
        updated_at: now,
      })
      .execute();

    return { id, name: input.name, slug: input.slug, createdAt: now, updatedAt: now };
  }

  /**
   * Fetch a single organization by primary key.
   * Returns null if not found.
   */
  async getOrganization(id: string): Promise<StoredOrg | null> {
    await this.ready;

    const row = await this.db
      .selectFrom("organizations")
      .selectAll()
      .where("id", "=", id)
      .executeTakeFirst();

    return row ? rowToStoredOrg(row) : null;
  }

  /**
   * Fetch a single organization by its unique slug.
   * Returns null if not found.
   */
  async getOrganizationBySlug(slug: string): Promise<StoredOrg | null> {
    await this.ready;

    const row = await this.db
      .selectFrom("organizations")
      .selectAll()
      .where("slug", "=", slug)
      .executeTakeFirst();

    return row ? rowToStoredOrg(row) : null;
  }

  /**
   * List all organizations ordered by creation date (newest first).
   * Reserved for global ADMIN use — non-admin access is restricted at the route layer.
   */
  async listOrganizations(): Promise<StoredOrg[]> {
    await this.ready;

    const rows = await this.db
      .selectFrom("organizations")
      .selectAll()
      .orderBy("created_at", "desc")
      .execute();

    return rows.map(rowToStoredOrg);
  }

  /**
   * Update organization name and/or slug.
   * Throws if new slug conflicts with an existing organization.
   */
  async updateOrganization(id: string, input: UpdateOrgInput): Promise<StoredOrg> {
    await this.ready;

    if (input.slug) {
      const conflict = await this.getOrganizationBySlug(input.slug);
      if (conflict && conflict.id !== id) {
        throw new Error(`Organization with slug '${input.slug}' already exists`);
      }
    }

    const now = new Date().toISOString();

    await this.db
      .updateTable("organizations")
      .set({
        ...(input.name ? { name: input.name } : {}),
        ...(input.slug ? { slug: input.slug } : {}),
        updated_at: now,
      })
      .where("id", "=", id)
      .execute();

    const updated = await this.getOrganization(id);
    if (!updated) {
      throw new Error(`Organization '${id}' not found after update`);
    }
    return updated;
  }

  /**
   * Hard-delete an organization.
   * Callers must ensure no users, policies, or audit data reference this org
   * before deleting (enforced at the route layer).
   */
  async deleteOrganization(id: string): Promise<void> {
    await this.ready;

    await this.db.deleteFrom("organizations").where("id", "=", id).execute();
  }

  /**
   * Count of users belonging to the given organization.
   * Used to prevent deletion of orgs that still have members.
   */
  async getOrgMemberCount(orgId: string): Promise<number> {
    await this.ready;

    const result = await this.db
      .selectFrom("users")
      .select((eb) => eb.fn.countAll<number>().as("count"))
      .where("organization_id", "=", orgId)
      .executeTakeFirst();

    return Number(result?.count ?? 0);
  }
}
