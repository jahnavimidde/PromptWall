/**
 * @file user-store.ts
 * @module src/auth
 *
 * User management and password authentication store (M7C).
 * Uses Bun.password hashing for secure credentials storage.
 */

import { getConfig } from "../config";
import { createLogDatabase, type LogKysely, migrateLogDatabase } from "../logging/db";
import type { Role } from "./permissions";

export interface StoredUser {
  id: string;
  email: string;
  passwordHash: string;
  role: Role;
  /** M12: organization this user belongs to */
  organizationId: string | null;
  /** M12: org-scoped role within the user's organization */
  orgRole: string | null;
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

export class UserStore {
  private readonly db: LogKysely;
  private readonly ready: Promise<void>;

  constructor(options: { db?: LogKysely } = {}) {
    const { db, ready } = getDb(options.db);
    this.db = db;
    this.ready = ready;
  }

  /**
   * Create a new user with hashed password.
   */
  async createUser(
    email: string,
    plainPassword: string,
    role: Role = "VIEWER",
    organizationId: string | null = null,
    orgRole: string | null = null,
  ): Promise<StoredUser> {
    await this.ready;

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await this.findUserByEmail(normalizedEmail);
    if (existing) {
      throw new Error(`User with email '${normalizedEmail}' already exists`);
    }

    const id = `usr_${crypto.randomUUID().slice(0, 8)}`;
    const passwordHash = await Bun.password.hash(plainPassword, {
      algorithm: "bcrypt",
      cost: 10,
    });
    const now = new Date().toISOString();

    await this.db
      .insertInto("users")
      .values({
        id,
        email: normalizedEmail,
        password_hash: passwordHash,
        role,
        organization_id: organizationId,
        org_role: orgRole,
        created_at: now,
        updated_at: now,
      })
      .execute();

    return {
      id,
      email: normalizedEmail,
      passwordHash,
      role,
      organizationId,
      orgRole,
      createdAt: now,
      updatedAt: now,
    };
  }

  /**
   * Find user by email.
   */
  async findUserByEmail(email: string): Promise<StoredUser | null> {
    await this.ready;

    const normalizedEmail = email.trim().toLowerCase();
    const row = await this.db
      .selectFrom("users")
      .selectAll()
      .where("email", "=", normalizedEmail)
      .executeTakeFirst();

    if (!row) return null;

    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      role: row.role as Role,
      organizationId: row.organization_id ?? null,
      orgRole: row.org_role ?? null,
      createdAt: row.created_at ?? new Date().toISOString(),
      updatedAt: row.updated_at ?? new Date().toISOString(),
    };
  }

  /**
   * Verify plain password against stored hash.
   */
  async verifyPassword(plainPassword: string, passwordHash: string): Promise<boolean> {
    try {
      return await Bun.password.verify(plainPassword, passwordHash);
    } catch {
      return false;
    }
  }

  /**
   * Seed initial admin account from environment variables if no users exist.
   */
  async seedAdminFromEnv(): Promise<StoredUser | null> {
    await this.ready;

    const adminEmail = process.env.PROMPTWALL_ADMIN_EMAIL;
    const adminPassword = process.env.PROMPTWALL_ADMIN_PASSWORD;

    if (!adminEmail || !adminPassword) {
      return null;
    }

    const countResult = await this.db
      .selectFrom("users")
      .select((eb) => eb.fn.countAll<number>().as("count"))
      .executeTakeFirst();

    if (Number(countResult?.count ?? 0) > 0) {
      return null;
    }

    console.log(`[UserStore] Seeding initial admin user: ${adminEmail}`);
    return await this.createUser(adminEmail, adminPassword, "ADMIN", "org_system", "ORG_ADMIN");
  }
}
