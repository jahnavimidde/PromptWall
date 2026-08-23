/**
 * @file auth.test.ts
 * @module src/auth
 *
 * M7B/M7C Unit & Integration Tests for Authentication, JWT & RBAC.
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import type { LogDatabase } from "../logging/db";
import { migrateLogDatabase } from "../logging/db";
import { authRoutes } from "../routes/auth";
import { signUserToken, verifyUserToken } from "./jwt";
import { authMiddleware, requireRole } from "./middleware";
import { hasPermission, isValidRole } from "./permissions";
import { UserStore } from "./user-store";

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

describe("M7B & M7C — Authentication & RBAC Engine", () => {
  test("UserStore creates users and verifies passwords safely using Bun.password", async () => {
    const db = await createInMemoryDb();
    const userStore = new UserStore({ db });

    const user = await userStore.createUser(
      "analyst@promptwall.com",
      "SecurePassword123!",
      "SECURITY_ANALYST",
    );

    expect(user.id).toMatch(/^usr_/);
    expect(user.email).toBe("analyst@promptwall.com");
    expect(user.role).toBe("SECURITY_ANALYST");
    expect(user.passwordHash).not.toBe("SecurePassword123!");

    // Verify valid password
    const valid = await userStore.verifyPassword("SecurePassword123!", user.passwordHash);
    expect(valid).toBe(true);

    // Verify invalid password
    const invalid = await userStore.verifyPassword("WrongPassword!", user.passwordHash);
    expect(invalid).toBe(false);

    // Duplicate email rejected
    expect(userStore.createUser("analyst@promptwall.com", "Pass", "VIEWER")).rejects.toThrow();
  });

  test("JWT signing and verification", async () => {
    const token = await signUserToken("usr_123", "admin@promptwall.com", "ADMIN");
    expect(typeof token).toBe("string");

    const payload = await verifyUserToken(token);
    expect(payload).toBeDefined();
    expect(payload?.sub).toBe("usr_123");
    expect(payload?.email).toBe("admin@promptwall.com");
    expect(payload?.role).toBe("ADMIN");

    // Invalid token returns null
    const invalidPayload = await verifyUserToken("invalid.jwt.token");
    expect(invalidPayload).toBeNull();
  });

  test("RBAC permissions matrix", () => {
    expect(hasPermission("ADMIN", "policies:manage")).toBe(true);
    expect(hasPermission("ADMIN", "audit:cleanup")).toBe(true);
    expect(hasPermission("SECURITY_ANALYST", "policies:manage")).toBe(false);
    expect(hasPermission("SECURITY_ANALYST", "audit:export")).toBe(true);
    expect(hasPermission("VIEWER", "policies:manage")).toBe(false);
    expect(hasPermission("VIEWER", "audit:export")).toBe(false);
    expect(hasPermission("VIEWER", "audit:read")).toBe(true);

    expect(isValidRole("ADMIN")).toBe(true);
    expect(isValidRole("UNKNOWN")).toBe(false);
  });

  test("Auth REST routes (/api/auth/login & /api/auth/me)", async () => {
    const app = new Hono();
    app.route("/api/auth", authRoutes);

    const userStore = new UserStore();
    await userStore.createUser("testuser@promptwall.com", "Password123!", "ADMIN").catch(() => {});

    // Login with invalid credentials -> 401
    const resBad = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "testuser@promptwall.com", password: "WrongPassword" }),
    });
    expect(resBad.status).toBe(401);

    // Login with valid credentials -> 200 + token
    const resGood = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "testuser@promptwall.com", password: "Password123!" }),
    });
    expect(resGood.status).toBe(200);

    const body = (await resGood.json()) as { token: string; user: { role: string } };
    expect(body.token).toBeDefined();
    expect(body.user.role).toBe("ADMIN");

    // Access /api/auth/me with Bearer token -> 200
    const resMe = await app.request("/api/auth/me", {
      headers: { Authorization: `Bearer ${body.token}` },
    });
    expect(resMe.status).toBe(200);
    const bodyMe = (await resMe.json()) as { user: { email: string } };
    expect(bodyMe.user.email).toBe("testuser@promptwall.com");
  });

  test("requireRole middleware blocks unauthorized roles with 403 Forbidden", async () => {
    const app = new Hono();
    app.use("/admin-only", authMiddleware, requireRole(["ADMIN"]));
    app.get("/admin-only", (c) => c.json({ ok: true }));

    const analystToken = await signUserToken("usr_analyst", "analyst@test.com", "SECURITY_ANALYST");

    // Request as SECURITY_ANALYST to ADMIN route -> 403 Forbidden
    const resForbidden = await app.request("/admin-only", {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    expect(resForbidden.status).toBe(403);

    // Request as ADMIN -> 200 OK
    const adminToken = await signUserToken("usr_admin", "admin@test.com", "ADMIN");
    const resAllowed = await app.request("/admin-only", {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(resAllowed.status).toBe(200);
  });
});
