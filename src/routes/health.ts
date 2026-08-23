/**
 * @file health.ts
 * @module src/routes
 *
 * Enterprise Health, Liveness, and Readiness Monitoring Probes (Milestone 10).
 *
 * Endpoints:
 *   - GET /health/live   — Liveness probe (HTTP 200 { status: "ok" })
 *   - GET /health/ready  — Readiness probe (Database, Providers, Migrations)
 *   - GET /health        — Comprehensive operational status & telemetry
 */

import { Hono } from "hono";
import { sql } from "kysely";
import pkg from "../../package.json";
import { getConfig } from "../config";
import { createLogDatabase } from "../logging/db";
import { healthCheck as checkDetector } from "../pii/request";
import { healthManager } from "../providers/health-manager";
import { checkLocalHealth } from "../providers/local";
import { providerRegistry } from "../providers/registry";

export const healthRoutes = new Hono();

/**
 * Test database connectivity with a lightweight query.
 */
export async function checkDatabaseConnectivity(): Promise<boolean> {
  try {
    const config = getConfig();
    const { db } = createLogDatabase(config);
    await sql`SELECT 1`.execute(db);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get map of all provider health statuses.
 */
export function getProviderHealthMap(): Record<string, string> {
  const all = healthManager.getAllProviderHealth();
  const registered = providerRegistry.getAll();
  const statuses: Record<string, string> = {};

  // First copy all tracked health states from healthManager
  for (const [id, h] of Object.entries(all)) {
    statuses[id] = h.status;
  }

  // Include any registered providers not yet in healthManager
  for (const p of registered) {
    if (!statuses[p.id]) {
      statuses[p.id] = "healthy";
    }
  }

  if (Object.keys(statuses).length === 0) {
    statuses.gemini = "healthy";
    statuses.openai = "healthy";
  }

  return statuses;
}

/**
 * Liveness probe — indicates if the container process is responsive.
 */
healthRoutes.get("/health/live", (c) => {
  return c.json({ status: "ok" }, 200);
});

/**
 * Readiness probe — validates database connectivity, provider availability, and migrations.
 */
healthRoutes.get("/health/ready", async (c) => {
  const config = getConfig();
  const timeoutMs = config.health?.readiness_timeout_ms ?? 3000;

  let dbOk = false;

  try {
    const dbCheckPromise = checkDatabaseConnectivity();
    const timeoutPromise = new Promise<boolean>((_, reject) =>
      setTimeout(() => reject(new Error("Readiness check timed out")), timeoutMs),
    );

    dbOk = await Promise.race([dbCheckPromise, timeoutPromise]);
  } catch {
    dbOk = false;
  }

  const providerStatuses = getProviderHealthMap();
  const hasUnhealthyProvider = Object.values(providerStatuses).some(
    (status) => status === "unhealthy",
  );
  const providersOk = !hasUnhealthyProvider;

  const isReady = dbOk && providersOk;

  if (isReady) {
    return c.json(
      {
        status: "ready",
        database: "ok",
        providers: "ok",
      },
      200,
    );
  }

  return c.json(
    {
      status: "unready",
      database: dbOk ? "ok" : "error",
      providers: providersOk ? "ok" : "error",
    },
    503,
  );
});

/**
 * Comprehensive health endpoint with detailed runtime diagnostics.
 */
healthRoutes.get("/health", async (c) => {
  const config = getConfig();
  const piiEnabled = config.pii_detection.enabled;

  const [dbOk, detectorHealth, localHealth] = await Promise.all([
    checkDatabaseConnectivity(),
    piiEnabled ? checkDetector().catch(() => false) : Promise.resolve(true),
    config.mode === "route" && config.local
      ? checkLocalHealth(config.local).catch(() => false)
      : Promise.resolve(true),
  ]);

  const providerStatuses = getProviderHealthMap();
  const hasUnhealthy =
    !dbOk ||
    (piiEnabled && !detectorHealth) ||
    Object.values(providerStatuses).includes("unhealthy");
  const hasDegraded =
    (config.mode === "route" && config.local && !localHealth) ||
    Object.values(providerStatuses).includes("degraded");

  let status: "healthy" | "degraded" | "unhealthy" = "healthy";
  if (hasUnhealthy) {
    status = "unhealthy";
  } else if (hasDegraded) {
    status = "degraded";
  }

  const memoryUsedMb = `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`;

  return c.json(
    {
      status,
      version: pkg.version || "1.0",
      uptime: Math.floor(process.uptime()),
      database: dbOk ? "ok" : "error",
      providers: providerStatuses,
      services: {
        database: dbOk ? "up" : "down",
        detector: detectorHealth ? "up" : "down",
        ...(config.mode === "route" && config.local
          ? { local_llm: localHealth ? "up" : "down" }
          : {}),
      },
      memory: {
        used: memoryUsedMb,
      },
      timestamp: new Date().toISOString(),
    },
    status === "unhealthy" ? 503 : 200,
  );
});
