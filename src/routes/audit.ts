/**
 * @file audit.ts
 * @module src/routes
 *
 * REST API router for enterprise security audit logs & analytics (M6B).
 */

import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { getConfig } from "../config";
import { getAuditLogger } from "../logging/audit-logger";
import { getLogger } from "../logging/logger";
import { getSecurityAnalytics } from "../logging/audit-analytics";
import { exportSecurityEventsAsCSV, exportSecurityEventsAsJSON } from "../logging/audit-export";
import { getSecurityEventById, querySecurityEvents } from "../logging/audit-query";
import { authMiddleware, optionalAuthMiddleware, requireRole } from "../auth/middleware";

export const auditRoutes = new Hono();

// ── Validation Schemas ───────────────────────────────────────────────────────

const AuditEventsQuerySchema = z.object({
  action: z.enum(["allow", "mask", "block"]).optional(),
  riskLevel: z.enum(["low", "medium", "high", "critical"]).optional(),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  maxRiskScore: z.coerce.number().min(0).max(100).optional(),
  provider: z.string().optional(),
  model: z.string().optional(),
  detector: z.string().optional(),
  category: z.string().optional(),
  subtype: z.string().optional(),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  requestId: z.string().optional(),
  eventId: z.string().optional(),
  limit: z.coerce.number().min(1).max(500).default(50),
  offset: z.coerce.number().min(0).default(0),
  sortBy: z.enum(["timestamp", "riskScore", "latencyMs"]).default("timestamp"),
  sortOrder: z.enum(["asc", "desc"]).default("desc"),
});

const AuditStatsQuerySchema = z.object({
  timeframe: z.enum(["1h", "24h", "7d", "30d", "all"]).default("24h"),
});

const AuditExportQuerySchema = z.object({
  format: z.enum(["csv", "json"]).default("json"),
  action: z.enum(["allow", "mask", "block"]).optional(),
  riskLevel: z.enum(["low", "medium", "high", "critical"]).optional(),
  provider: z.string().optional(),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  limit: z.coerce.number().min(1).max(5000).default(1000),
});

const AuditCleanupSchema = z.object({
  retentionDays: z.coerce.number().optional(),
});

// ── Handlers ─────────────────────────────────────────────────────────────────

/**
 * GET /api/audit/events - Query and filter security audit events
 */
auditRoutes.get("/events", zValidator("query", AuditEventsQuerySchema), async (c) => {
  const filter = c.req.valid("query");
  const result = await querySecurityEvents(filter);

  return c.json({
    events: result.events,
    pagination: {
      total: result.total,
      limit: result.limit,
      offset: result.offset,
      hasMore: result.offset + result.events.length < result.total,
    },
  });
});

/**
 * GET /api/audit/events/:eventId - Retrieve single event by ID or eventId
 */
auditRoutes.get("/events/:eventId", async (c) => {
  const eventId = c.req.param("eventId");
  const event = await getSecurityEventById(eventId);

  if (!event) {
    return c.json(
      {
        error: {
          message: `Security event '${eventId}' not found`,
          type: "not_found",
        },
      },
      404,
    );
  }

  return c.json({ event });
});

/**
 * GET /api/audit/stats - Real-time security & threat analytics
 */
auditRoutes.get("/stats", zValidator("query", AuditStatsQuerySchema), async (c) => {
  const { timeframe } = c.req.valid("query");
  const stats = await getSecurityAnalytics(timeframe);

  return c.json({ stats });
});

/**
 * GET /api/audit/export - Compliance audit export (CSV or JSON format)
 * Requires ADMIN or SECURITY_ANALYST role.
 */
auditRoutes.get("/export", authMiddleware, requireRole(["ADMIN", "SECURITY_ANALYST"]), zValidator("query", AuditExportQuerySchema), async (c) => {
  const { format, ...filter } = c.req.valid("query");
  const result = await querySecurityEvents(filter);

  const timestampStr = new Date().toISOString().slice(0, 10);

  if (format === "csv") {
    const csvContent = exportSecurityEventsAsCSV(result.events);
    return new Response(csvContent, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="promptwall-audit-${timestampStr}.csv"`,
      },
    });
  }

  const jsonContent = exportSecurityEventsAsJSON(result.events);
  return new Response(jsonContent, {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="promptwall-audit-${timestampStr}.json"`,
    },
  });
});

/**
 * POST /api/audit/cleanup - Trigger manual retention cleanup
 * Requires ADMIN role.
 */
auditRoutes.post("/cleanup", authMiddleware, requireRole(["ADMIN"]), async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));
    const parseResult = AuditCleanupSchema.safeParse(body);
    const customDays = parseResult.success ? parseResult.data.retentionDays : undefined;

    const config = getConfig();
    const retentionDays = customDays ?? config.logging.retention_days;

    const auditLogger = getAuditLogger();
    const requestLogger = getLogger();

    const auditDeleted = await (async () => {
      try {
        return await auditLogger.cleanup(retentionDays);
      } catch {
        return 0;
      }
    })();

    const requestLogsDeleted = await (async () => {
      try {
        return await requestLogger.cleanup();
      } catch {
        return 0;
      }
    })();

    return c.json({
      success: true,
      retentionDays,
      cleaned: {
        securityEvents: auditDeleted,
        requestLogs: requestLogsDeleted,
        total: auditDeleted + requestLogsDeleted,
      },
    });
  } catch (error) {
    console.error("[Audit Cleanup Route Error]:", error);
    return c.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Cleanup failed",
      },
      500,
    );
  }
});
