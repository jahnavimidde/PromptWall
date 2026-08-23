import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { basicAuth } from "hono/basic-auth";
import { tailwind } from "hono-tailwind";
import { z } from "zod";
import { getConfig } from "../config";
import { getLogger } from "../logging/logger";
import { getSecurityAnalytics } from "../logging/audit-analytics";
import { exportSecurityEventsAsCSV, exportSecurityEventsAsJSON } from "../logging/audit-export";
import { getSecurityEventById, querySecurityEvents } from "../logging/audit-query";
import { getAuditLogger } from "../logging/audit-logger";
import DashboardPage from "../views/dashboard/page";

const LogsQuerySchema = z.object({
	limit: z.coerce.number().min(1).max(1000).default(100),
	offset: z.coerce.number().min(0).default(0),
});

const config = getConfig();

export const dashboardRoutes = new Hono();

dashboardRoutes.use("/tailwind.css", tailwind());

if (config.dashboard.auth) {
	dashboardRoutes.use(
		"*",
		basicAuth({
			username: config.dashboard.auth.username,
			password: config.dashboard.auth.password,
			realm: "PromptWall Dashboard",
		}),
	);
}

/**
 * GET /api/logs - Get recent request logs
 */
dashboardRoutes.get("/api/logs", zValidator("query", LogsQuerySchema), async (c) => {
	const { limit, offset } = c.req.valid("query");

	const logger = getLogger();
	const logs = await logger.getLogs(limit, offset);

	return c.json({
		logs,
		pagination: {
			limit,
			offset,
			count: logs.length,
		},
	});
});

/**
 * GET /api/stats - Get statistics
 */
dashboardRoutes.get("/api/stats", async (c) => {
	const config = getConfig();
	const logger = getLogger();
	const stats = await logger.getStats();
	const entityStats = await logger.getEntityStats();

	return c.json({
		...stats,
		entity_breakdown: entityStats,
		mode: config.mode,
	});
});

/**
 * GET /dashboard/api/audit/events - Get security audit events
 */
dashboardRoutes.get("/api/audit/events", async (c) => {
	const action = c.req.query("action") as "allow" | "mask" | "block" | undefined;
	const riskLevel = c.req.query("riskLevel") as "low" | "medium" | "high" | "critical" | undefined;
	const provider = c.req.query("provider");
	const limit = Number(c.req.query("limit") || 50);
	const offset = Number(c.req.query("offset") || 0);

	const result = await querySecurityEvents({
		action,
		riskLevel,
		provider,
		limit,
		offset,
	});

	return c.json(result);
});

/**
 * GET /dashboard/api/audit/stats - Get risk & security analytics
 */
dashboardRoutes.get("/api/audit/stats", async (c) => {
	const timeframe = (c.req.query("timeframe") || "24h") as "1h" | "24h" | "7d" | "30d" | "all";
	const stats = await getSecurityAnalytics(timeframe);

	return c.json({ stats });
});

/**
 * GET /dashboard/api/audit/export - CSV / JSON compliance export
 */
dashboardRoutes.get("/api/audit/export", async (c) => {
	const format = c.req.query("format") === "csv" ? "csv" : "json";
	const action = c.req.query("action") as "allow" | "mask" | "block" | undefined;
	const riskLevel = c.req.query("riskLevel") as "low" | "medium" | "high" | "critical" | undefined;

	const result = await querySecurityEvents({ action, riskLevel, limit: 1000 });
	const timestampStr = new Date().toISOString().slice(0, 10);

	if (format === "csv") {
		const csvContent = exportSecurityEventsAsCSV(result.events);
		return new Response(csvContent, {
			headers: {
				"Content-Type": "text/csv; charset=utf-8",
				"Content-Disposition": `attachment; filename="promptwall-security-audit-${timestampStr}.csv"`,
			},
		});
	}

	const jsonContent = exportSecurityEventsAsJSON(result.events);
	return new Response(jsonContent, {
		headers: {
			"Content-Type": "application/json; charset=utf-8",
			"Content-Disposition": `attachment; filename="promptwall-security-audit-${timestampStr}.json"`,
		},
	});
});

/**
 * GET /dashboard - Dashboard HTML UI
 */
dashboardRoutes.get("/", (c) => {
	return c.html(<DashboardPage />);
});
