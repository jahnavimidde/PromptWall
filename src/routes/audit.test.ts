/**
 * @file audit.test.ts
 * @module src/routes
 *
 * M6B Route Integration Tests for Audit REST API (/api/audit/*).
 */

import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { buildSecurityEvent, type Candidate, type PipelineResult } from "@promptwall/engine";
import { SqliteAuditLogger } from "../logging/audit-logger";
import { signUserToken } from "../auth/jwt";
import { auditRoutes } from "./audit";

function makeCandidate(subtype: string, category: "secret" | "pii" | "malicious" = "secret", detector = "test-detector"): Candidate {
  return {
    id: crypto.randomUUID(),
    category,
    subtype,
    value: "secret-val",
    normalizedValue: "secret-val",
    location: { start: 0, end: 10 },
    confidence: 0.99,
    severity: "critical",
    detector,
    evidence: [],
    metadata: {},
  };
}

function makePipelineResult(action: "allow" | "mask" | "block", riskScore: number, candidates: Candidate[] = []): PipelineResult {
  const level = riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low";
  return {
    candidates,
    detectionResult: {
      candidates,
      errors: [],
      warnings: [],
      detectorStats: [],
      executionTimeMs: 5,
      pipelineExecutionTime: 5,
      registryVersion: 1,
    },
    riskAssessment: {
      score: riskScore,
      level,
      factors: [],
      candidateIds: candidates.map((c) => c.id),
      summary: "summary",
    },
    policyDecision: {
      action,
      reason: `Action ${action}`,
      matchedRuleIds: [action],
      riskScore,
      riskLevel: level,
      candidateIds: candidates.map((c) => c.id),
    },
  };
}

describe("M6B — Audit REST API Routes (/api/audit/*)", () => {
  const app = new Hono();
  app.route("/api/audit", auditRoutes);

  test("GET /api/audit/events returns query results with pagination", async () => {
    const logger = new SqliteAuditLogger();
    const ev = buildSecurityEvent(makePipelineResult("block", 90, [makeCandidate("AWS_KEY")]), {
      requestId: "req-api-query",
      provider: "openai",
      model: "gpt-4o",
      latencyMs: 15,
    });
    await logger.log(ev);

    const res = await app.request("/api/audit/events?action=block&limit=10");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { events: Array<{ requestId: string }>; pagination: { total: number } };
    expect(body.events).toBeDefined();
    expect(body.events.length).toBeGreaterThanOrEqual(1);
    expect(body.pagination.total).toBeGreaterThanOrEqual(1);
  });

  test("GET /api/audit/events/:eventId returns single event or 404", async () => {
    const logger = new SqliteAuditLogger();
    const ev = buildSecurityEvent(makePipelineResult("allow", 10), {
      requestId: "req-single-api",
      provider: "gemini",
      model: "gemini-2.0-flash",
      latencyMs: 8,
    });
    await logger.log(ev);

    // Fetch existing
    const resFound = await app.request(`/api/audit/events/${ev.eventId}`);
    expect(resFound.status).toBe(200);

    const bodyFound = (await resFound.json()) as { event: { eventId: string } };
    expect(bodyFound.event.eventId).toBe(ev.eventId);

    // Fetch non-existent
    const resNotFound = await app.request("/api/audit/events/non-existent-event-id");
    expect(resNotFound.status).toBe(404);
  });

  test("GET /api/audit/stats returns real-time risk analytics", async () => {
    const res = await app.request("/api/audit/stats?timeframe=24h");
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      stats: {
        totalEvents: number;
        actionBreakdown: { allow: number; mask: number; block: number };
        latencyMetrics: { avg: number };
      };
    };

    expect(body.stats).toBeDefined();
    expect(typeof body.stats.totalEvents).toBe("number");
    expect(body.stats.actionBreakdown).toBeDefined();
    expect(body.stats.latencyMetrics).toBeDefined();
  });

  test("GET /api/audit/export returns JSON and CSV attachments", async () => {
    const adminToken = await signUserToken("usr_admin", "admin@promptwall.com", "ADMIN");

    // JSON export
    const jsonRes = await app.request("/api/audit/export?format=json", {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(jsonRes.status).toBe(200);
    expect(jsonRes.headers.get("Content-Type")).toContain("application/json");

    // CSV export
    const csvRes = await app.request("/api/audit/export?format=csv", {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(csvRes.status).toBe(200);
    expect(csvRes.headers.get("Content-Type")).toContain("text/csv");
    const csvText = await csvRes.text();
    expect(csvText).toContain("eventId,requestId,timestamp");
  });

  test("POST /api/audit/cleanup triggers retention cleanup", async () => {
    const adminToken = await signUserToken("usr_admin", "admin@promptwall.com", "ADMIN");

    const res = await app.request("/api/audit/cleanup", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; cleaned: { total: number } };
    expect(body.success).toBe(true);
    expect(body.cleaned).toBeDefined();
    expect(typeof body.cleaned.total).toBe("number");
  });
});
