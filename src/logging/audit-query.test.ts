/**
 * @file audit-query.test.ts
 * @module src/logging
 *
 * M6B Unit Tests for Audit Query & Analytics Engines.
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { buildSecurityEvent, type Candidate, type PipelineResult } from "@promptwall/engine";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import { getSecurityAnalytics } from "./audit-analytics";
import { exportSecurityEventsAsCSV, exportSecurityEventsAsJSON } from "./audit-export";
import { SqliteAuditLogger } from "./audit-logger";
import { getSecurityEventById, querySecurityEvents } from "./audit-query";
import type { LogDatabase } from "./db";
import { migrateLogDatabase } from "./db";

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

function makeCandidate(
  subtype: string,
  category: "secret" | "pii" | "malicious" = "secret",
  detector = "test-detector",
): Candidate {
  return {
    id: crypto.randomUUID(),
    category,
    subtype,
    value: "sensitive-val",
    normalizedValue: "sensitive-val",
    location: { start: 0, end: 10 },
    confidence: 0.95,
    severity: "high",
    detector,
    evidence: [],
    metadata: {},
  };
}

function makePipelineResult(
  action: "allow" | "mask" | "block",
  riskScore: number,
  candidates: Candidate[] = [],
): PipelineResult {
  const level =
    riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low";
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

describe("M6B — Audit Query Engine", () => {
  test("filters by action, risk level, score range, provider, and detector", async () => {
    const db = await createInMemoryDb();
    const logger = new SqliteAuditLogger({ db });

    const ev1 = buildSecurityEvent(
      makePipelineResult("block", 90, [makeCandidate("AWS_KEY", "secret", "secret-regex")]),
      {
        requestId: "req-1",
        provider: "openai",
        model: "gpt-4o",
        latencyMs: 10,
      },
    );
    const ev2 = buildSecurityEvent(makePipelineResult("allow", 10, []), {
      requestId: "req-2",
      provider: "gemini",
      model: "gemini-2.0-flash",
      latencyMs: 20,
    });
    const ev3 = buildSecurityEvent(
      makePipelineResult("mask", 65, [makeCandidate("EMAIL", "pii", "pii-gliner")]),
      {
        requestId: "req-3",
        provider: "anthropic",
        model: "claude-3-5",
        latencyMs: 30,
      },
    );

    await logger.log(ev1);
    await logger.log(ev2);
    await logger.log(ev3);

    // Filter by action=block
    const blocks = await querySecurityEvents({ action: "block" }, db);
    expect(blocks.events).toHaveLength(1);
    expect(blocks.events[0].requestId).toBe("req-1");

    // Filter by riskLevel=high
    const highRisk = await querySecurityEvents({ riskLevel: "high" }, db);
    expect(highRisk.events).toHaveLength(1);
    expect(highRisk.events[0].requestId).toBe("req-3");

    // Filter by score range
    const scoreRange = await querySecurityEvents({ minRiskScore: 50, maxRiskScore: 95 }, db);
    expect(scoreRange.events).toHaveLength(2);

    // Filter by provider
    const geminiRes = await querySecurityEvents({ provider: "gemini" }, db);
    expect(geminiRes.events).toHaveLength(1);

    // Filter by detector
    const piiGlinerRes = await querySecurityEvents({ detector: "pii-gliner" }, db);
    expect(piiGlinerRes.events).toHaveLength(1);

    // Filter by candidate category
    const secretCategoryRes = await querySecurityEvents({ category: "secret" }, db);
    expect(secretCategoryRes.events).toHaveLength(1);

    // Filter by candidate subtype
    const emailSubtypeRes = await querySecurityEvents({ subtype: "EMAIL" }, db);
    expect(emailSubtypeRes.events).toHaveLength(1);

    await logger.close();
  });

  test("supports pagination and custom sorting", async () => {
    const db = await createInMemoryDb();
    const logger = new SqliteAuditLogger({ db });

    for (let i = 1; i <= 5; i++) {
      const ev = buildSecurityEvent(
        makePipelineResult(i % 2 === 0 ? "block" : "allow", i * 15, []),
        {
          requestId: `req-sort-${i}`,
          provider: "openai",
          model: "gpt-4",
          latencyMs: i * 10,
        },
      );
      await logger.log(ev);
    }

    // Sort by latencyMs asc
    const ascLatency = await querySecurityEvents(
      { sortBy: "latencyMs", sortOrder: "asc", limit: 2, offset: 0 },
      db,
    );
    expect(ascLatency.events).toHaveLength(2);
    expect(ascLatency.total).toBe(5);
    expect(ascLatency.events[0].latencyMs).toBe(10);
    expect(ascLatency.events[1].latencyMs).toBe(20);

    // Sort by riskScore desc
    const descRisk = await querySecurityEvents(
      { sortBy: "riskScore", sortOrder: "desc", limit: 2, offset: 0 },
      db,
    );
    expect(descRisk.events[0].riskScore).toBe(75);
    expect(descRisk.events[1].riskScore).toBe(60);

    await logger.close();
  });

  test("getSecurityEventById returns correct single event", async () => {
    const db = await createInMemoryDb();
    const logger = new SqliteAuditLogger({ db });

    const ev = buildSecurityEvent(
      makePipelineResult("block", 85, [makeCandidate("CREDIT_CARD", "pii")]),
      {
        requestId: "req-single",
        provider: "openai",
        model: "gpt-4o",
        latencyMs: 15,
      },
    );
    await logger.log(ev);

    const fetched = await getSecurityEventById(ev.eventId, db);
    expect(fetched).toBeDefined();
    expect(fetched?.eventId).toBe(ev.eventId);
    expect(fetched?.requestId).toBe("req-single");

    const nonExistent = await getSecurityEventById("non-existent-id", db);
    expect(nonExistent).toBeNull();

    await logger.close();
  });
});

describe("M6B — Analytics & Export Engine", () => {
  test("computes accurate analytics breakdown and percentiles", async () => {
    const db = await createInMemoryDb();
    const logger = new SqliteAuditLogger({ db });

    await logger.log(
      buildSecurityEvent(
        makePipelineResult("block", 90, [makeCandidate("AWS_KEY", "secret", "secret-regex")]),
        { requestId: "1", provider: "openai", model: "m", latencyMs: 10 },
      ),
    );
    await logger.log(
      buildSecurityEvent(
        makePipelineResult("mask", 60, [makeCandidate("EMAIL", "pii", "pii-gliner")]),
        { requestId: "2", provider: "openai", model: "m", latencyMs: 20 },
      ),
    );
    await logger.log(
      buildSecurityEvent(makePipelineResult("allow", 10, []), {
        requestId: "3",
        provider: "openai",
        model: "m",
        latencyMs: 30,
      }),
    );

    const analytics = await getSecurityAnalytics("all", db);

    expect(analytics.totalEvents).toBe(3);
    expect(analytics.actionBreakdown.block).toBe(1);
    expect(analytics.actionBreakdown.mask).toBe(1);
    expect(analytics.actionBreakdown.allow).toBe(1);
    expect(analytics.actionBreakdown.blockPercentage).toBe(33.3);

    expect(analytics.riskLevelDistribution.critical).toBe(1);
    expect(analytics.riskLevelDistribution.high).toBe(1);
    expect(analytics.riskLevelDistribution.low).toBe(1);

    expect(analytics.latencyMetrics.avg).toBe(20);
    expect(analytics.latencyMetrics.max).toBe(30);

    expect(analytics.topDetectors.map((d) => d.detector)).toContain("secret-regex");
    expect(analytics.topThreatSubtypes.map((s) => s.subtype)).toContain("AWS_KEY");

    await logger.close();
  });

  test("exports events as JSON and CSV without raw content", async () => {
    const db = await createInMemoryDb();
    const logger = new SqliteAuditLogger({ db });

    const rawSecret = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const ev = buildSecurityEvent(
      makePipelineResult("block", 95, [makeCandidate("AWS_KEY", "secret", "secret-regex")]),
      {
        requestId: "req-exp",
        provider: "openai",
        model: "gpt-4",
        latencyMs: 12,
      },
    );
    await logger.log(ev);

    const queryResult = await querySecurityEvents({}, db);

    // JSON export
    const jsonStr = exportSecurityEventsAsJSON(queryResult.events);
    expect(jsonStr).toContain('"requestId": "req-exp"');
    expect(jsonStr).not.toContain(rawSecret);

    // CSV export
    const csvStr = exportSecurityEventsAsCSV(queryResult.events);
    expect(csvStr).toContain("eventId,requestId,timestamp");
    expect(csvStr).toContain("req-exp");
    expect(csvStr).not.toContain(rawSecret);

    await logger.close();
  });
});
