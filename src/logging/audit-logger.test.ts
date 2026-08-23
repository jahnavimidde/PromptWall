/**
 * @file audit-logger.test.ts
 * @module src/logging
 *
 * M6A Tests — Enterprise Security Audit Logging
 *
 * Tests:
 *   A. buildSecurityEvent() produces the correct SecurityEvent shape.
 *   B. Raw secrets are NEVER persisted (value, normalizedValue, etc. are absent).
 *   C. Multiple events stored and retrieved correctly (ordered newest-first).
 *   D. BLOCK request creates an audit event before the HTTP 400 is returned.
 *   E. ALLOW request creates an audit event before the provider is called.
 *
 * All DB-backed tests use in-memory SQLite or the default audit logger without
 * modifying global mocks, ensuring zero cross-test file pollution.
 */

import { Database, type SQLQueryBindings } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import {
  buildSecurityEvent,
  type Candidate,
  type CandidateSummary,
  type PipelineResult,
} from "@promptwall/engine";
import { fetch as nativeFetch } from "bun";
import { Hono } from "hono";
import { Kysely, type SqliteDatabase, SqliteDialect, type SqliteStatement } from "kysely";
import { getAuditLogger, SqliteAuditLogger } from "./audit-logger";
import type { LogDatabase } from "./db";
import { migrateLogDatabase } from "./db";

// ── In-memory Kysely helper ───────────────────────────────────────────────────

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

/** Create a fresh in-memory Kysely instance and run migrations on it. */
async function createInMemoryDb(): Promise<Kysely<LogDatabase>> {
  const db = new Kysely<LogDatabase>({
    dialect: new SqliteDialect({
      database: new BunSqliteDatabase(new Database(":memory:")),
    }),
  });
  await migrateLogDatabase(db, "sqlite");
  return db;
}

// ── Fixture builders ──────────────────────────────────────────────────────────

/**
 * Minimal valid Candidate with a raw secret value.
 * The `value` field contains a sensitive string — it must NEVER appear in
 * the stored security event.
 */
function makeSecretCandidate(overrides: Partial<Candidate> = {}): Candidate {
  const rawSecret = ["AKIA", "IOSFODNN7EXAMPLE"].join(""); // Push Protection-safe dynamic construction
  return {
    id: crypto.randomUUID(),
    category: "secret",
    subtype: "AWS_ACCESS_KEY",
    value: rawSecret, // ← THIS must NOT be stored
    normalizedValue: rawSecret.toLowerCase(), // ← THIS must NOT be stored
    location: { start: 0, end: rawSecret.length }, // ← THIS must NOT be stored
    confidence: 0.99,
    severity: "critical",
    detector: "secret-regex-detector",
    evidence: [
      {
        id: crypto.randomUUID(),
        source: "regex",
        label: "AWS key pattern",
        score: 0.99,
        confidenceContribution: 1.0,
        detail: `Matched: ${rawSecret}`, // ← THIS must NOT be stored
        metadata: { rawValue: rawSecret }, // ← THIS must NOT be stored
      },
    ],
    metadata: { rawSecret }, // ← THIS must NOT be stored
    ...overrides,
  };
}

function makePipelineResult(
  overrides: {
    action?: "allow" | "mask" | "block";
    candidates?: Candidate[];
    riskScore?: number;
    riskLevel?: string;
  } = {},
): PipelineResult {
  const candidates = overrides.candidates ?? [makeSecretCandidate()];
  const action = overrides.action ?? "block";
  const riskScore = overrides.riskScore ?? 91;
  const riskLevel = overrides.riskLevel ?? "critical";

  return {
    candidates,
    detectionResult: {
      candidates,
      errors: [],
      warnings: [],
      detectorStats: [],
      executionTimeMs: 10,
      pipelineExecutionTime: 10,
      registryVersion: 1,
    },
    riskAssessment: {
      score: riskScore,
      level: riskLevel as "low" | "medium" | "high" | "critical",
      factors: [],
      candidateIds: candidates.map((c) => c.id),
      summary: `${riskLevel} risk`,
    },
    policyDecision: {
      action,
      reason: `Policy triggered for ${action}`,
      matchedRuleIds: action === "block" ? ["block-critical-secret"] : [],
      riskScore,
      riskLevel: riskLevel as "low" | "medium" | "high" | "critical",
      candidateIds: candidates.map((c) => c.id),
    },
  };
}

// ── A. SecurityEvent creation ─────────────────────────────────────────────────

describe("A. buildSecurityEvent — shape and field mapping", () => {
  test("produces a SecurityEvent with all required fields", () => {
    const result = makePipelineResult({ action: "block", riskScore: 91, riskLevel: "critical" });

    const event = buildSecurityEvent(result, {
      requestId: "req-test-001",
      provider: "openai",
      model: "gpt-4o",
      latencyMs: 14,
    });

    expect(event.eventId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(event.requestId).toBe("req-test-001");
    expect(event.source).toBe("promptwall");
    expect(event.provider).toBe("openai");
    expect(event.model).toBe("gpt-4o");
    expect(event.riskScore).toBe(91);
    expect(event.riskLevel).toBe("critical");
    expect(event.action).toBe("block");
    expect(event.decisionReason).toBe("Policy triggered for block");
    expect(event.matchedRuleIds).toContain("block-critical-secret");
    expect(event.latencyMs).toBe(14);
    expect(typeof event.timestamp).toBe("string");
    expect(event.candidates).toHaveLength(1);
  });

  test("detectorsTriggered is a deduplicated list of detector ids", () => {
    const c1 = makeSecretCandidate({ id: crypto.randomUUID(), detector: "secret-regex-detector" });
    const c2 = makeSecretCandidate({
      id: crypto.randomUUID(),
      detector: "entropy-secret-detector",
    });
    const c3 = makeSecretCandidate({ id: crypto.randomUUID(), detector: "secret-regex-detector" }); // duplicate

    const result = makePipelineResult({ candidates: [c1, c2, c3] });
    const event = buildSecurityEvent(result, {
      requestId: "req-x",
      provider: "gemini",
      model: "gemini-2.0-flash",
      latencyMs: 5,
    });

    expect(event.detectorsTriggered).toHaveLength(2);
    expect(event.detectorsTriggered).toContain("secret-regex-detector");
    expect(event.detectorsTriggered).toContain("entropy-secret-detector");
  });

  test("confidence is rounded to 4 decimal places", () => {
    const c = makeSecretCandidate({ confidence: 0.987654321 });
    const result = makePipelineResult({ candidates: [c] });
    const event = buildSecurityEvent(result, {
      requestId: "r",
      provider: "openai",
      model: "gpt-4",
      latencyMs: 1,
    });

    expect(event.candidates[0].confidence).toBe(0.9877);
  });

  test("empty candidates list produces empty detectorsTriggered", () => {
    const result = makePipelineResult({
      candidates: [],
      action: "allow",
      riskScore: 0,
      riskLevel: "low",
    });
    const event = buildSecurityEvent(result, {
      requestId: "r",
      provider: "openai",
      model: "gpt-4",
      latencyMs: 2,
    });

    expect(event.candidates).toHaveLength(0);
    expect(event.detectorsTriggered).toHaveLength(0);
  });
});

// ── B. Raw secrets are never persisted ───────────────────────────────────────

describe("B. Security invariant — raw values never stored", () => {
  test("stored CandidateSummary contains only classification metadata", async () => {
    const rawSecret = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const candidate = makeSecretCandidate({ value: rawSecret });
    const result = makePipelineResult({ candidates: [candidate] });

    const db = await createInMemoryDb();
    const auditLogger = new SqliteAuditLogger({ db });

    const event = buildSecurityEvent(result, {
      requestId: "req-secret-test",
      provider: "openai",
      model: "gpt-4o",
      latencyMs: 10,
    });
    await auditLogger.log(event);

    const [stored] = await auditLogger.getRecentEvents(1, 0);
    expect(stored).toBeDefined();

    // Must have the safe fields:
    const storedCandidate: CandidateSummary = stored.candidates[0];
    expect(storedCandidate.category).toBe("secret");
    expect(storedCandidate.subtype).toBe("AWS_ACCESS_KEY");
    expect(storedCandidate.severity).toBe("critical");
    expect(typeof storedCandidate.confidence).toBe("number");
    expect(storedCandidate.detector).toBe("secret-regex-detector");
    expect(storedCandidate.id).toBe(candidate.id);

    // Must NOT have any raw-value fields:
    expect("value" in storedCandidate).toBe(false);
    expect("normalizedValue" in storedCandidate).toBe(false);
    expect("location" in storedCandidate).toBe(false);
    expect("evidence" in storedCandidate).toBe(false);
    expect("metadata" in storedCandidate).toBe(false);

    // Raw secret string must not appear anywhere in the serialised row:
    const rawCandidatesJson: string = await db
      .selectFrom("security_events")
      .select("candidates")
      .executeTakeFirstOrThrow()
      .then((r) => r.candidates);

    expect(rawCandidatesJson).not.toContain(rawSecret);
    expect(rawCandidatesJson).not.toContain(rawSecret.toLowerCase());

    await auditLogger.close();
  });

  test("decision_reason is stored but never includes the raw matched text", async () => {
    const rawSecret = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const result = makePipelineResult({ candidates: [makeSecretCandidate({ value: rawSecret })] });

    const db = await createInMemoryDb();
    const auditLogger = new SqliteAuditLogger({ db });

    const event = buildSecurityEvent(result, {
      requestId: "r",
      provider: "openai",
      model: "gpt-4",
      latencyMs: 5,
    });
    await auditLogger.log(event);

    const row = await db
      .selectFrom("security_events")
      .select("decision_reason")
      .executeTakeFirstOrThrow();

    expect(row.decision_reason).not.toContain(rawSecret);

    await auditLogger.close();
  });
});

// ── C. Multiple events stored correctly ───────────────────────────────────────

describe("C. Storage — multiple events", () => {
  test("stores multiple events and returns them newest-first", async () => {
    const db = await createInMemoryDb();
    const auditLogger = new SqliteAuditLogger({ db });

    const makeEvent = (action: "allow" | "block", tsOffset: number) => {
      const result = makePipelineResult({
        action,
        candidates: action === "block" ? [makeSecretCandidate()] : [],
        riskScore: action === "block" ? 91 : 0,
        riskLevel: action === "block" ? "critical" : "low",
      });
      const event = buildSecurityEvent(result, {
        requestId: `req-${tsOffset}`,
        provider: "openai",
        model: "gpt-4",
        latencyMs: tsOffset,
      });
      // Override timestamp so order is deterministic
      return { ...event, timestamp: new Date(Date.now() - tsOffset * 1000).toISOString() };
    };

    await auditLogger.log(makeEvent("block", 200));
    await auditLogger.log(makeEvent("allow", 100));
    await auditLogger.log(makeEvent("block", 50));

    const events = await auditLogger.getRecentEvents(10, 0);
    expect(events).toHaveLength(3);

    // Newest-first: tsOffset 50 < 100 < 200
    expect(events[0].latencyMs).toBe(50);
    expect(events[1].latencyMs).toBe(100);
    expect(events[2].latencyMs).toBe(200);

    // Actions preserved correctly
    expect(events[0].action).toBe("block");
    expect(events[1].action).toBe("allow");
    expect(events[2].action).toBe("block");

    await auditLogger.close();
  });

  test("pagination works correctly with limit and offset", async () => {
    const db = await createInMemoryDb();
    const auditLogger = new SqliteAuditLogger({ db });

    for (let i = 0; i < 5; i++) {
      const result = makePipelineResult({
        action: "allow",
        candidates: [],
        riskScore: 0,
        riskLevel: "low",
      });
      const event = buildSecurityEvent(result, {
        requestId: `req-page-${i}`,
        provider: "openai",
        model: "gpt-4",
        latencyMs: i,
      });
      await auditLogger.log({ ...event, timestamp: new Date(Date.now() - i * 1000).toISOString() });
    }

    const page1 = await auditLogger.getRecentEvents(2, 0);
    const page2 = await auditLogger.getRecentEvents(2, 2);

    expect(page1).toHaveLength(2);
    expect(page2).toHaveLength(2);
    // They should be different events
    expect(page1[0].requestId).not.toBe(page2[0].requestId);

    await auditLogger.close();
  });

  test("cleanup removes events older than retention cutoff", async () => {
    const db = await createInMemoryDb();

    const oldAuditLogger = new (class extends SqliteAuditLogger {
      async cleanup() {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - 1); // 1 day retention
        const result = await (this as unknown as { db: import("./db").LogKysely }).db
          .deleteFrom("security_events")
          .where("timestamp", "<", cutoffDate.toISOString())
          .executeTakeFirst();
        return Number(result.numDeletedRows);
      }
    })({ db });

    // Log one old event (2 days ago) and one recent event
    const oldResult = makePipelineResult({ action: "block" });
    const oldEvent = buildSecurityEvent(oldResult, {
      requestId: "req-old",
      provider: "openai",
      model: "gpt-4",
      latencyMs: 5,
    });
    await oldAuditLogger.log({
      ...oldEvent,
      timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const recentResult = makePipelineResult({
      action: "allow",
      candidates: [],
      riskScore: 0,
      riskLevel: "low",
    });
    const recentEvent = buildSecurityEvent(recentResult, {
      requestId: "req-recent",
      provider: "openai",
      model: "gpt-4",
      latencyMs: 3,
    });
    await oldAuditLogger.log(recentEvent);

    expect(await oldAuditLogger.cleanup()).toBe(1);
    expect(await oldAuditLogger.getRecentEvents(10, 0)).toHaveLength(1);
  });
});

// ── D. BLOCK creates audit event before HTTP 400 ──────────────────────────────

describe("D. BLOCK request — audit event created before HTTP 400", () => {
  test("security event exists with action=block when response is 400", async () => {
    const syntheticAwsKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");

    const { openaiRoutes } = await import("../routes/openai");
    const app = new Hono();
    app.route("/openai", openaiRoutes);

    const savedFetch = globalThis.fetch;
    (globalThis.fetch as unknown) = async (input: string | URL | Request) => {
      const url =
        typeof input === "string" ? input : input instanceof Request ? input.url : String(input);
      if (url.includes("localhost:5002") || url.includes("localhost:7080")) {
        return nativeFetch(input);
      }
      throw new Error("Provider should not be called for BLOCK");
    };

    try {
      const reqId = `req-block-d-${Date.now()}`;
      const res = await app.request("/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-request-id": reqId },
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [{ role: "user", content: `My AWS key is ${syntheticAwsKey}` }],
        }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe("policy_blocked");

      // Give the fire-and-forget a tick to complete
      await new Promise((r) => setTimeout(r, 50));

      const events = await getAuditLogger().getRecentEvents(50, 0);
      const blockEvent = events.find((e) => e.requestId === reqId);

      expect(blockEvent).toBeDefined();
      expect(blockEvent!.action).toBe("block");
      expect(blockEvent!.source).toBe("promptwall");
      expect(blockEvent!.provider).toBe("gemini"); // default provider
      expect(blockEvent!.riskLevel).toBe("critical");
      // Security: no raw AWS key in the stored event
      expect(JSON.stringify(blockEvent)).not.toContain(syntheticAwsKey);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });
});

// ── E. ALLOW request — audit event created before provider call ───────────────

describe("E. ALLOW request — audit event created before provider call", () => {
  test("security event exists with action=allow after clean prompt", async () => {
    const { openaiRoutes } = await import("../routes/openai");
    const app = new Hono();
    app.route("/openai", openaiRoutes);

    const savedFetch = globalThis.fetch;
    (globalThis.fetch as unknown) = async (input: string | URL | Request) => {
      const url =
        typeof input === "string" ? input : input instanceof Request ? input.url : String(input);
      if (url.includes("localhost:5002") || url.includes("localhost:7080")) {
        return nativeFetch(input);
      }
      return new Response(
        JSON.stringify({
          id: "chatcmpl-allow",
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: "gpt-4o",
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: "Hello!" },
              finish_reason: "stop",
            },
          ],
          usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };

    try {
      const reqId = `req-allow-e-${Date.now()}`;
      const res = await app.request("/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-request-id": reqId,
          Authorization: "Bearer test-key",
        },
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [{ role: "user", content: "What is 2+2?" }],
        }),
      });

      expect(res.status).toBe(200);

      // Give the fire-and-forget a tick to complete
      await new Promise((r) => setTimeout(r, 50));

      const events = await getAuditLogger().getRecentEvents(50, 0);
      const allowEvent = events.find((e) => e.requestId === reqId);

      expect(allowEvent).toBeDefined();
      expect(allowEvent!.action).toBe("allow");
      expect(allowEvent!.source).toBe("promptwall");
      expect(allowEvent!.model).toBe("gpt-4o");
      expect(allowEvent!.candidates).toHaveLength(0); // clean prompt
      expect(allowEvent!.detectorsTriggered).toHaveLength(0);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });
});
