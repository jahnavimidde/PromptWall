/**
 * @file DetectorRegistry.test.ts
 * @module @promptwall/engine/detector
 *
 * Unit tests for DetectorRegistry.
 *
 * Covers:
 * - Happy path: register + detect
 * - Structural operations: register, unregister, has, list, currentVersion
 * - Timeout isolation (HangingDetector)
 * - Error isolation (FailingDetector)
 * - Pre-flight skipping (supports() → false)
 * - Mixed pipeline (DummyDetector + HangingDetector + FailingDetector)
 * - registryVersion snapshot in DetectionResult
 * - pipelineExecutionTime ≤ executionTimeMs
 */

import { describe, expect, test, beforeEach } from "bun:test";
import { DetectorRegistry, DetectorTimeoutError } from "./DetectorRegistry";
import { DummyDetector } from "../testing/DummyDetector";
import { HangingDetector } from "../testing/HangingDetector";
import { FailingDetector } from "../testing/FailingDetector";
import type { Detector, DetectorCapabilities } from "./Detector";
import type { Candidate } from "../candidate/Candidate";
import type { DetectionRequest } from "./DetectionRequest";

// ── Helpers ───────────────────────────────────────────────────────────────────

const req = (): DetectionRequest => ({ content: "The quick brown fox" });

// ── Registration ──────────────────────────────────────────────────────────────

describe("DetectorRegistry — registration", () => {
  test("register() adds detector; has() returns true", () => {
    const registry = new DetectorRegistry();
    registry.register(new DummyDetector());
    expect(registry.has("dummy-detector")).toBe(true);
  });

  test("register() duplicate id throws", () => {
    const registry = new DetectorRegistry();
    registry.register(new DummyDetector());
    expect(() => registry.register(new DummyDetector())).toThrow(
      /already registered/,
    );
  });

  test("unregister() removes detector; has() returns false", () => {
    const registry = new DetectorRegistry();
    registry.register(new DummyDetector());
    registry.unregister("dummy-detector");
    expect(registry.has("dummy-detector")).toBe(false);
  });

  test("unregister() unknown id throws", () => {
    const registry = new DetectorRegistry();
    expect(() => registry.unregister("ghost")).toThrow(/cannot unregister/);
  });

  test("list() returns registered detectors in order", () => {
    const registry = new DetectorRegistry();
    registry.register(new DummyDetector());
    registry.register(new HangingDetector("h1"));
    const ids = registry.list().map((d) => d.id);
    expect(ids).toEqual(["dummy-detector", "h1"]);
  });

  test("list() returns a snapshot — mutations do not affect registry", () => {
    const registry = new DetectorRegistry();
    registry.register(new DummyDetector());
    const snapshot = registry.list() as Detector[];
    snapshot.push(new DummyDetector()); // mutate snapshot
    expect(registry.list()).toHaveLength(1); // registry unaffected
  });

  test("currentVersion increments on register and unregister", () => {
    const registry = new DetectorRegistry({ initialVersion: 10 });
    expect(registry.currentVersion).toBe(10);
    registry.register(new DummyDetector());
    expect(registry.currentVersion).toBe(11);
    registry.unregister("dummy-detector");
    expect(registry.currentVersion).toBe(12);
  });
});

// ── Happy path ─────────────────────────────────────────────────────────────────

describe("DetectorRegistry — happy path", () => {
  let registry: DetectorRegistry;

  beforeEach(() => {
    registry = new DetectorRegistry({ defaultTimeoutMs: 200 });
    registry.register(new DummyDetector());
  });

  test("returns at least one candidate", async () => {
    const result = await registry.detect(req());
    expect(result.candidates.length).toBeGreaterThan(0);
  });

  test("no errors or warnings on clean run", async () => {
    const result = await registry.detect(req());
    expect(result.errors).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  test("detectorStats has one entry", async () => {
    const result = await registry.detect(req());
    expect(result.detectorStats).toHaveLength(1);
    const stats = result.detectorStats[0];
    expect(stats?.detectorId).toBe("dummy-detector");
    expect(stats?.timedOut).toBe(false);
    expect(stats?.errored).toBe(false);
    expect(stats?.candidatesFound).toBeGreaterThan(0);
  });

  test("pipelineExecutionTime ≤ executionTimeMs", async () => {
    const result = await registry.detect(req());
    expect(result.pipelineExecutionTime).toBeLessThanOrEqual(result.executionTimeMs);
  });

  test("registryVersion snapshot matches version at dispatch", async () => {
    const versionAtDispatch = registry.currentVersion;
    const result = await registry.detect(req());
    expect(result.registryVersion).toBe(versionAtDispatch);
  });

  test("empty registry returns empty result", async () => {
    const empty = new DetectorRegistry();
    const result = await empty.detect(req());
    expect(result.candidates).toHaveLength(0);
    expect(result.detectorStats).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  test("unregistered detector is excluded from pipeline", async () => {
    registry.unregister("dummy-detector");
    const result = await registry.detect(req());
    expect(result.candidates).toHaveLength(0);
  });
});

// ── Timeout isolation ──────────────────────────────────────────────────────────

describe("DetectorRegistry — timeout isolation", () => {
  test("HangingDetector is marked timedOut; no candidates from it", async () => {
    const registry = new DetectorRegistry({ defaultTimeoutMs: 50 });
    registry.register(new HangingDetector());
    const result = await registry.detect(req());
    const stats = result.detectorStats[0];
    expect(stats?.timedOut).toBe(true);
    expect(result.candidates).toHaveLength(0);
    expect(result.errors).toHaveLength(0); // timeout ≠ error
  }, 500);

  test("HangingDetector does not block DummyDetector", async () => {
    const registry = new DetectorRegistry({ defaultTimeoutMs: 50 });
    registry.register(new HangingDetector());
    registry.register(new DummyDetector());
    const result = await registry.detect(req());
    expect(result.candidates.length).toBeGreaterThan(0);
    const hangStats = result.detectorStats.find(
      (s) => s.detectorId === "hanging-detector",
    );
    const dummyStats = result.detectorStats.find(
      (s) => s.detectorId === "dummy-detector",
    );
    expect(hangStats?.timedOut).toBe(true);
    expect(dummyStats?.errored).toBe(false);
  }, 500);

  test("per-call timeoutMs override is respected", async () => {
    const registry = new DetectorRegistry({ defaultTimeoutMs: 5_000 });
    registry.register(new HangingDetector());
    const result = await registry.detect(req(), { timeoutMs: 50 });
    expect(result.detectorStats[0]?.timedOut).toBe(true);
  }, 500);
});

// ── Error isolation ────────────────────────────────────────────────────────────

describe("DetectorRegistry — error isolation", () => {
  test("FailingDetector error is captured; pipeline continues", async () => {
    const registry = new DetectorRegistry();
    registry.register(new FailingDetector());
    registry.register(new DummyDetector());
    const result = await registry.detect(req());
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.detectorId).toBe("failing-detector");
    expect(result.errors[0]?.message).toMatch(/Simulated detector failure/);
    expect(result.candidates.length).toBeGreaterThan(0);
  });

  test("FailingDetector stats: errored=true, timedOut=false", async () => {
    const registry = new DetectorRegistry();
    registry.register(new FailingDetector());
    const result = await registry.detect(req());
    const stats = result.detectorStats[0];
    expect(stats?.errored).toBe(true);
    expect(stats?.timedOut).toBe(false);
    expect(stats?.candidatesFound).toBe(0);
  });

  test("custom error message is propagated", async () => {
    const registry = new DetectorRegistry();
    registry.register(new FailingDetector("custom-fail", "DB connection lost"));
    const result = await registry.detect(req());
    expect(result.errors[0]?.message).toBe("DB connection lost");
  });
});

// ── Pre-flight (supports()) ────────────────────────────────────────────────────

describe("DetectorRegistry — supports() pre-flight", () => {
  class PdfOnlyDetector implements Detector {
    readonly id = "pdf-only";
    readonly displayName = "PDF Only Detector";
    readonly version = "1.0.0";
    readonly capabilities: DetectorCapabilities = {
      supportsStreaming: false,
      supportsBinary: false,
      priority: 100,
      supportedMimeTypes: ["application/pdf"],
    };
    supports(request: DetectionRequest): boolean {
      return request.mimeType === "application/pdf";
    }
    async detect(_req: DetectionRequest, _signal?: AbortSignal): Promise<Candidate[]> {
      return [];
    }
  }

  test("incompatible detector is skipped and generates warning", async () => {
    const registry = new DetectorRegistry();
    registry.register(new PdfOnlyDetector());
    const result = await registry.detect({ content: "hello", mimeType: "text/plain" });
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]?.detectorId).toBe("pdf-only");
    expect(result.detectorStats).toHaveLength(0); // skipped detectors have no stats
  });

  test("compatible detector is not skipped", async () => {
    const registry = new DetectorRegistry();
    registry.register(new PdfOnlyDetector());
    // No mimeType restriction in DummyDetector.supports()
    registry.register(new DummyDetector());
    const result = await registry.detect({ content: "hello", mimeType: "application/pdf" });
    expect(result.warnings).toHaveLength(0);
    expect(result.detectorStats).toHaveLength(2);
  });
});

// ── DetectorTimeoutError ──────────────────────────────────────────────────────

describe("DetectorTimeoutError", () => {
  test("has correct properties", () => {
    const err = new DetectorTimeoutError("my-detector", 3000);
    expect(err.detectorId).toBe("my-detector");
    expect(err.timeoutMs).toBe(3000);
    expect(err.name).toBe("DetectorTimeoutError");
    expect(err instanceof Error).toBe(true);
  });
});
