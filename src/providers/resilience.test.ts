/**
 * @file resilience.test.ts
 * @module src/providers
 *
 * M9B Unit & Integration Tests — Provider Resilience & Fault Tolerance.
 *
 * Tests:
 *   - Provider Health Manager: state transitions, latency calculation, health checks
 *   - Provider Timeout Wrapper: timeout triggers, cancellation, success path
 *   - Provider Retry Engine: exponential backoff, retryable vs non-retryable errors
 *   - Provider Circuit Breaker: CLOSED -> OPEN -> HALF_OPEN -> CLOSED state machine
 *   - Resilient Provider & Failover: automatic failover on failure, all-failed fallback
 *   - Provider Metrics: metric counters, latency tracking, aggregation
 */

import { beforeEach, describe, expect, test } from "bun:test";
import { CircuitBreaker, CircuitBreakerOpenError, circuitBreaker } from "./circuit-breaker";
import { ProviderError } from "./errors";
import { healthManager, ProviderHealthManager } from "./health-manager";
import { getProviderMetrics, ProviderMetricsTracker, providerMetrics } from "./provider-metrics";
import { ProviderRegistry } from "./registry";
import { ResilientProvider } from "./resilient-provider";
import { calculateBackoffDelay, isRetryableError, withRetry } from "./retry";
import { ProviderTimeoutError, withTimeout } from "./timeout";
import type { LLMCompletionResult, LLMProvider, LLMRequest, ProviderInfo } from "./types";

// Helper mock provider
function createMockProvider(
  id: string,
  completeImpl: (request: LLMRequest) => Promise<LLMCompletionResult>,
): LLMProvider {
  return {
    id,
    name: `Mock ${id}`,
    complete: completeImpl,
    info(): ProviderInfo {
      return {
        id,
        displayName: `Mock ${id}`,
        vendor: "MockVendor",
        deploymentType: "cloud",
        supportsStreaming: false,
        supportsVision: false,
        supportsTools: false,
        supportsEmbeddings: false,
        capabilities: {
          supportsStreaming: false,
          supportsVision: false,
          supportsTools: false,
          supportsFunctionCalling: false,
          supportsJSONMode: false,
          supportsSystemInstruction: false,
          supportsEmbeddings: false,
          supportsAudio: false,
          supportsReasoning: false,
          supportsThinking: false,
          supportsSafetySettings: false,
          supportsImages: false,
          supportsVideo: false,
          supportsBatch: false,
          supportsCaching: false,
          supportsFineTuning: false,
          supportsLocalExecution: false,
        },
      };
    },
  };
}

describe("M9B — Provider Health Manager", () => {
  let hm: ProviderHealthManager;

  beforeEach(() => {
    hm = new ProviderHealthManager();
  });

  test("new provider starts as healthy", () => {
    const health = hm.getProviderHealth("openai");
    expect(health.provider).toBe("openai");
    expect(health.status).toBe("healthy");
    expect(health.failureCount).toBe(0);
    expect(health.successCount).toBe(0);
    expect(hm.isHealthy("openai")).toBe(true);
  });

  test("successful call marks provider healthy and updates latency", () => {
    hm.recordSuccess("openai", 120);
    const health1 = hm.getProviderHealth("openai");
    expect(health1.status).toBe("healthy");
    expect(health1.successCount).toBe(1);
    expect(health1.averageLatencyMs).toBe(120);
    expect(health1.lastSuccessAt).toBeDefined();

    // Second success calculates cumulative moving average: (120 + 80) / 2 = 100
    hm.recordSuccess("openai", 80);
    const health2 = hm.getProviderHealth("openai");
    expect(health2.successCount).toBe(2);
    expect(health2.averageLatencyMs).toBe(100);
  });

  test("failures increase failureCount and transition healthy -> degraded -> unhealthy", () => {
    // 1-2 failures: healthy
    hm.recordFailure("gemini");
    expect(hm.getProviderHealth("gemini").status).toBe("healthy");
    expect(hm.isHealthy("gemini")).toBe(true);

    hm.recordFailure("gemini");
    expect(hm.getProviderHealth("gemini").status).toBe("healthy");

    // 3-5 failures: degraded
    hm.recordFailure("gemini"); // 3
    expect(hm.getProviderHealth("gemini").status).toBe("degraded");
    expect(hm.isHealthy("gemini")).toBe(true); // Degraded is still usable

    hm.recordFailure("gemini"); // 4
    hm.recordFailure("gemini"); // 5
    expect(hm.getProviderHealth("gemini").status).toBe("degraded");

    // >5 failures: unhealthy
    hm.recordFailure("gemini"); // 6
    expect(hm.getProviderHealth("gemini").status).toBe("unhealthy");
    expect(hm.isHealthy("gemini")).toBe(false);
  });

  test("successful call resets failure count back to healthy", () => {
    for (let i = 0; i < 6; i++) {
      hm.recordFailure("anthropic");
    }
    expect(hm.getProviderHealth("anthropic").status).toBe("unhealthy");

    hm.recordSuccess("anthropic", 150);
    const health = hm.getProviderHealth("anthropic");
    expect(health.status).toBe("healthy");
    expect(health.failureCount).toBe(0);
    expect(hm.isHealthy("anthropic")).toBe(true);
  });

  test("getAllProviderHealth returns all tracked providers", () => {
    hm.recordSuccess("openai", 100);
    hm.recordFailure("gemini");

    const all = hm.getAllProviderHealth();
    expect(Object.keys(all)).toContain("openai");
    expect(Object.keys(all)).toContain("gemini");
  });
});

describe("M9B — Provider Timeout Wrapper", () => {
  test("fast provider resolves within deadline", async () => {
    const result = await withTimeout(
      async () => {
        return "fast response";
      },
      { timeoutMs: 1000, provider: "test-provider" },
    );

    expect(result).toBe("fast response");
  });

  test("slow provider triggers timeout and throws ProviderTimeoutError", async () => {
    let errorThrown: unknown;

    try {
      await withTimeout(
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 200));
          return "too late";
        },
        { timeoutMs: 50, provider: "test-provider" },
      );
    } catch (err) {
      errorThrown = err;
    }

    expect(errorThrown).toBeInstanceOf(ProviderTimeoutError);
    const timeoutErr = errorThrown as ProviderTimeoutError;
    expect(timeoutErr.type).toBe("provider_timeout");
    expect(timeoutErr.status).toBe(504);
    expect(timeoutErr.message).toContain("exceeded timeout");
  });
});

describe("M9B — Provider Retry Engine", () => {
  test("calculateBackoffDelay computes exponential delays", () => {
    expect(calculateBackoffDelay(1, 500)).toBe(500);
    expect(calculateBackoffDelay(2, 500)).toBe(1000);
    expect(calculateBackoffDelay(3, 500)).toBe(2000);
  });

  test("isRetryableError classifies errors correctly", () => {
    // Retryable
    expect(isRetryableError(new ProviderTimeoutError())).toBe(true);
    expect(isRetryableError(new ProviderError(429, "Too Many Requests", "{}"))).toBe(true);
    expect(isRetryableError(new ProviderError(500, "Internal Server Error", "{}"))).toBe(true);
    expect(isRetryableError(new ProviderError(502, "Bad Gateway", "{}"))).toBe(true);
    expect(isRetryableError(new ProviderError(503, "Service Unavailable", "{}"))).toBe(true);
    expect(isRetryableError(new ProviderError(504, "Gateway Timeout", "{}"))).toBe(true);
    expect(isRetryableError(new Error("fetch failed"))).toBe(true);
    expect(isRetryableError(new Error("connect ECONNREFUSED 127.0.0.1"))).toBe(true);

    // Non-retryable
    expect(isRetryableError(new ProviderError(400, "Bad Request", "{}"))).toBe(false);
    expect(isRetryableError(new ProviderError(401, "Unauthorized", "{}"))).toBe(false);
    expect(isRetryableError(new ProviderError(403, "Forbidden", "{}"))).toBe(false);
    expect(isRetryableError(new ProviderError(404, "Not Found", "{}"))).toBe(false);
    expect(isRetryableError(new Error("Invalid prompt format"))).toBe(false);
  });

  test("retries transient failure and succeeds on subsequent attempt", async () => {
    let attempts = 0;
    const retryDelays: number[] = [];

    const result = await withRetry(
      async () => {
        attempts++;
        if (attempts < 3) {
          throw new ProviderError(503, "Service Unavailable", "{}");
        }
        return "success after retries";
      },
      {
        maxRetries: 3,
        retryDelayMs: 10,
        sleepFn: async (ms) => {
          retryDelays.push(ms);
        },
      },
    );

    expect(result).toBe("success after retries");
    expect(attempts).toBe(3);
    expect(retryDelays).toHaveLength(2);
    expect(retryDelays[0]).toBe(10);
    expect(retryDelays[1]).toBe(20);
  });

  test("non-retryable errors fail immediately without retry", async () => {
    let attempts = 0;

    expect(
      withRetry(
        async () => {
          attempts++;
          throw new ProviderError(401, "Unauthorized", "{}");
        },
        { maxRetries: 3, retryDelayMs: 10 },
      ),
    ).rejects.toThrow();

    expect(attempts).toBe(1);
  });

  test("exhausted retries throws last error", async () => {
    let attempts = 0;

    expect(
      withRetry(
        async () => {
          attempts++;
          throw new ProviderError(500, "Server Error", "{}");
        },
        {
          maxRetries: 2,
          retryDelayMs: 10,
          sleepFn: async () => {},
        },
      ),
    ).rejects.toThrow();

    expect(attempts).toBe(3); // 1 initial + 2 retries
  });
});

describe("M9B — Provider Circuit Breaker", () => {
  let cb: CircuitBreaker;

  beforeEach(() => {
    cb = new CircuitBreaker();
  });

  test("starts CLOSED and allows execution", () => {
    expect(cb.getState("openai")).toBe("CLOSED");
    expect(cb.canExecute("openai")).toBe(true);
  });

  test("transitions to OPEN after 5 failures", () => {
    for (let i = 0; i < 4; i++) {
      cb.recordFailure("openai", { failureThreshold: 5 });
      expect(cb.getState("openai")).toBe("CLOSED");
    }

    cb.recordFailure("openai", { failureThreshold: 5 });
    expect(cb.getState("openai")).toBe("OPEN");
    expect(cb.canExecute("openai")).toBe(false);
  });

  test("execute blocks immediately when OPEN with CircuitBreakerOpenError", async () => {
    for (let i = 0; i < 5; i++) {
      cb.recordFailure("openai", { failureThreshold: 5 });
    }

    expect(cb.execute("openai", async () => "ok")).rejects.toThrow(CircuitBreakerOpenError);
  });

  test("transitions to HALF_OPEN after reset timeout expires", async () => {
    for (let i = 0; i < 5; i++) {
      cb.recordFailure("openai", { failureThreshold: 5, resetTimeoutMs: 50 });
    }
    expect(cb.getState("openai", { resetTimeoutMs: 50 })).toBe("OPEN");

    // Wait for reset timeout
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(cb.getState("openai", { resetTimeoutMs: 50 })).toBe("HALF_OPEN");
    expect(cb.canExecute("openai", { resetTimeoutMs: 50 })).toBe(true);
  });

  test("successful call in HALF_OPEN resets circuit to CLOSED", async () => {
    for (let i = 0; i < 5; i++) {
      cb.recordFailure("openai", { failureThreshold: 5, resetTimeoutMs: 20 });
    }
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(cb.getState("openai", { resetTimeoutMs: 20 })).toBe("HALF_OPEN");

    cb.recordSuccess("openai");
    expect(cb.getState("openai")).toBe("CLOSED");
  });

  test("failed call in HALF_OPEN reverts circuit to OPEN", async () => {
    for (let i = 0; i < 5; i++) {
      cb.recordFailure("openai", { failureThreshold: 5, resetTimeoutMs: 20 });
    }
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(cb.getState("openai", { resetTimeoutMs: 20 })).toBe("HALF_OPEN");

    cb.recordFailure("openai", { resetTimeoutMs: 20 });
    expect(cb.getState("openai", { resetTimeoutMs: 20 })).toBe("OPEN");
  });
});

describe("M9B — Resilient Provider Gateway & Failover", () => {
  let testRegistry: ProviderRegistry;

  beforeEach(() => {
    testRegistry = new ProviderRegistry();
    healthManager.reset();
    circuitBreaker.reset();
    providerMetrics.reset();
  });

  test("successfully executes primary provider when healthy", async () => {
    const mockOpenAI = createMockProvider("openai", async () => ({
      isStreaming: false,
      response: { choices: [{ message: { content: "Hello from OpenAI" } }] },
      model: "gpt-4o",
    }));
    testRegistry.register(mockOpenAI);

    const gateway = new ResilientProvider(testRegistry);
    const result = await gateway.complete({ messages: [] }, { provider: "openai" });

    expect(result.isStreaming).toBe(false);
    expect(result.model).toBe("gpt-4o");
    expect(healthManager.isHealthy("openai")).toBe(true);
  });

  test("fails over to backup provider when primary fails", async () => {
    const mockOpenAI = createMockProvider("openai", async () => {
      throw new ProviderError(503, "Service Unavailable", "{}");
    });
    const mockGemini = createMockProvider("gemini", async () => ({
      isStreaming: false,
      response: { choices: [{ message: { content: "Hello from Gemini Fallback" } }] },
      model: "gemini-2.5-flash",
    }));

    testRegistry.register(mockOpenAI);
    testRegistry.register(mockGemini);

    const gateway = new ResilientProvider(testRegistry);
    const result = await gateway.complete(
      { messages: [] },
      { provider: "openai", maxRetries: 0, retryDelayMs: 1 },
    );

    expect(result.model).toBe("gemini-2.5-flash");
    expect(healthManager.getProviderHealth("openai").failureCount).toBe(1);
    expect(healthManager.isHealthy("gemini")).toBe(true);

    const metrics = getProviderMetrics() as { failovers: number };
    expect(metrics.failovers).toBe(1);
  });

  test("throws error when all registered providers fail", async () => {
    const mockOpenAI = createMockProvider("openai", async () => {
      throw new ProviderError(500, "OpenAI Down", "{}");
    });
    const mockGemini = createMockProvider("gemini", async () => {
      throw new ProviderError(500, "Gemini Down", "{}");
    });

    testRegistry.register(mockOpenAI);
    testRegistry.register(mockGemini);

    const gateway = new ResilientProvider(testRegistry);
    expect(
      gateway.complete({ messages: [] }, { provider: "openai", maxRetries: 0 }),
    ).rejects.toThrow();
  });
});

describe("M9B — Provider Observability Metrics", () => {
  let tracker: ProviderMetricsTracker;

  beforeEach(() => {
    tracker = new ProviderMetricsTracker();
  });

  test("tracks requests, success, latency, failures, retries, and failovers", () => {
    tracker.recordRequest("openai");
    tracker.recordSuccess("openai", 100);
    tracker.recordRequest("openai");
    tracker.recordSuccess("openai", 200);

    tracker.recordRequest("gemini");
    tracker.recordFailure("gemini");
    tracker.recordRetry("gemini");
    tracker.recordFailover("gemini", "anthropic");

    const openaiMetrics = tracker.getProviderMetrics("openai") as {
      totalRequests: number;
      successfulRequests: number;
      averageLatencyMs: number;
    };
    expect(openaiMetrics.totalRequests).toBe(2);
    expect(openaiMetrics.successfulRequests).toBe(2);
    expect(openaiMetrics.averageLatencyMs).toBe(150);

    const geminiMetrics = tracker.getProviderMetrics("gemini") as {
      totalRequests: number;
      failedRequests: number;
      retries: number;
      failovers: number;
    };
    expect(geminiMetrics.totalRequests).toBe(1);
    expect(geminiMetrics.failedRequests).toBe(1);
    expect(geminiMetrics.retries).toBe(1);
    expect(geminiMetrics.failovers).toBe(1);

    const globalMetrics = tracker.getProviderMetrics() as {
      totalRequests: number;
      successfulRequests: number;
      failedRequests: number;
      failovers: number;
    };
    expect(globalMetrics.totalRequests).toBe(3);
    expect(globalMetrics.successfulRequests).toBe(2);
    expect(globalMetrics.failedRequests).toBe(1);
    expect(globalMetrics.failovers).toBe(1);
  });
});
