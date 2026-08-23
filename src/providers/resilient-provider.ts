/**
 * @file resilient-provider.ts
 * @module src/providers
 *
 * Resilient Provider Gateway & Failover Router (Milestone 9B).
 *
 * Implements end-to-end fault tolerance for LLM provider execution:
 *   - Circuit breaker validation
 *   - Provider health verification
 *   - Strict per-request timeouts
 *   - Exponential backoff retries on transient errors
 *   - Automatic provider failover to healthy alternatives
 *   - Real-time metrics and latency collection
 *
 * Invariant: The security pipeline (DetectionPipeline, PolicyEngine, RiskEngine,
 * AuditLogger, Request Security Middleware) is authoritative and remains untouched.
 */

import { circuitBreaker } from "./circuit-breaker";
import { ProviderError } from "./errors";
import { healthManager } from "./health-manager";
import { providerMetrics } from "./provider-metrics";
import { type ProviderRegistry, providerRegistry } from "./registry";
import { withRetry } from "./retry";
import { withTimeout } from "./timeout";
import type {
  LLMCompleteOptions,
  LLMCompletionResult,
  LLMProvider,
  LLMRequest,
  ProviderInfo,
} from "./types";

export interface ResilientCompleteOptions extends LLMCompleteOptions {
  provider?: string;
  targetProvider?: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
  allowFailover?: boolean;
}

export class ResilientProvider implements LLMProvider {
  public readonly id = "resilient-gateway";
  public readonly name = "PromptWall Resilient Gateway";
  private customRegistry?: ProviderRegistry;

  constructor(registry?: ProviderRegistry) {
    this.customRegistry = registry;
  }

  private getRegistry(): ProviderRegistry {
    return this.customRegistry ?? providerRegistry;
  }

  /**
   * Determine the sequence of candidate providers for failover.
   */
  private getCandidateProviders(targetProviderId?: string): string[] {
    const allProviders = this.getRegistry()
      .getAll()
      .map((p: LLMProvider) => p.id);
    const primary = targetProviderId || "gemini";

    // Deduplicated list starting with primary provider
    const candidates = [primary, ...allProviders.filter((id: string) => id !== primary)];
    return Array.from(new Set(candidates));
  }

  /**
   * Execute a single provider with timeout, retry, and circuit breaking.
   */
  private async executeProvider(
    provider: LLMProvider,
    request: LLMRequest,
    options: ResilientCompleteOptions,
  ): Promise<LLMCompletionResult> {
    const providerId = provider.id;
    providerMetrics.recordRequest(providerId);

    if (!circuitBreaker.canExecute(providerId)) {
      providerMetrics.recordFailure(providerId);
      throw new ProviderError(
        503,
        "Service Unavailable",
        JSON.stringify({
          error: {
            message: `Circuit breaker is OPEN for provider "${providerId}"`,
            type: "circuit_breaker_open",
          },
        }),
      );
    }

    const startTime = Date.now();

    try {
      const result = await withRetry(
        async (_attempt) => {
          return await withTimeout(
            async (_signal) => {
              return await provider.complete(request, options);
            },
            {
              timeoutMs: options.timeoutMs,
              provider: providerId,
            },
          );
        },
        {
          maxRetries: options.maxRetries,
          retryDelayMs: options.retryDelayMs,
          provider: providerId,
          onRetry: (_err, _attempt) => {
            providerMetrics.recordRetry(providerId);
          },
        },
      );

      const latencyMs = Date.now() - startTime;
      healthManager.recordSuccess(providerId, latencyMs);
      circuitBreaker.recordSuccess(providerId);
      providerMetrics.recordSuccess(providerId, latencyMs);

      return result;
    } catch (error) {
      healthManager.recordFailure(providerId);
      circuitBreaker.recordFailure(providerId);
      providerMetrics.recordFailure(providerId);
      throw error;
    }
  }

  /**
   * Complete LLM request with automatic failover to healthy providers.
   */
  public async complete(
    request: LLMRequest,
    options: ResilientCompleteOptions = {},
  ): Promise<LLMCompletionResult> {
    const targetProviderId = options.provider || options.targetProvider;
    const allowFailover = options.allowFailover ?? true;
    const candidates = allowFailover
      ? this.getCandidateProviders(targetProviderId)
      : [targetProviderId || "gemini"];

    let lastError: unknown;
    let attemptedCount = 0;

    for (let i = 0; i < candidates.length; i++) {
      const candidateId = candidates[i];
      const provider = this.getRegistry().get(candidateId);

      if (!provider) {
        continue;
      }

      // Check if circuit is open — skip to next provider during failover
      if (allowFailover && i > 0 && !circuitBreaker.canExecute(candidateId)) {
        continue;
      }

      // If we are failing over from a previous candidate, record failover metric
      if (i > 0 && attemptedCount > 0) {
        providerMetrics.recordFailover(candidates[0], candidateId);
      }

      attemptedCount++;

      try {
        return await this.executeProvider(provider, request, options);
      } catch (error) {
        lastError = error;

        // If failover is not allowed or if this was the last candidate, rethrow
        if (!allowFailover || i === candidates.length - 1) {
          break;
        }
      }
    }

    if (lastError) {
      throw lastError;
    }

    throw new ProviderError(
      503,
      "Service Unavailable",
      JSON.stringify({
        error: {
          message: "All candidate LLM providers are currently unavailable",
          type: "all_providers_failed",
        },
      }),
    );
  }

  public info(): ProviderInfo {
    return {
      id: this.id,
      displayName: this.name,
      vendor: "PromptWall",
      deploymentType: "gateway",
      supportsStreaming: true,
      supportsVision: true,
      supportsTools: true,
      supportsEmbeddings: false,
      capabilities: {
        supportsStreaming: true,
        supportsVision: true,
        supportsTools: true,
        supportsFunctionCalling: true,
        supportsJSONMode: true,
        supportsSystemInstruction: true,
        supportsEmbeddings: false,
        supportsAudio: false,
        supportsReasoning: true,
        supportsThinking: true,
        supportsSafetySettings: true,
        supportsImages: true,
        supportsVideo: false,
        supportsBatch: false,
        supportsCaching: true,
        supportsFineTuning: false,
        supportsLocalExecution: false,
      },
    };
  }
}

export const resilientProvider = new ResilientProvider();
