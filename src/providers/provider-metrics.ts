/**
 * @file provider-metrics.ts
 * @module src/providers
 *
 * Provider Observability Metrics (Milestone 9B).
 *
 * Collects and aggregates real-time runtime metrics across LLM providers:
 *   - total requests
 *   - successful requests
 *   - failed requests
 *   - average latency
 *   - retries triggered
 *   - failovers executed
 */

export interface SingleProviderMetrics {
  provider: string;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageLatencyMs: number;
  retries: number;
  failovers: number;
}

export interface GlobalProviderMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageLatencyMs: number;
  retries: number;
  failovers: number;
  providers: Record<string, SingleProviderMetrics>;
}

export class ProviderMetricsTracker {
  private metrics = new Map<string, SingleProviderMetrics>();
  private globalFailovers = 0;

  private getOrCreate(provider: string): SingleProviderMetrics {
    let state = this.metrics.get(provider);
    if (!state) {
      state = {
        provider,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        averageLatencyMs: 0,
        retries: 0,
        failovers: 0,
      };
      this.metrics.set(provider, state);
    }
    return state;
  }

  public recordRequest(provider: string): void {
    const state = this.getOrCreate(provider);
    state.totalRequests += 1;
  }

  public recordSuccess(provider: string, latencyMs: number): void {
    const state = this.getOrCreate(provider);
    const prevSuccess = state.successfulRequests;
    state.successfulRequests += 1;
    state.averageLatencyMs = Math.round(
      (state.averageLatencyMs * prevSuccess + latencyMs) / (prevSuccess + 1),
    );
  }

  public recordFailure(provider: string): void {
    const state = this.getOrCreate(provider);
    state.failedRequests += 1;
  }

  public recordRetry(provider: string): void {
    const state = this.getOrCreate(provider);
    state.retries += 1;
  }

  public recordFailover(fromProvider: string, toProvider: string): void {
    const fromState = this.getOrCreate(fromProvider);
    fromState.failovers += 1;
    this.globalFailovers += 1;
    // Also track on destination if needed
    this.getOrCreate(toProvider);
  }

  public getProviderMetrics(provider?: string): SingleProviderMetrics | GlobalProviderMetrics {
    if (provider) {
      return { ...this.getOrCreate(provider) };
    }

    let totalRequests = 0;
    let successfulRequests = 0;
    let failedRequests = 0;
    let totalLatencyWeighted = 0;
    let retries = 0;
    const providers: Record<string, SingleProviderMetrics> = {};

    for (const [name, state] of this.metrics.entries()) {
      providers[name] = { ...state };
      totalRequests += state.totalRequests;
      successfulRequests += state.successfulRequests;
      failedRequests += state.failedRequests;
      totalLatencyWeighted += state.averageLatencyMs * state.successfulRequests;
      retries += state.retries;
    }

    const averageLatencyMs =
      successfulRequests > 0 ? Math.round(totalLatencyWeighted / successfulRequests) : 0;

    return {
      totalRequests,
      successfulRequests,
      failedRequests,
      averageLatencyMs,
      retries,
      failovers: this.globalFailovers,
      providers,
    };
  }

  public reset(): void {
    this.metrics.clear();
    this.globalFailovers = 0;
  }
}

export const providerMetrics = new ProviderMetricsTracker();

// Top-level function matching the spec
export function getProviderMetrics(provider?: string) {
  return providerMetrics.getProviderMetrics(provider);
}
