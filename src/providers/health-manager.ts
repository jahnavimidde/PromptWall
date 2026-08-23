/**
 * @file health-manager.ts
 * @module src/providers
 *
 * Provider Health Manager (Milestone 9B).
 *
 * Monitors real-time health, success/failure counts, and latency across
 * LLM providers.
 *
 * Health status transitions:
 *   - 0-2 failures: "healthy"
 *   - 3-5 failures: "degraded"
 *   - >5 failures: "unhealthy"
 */

export type ProviderHealthStatus = "healthy" | "degraded" | "unhealthy";

export interface ProviderHealthState {
  provider: string;
  status: ProviderHealthStatus;
  failureCount: number;
  successCount: number;
  averageLatencyMs: number;
  lastFailureAt?: string;
  lastSuccessAt?: string;
}

export class ProviderHealthManager {
  private healthStates = new Map<string, ProviderHealthState>();

  private getOrCreate(provider: string): ProviderHealthState {
    let state = this.healthStates.get(provider);
    if (!state) {
      state = {
        provider,
        status: "healthy",
        failureCount: 0,
        successCount: 0,
        averageLatencyMs: 0,
      };
      this.healthStates.set(provider, state);
    }
    return state;
  }

  private computeStatus(failureCount: number): ProviderHealthStatus {
    if (failureCount <= 2) {
      return "healthy";
    }
    if (failureCount <= 5) {
      return "degraded";
    }
    return "unhealthy";
  }

  /**
   * Record a successful provider call and update latency statistics.
   */
  public recordSuccess(provider: string, latencyMs: number): void {
    const state = this.getOrCreate(provider);
    const prevSuccess = state.successCount;
    state.successCount += 1;
    state.failureCount = 0;
    state.status = "healthy";
    state.lastSuccessAt = new Date().toISOString();

    // Cumulative moving average
    state.averageLatencyMs = Math.round(
      (state.averageLatencyMs * prevSuccess + latencyMs) / (prevSuccess + 1),
    );
  }

  /**
   * Record a provider failure and update status.
   */
  public recordFailure(provider: string): void {
    const state = this.getOrCreate(provider);
    state.failureCount += 1;
    state.lastFailureAt = new Date().toISOString();
    state.status = this.computeStatus(state.failureCount);
  }

  /**
   * Get health state for a single provider.
   */
  public getProviderHealth(provider: string): ProviderHealthState {
    return { ...this.getOrCreate(provider) };
  }

  /**
   * Get health state for all tracked providers.
   */
  public getAllProviderHealth(): Record<string, ProviderHealthState> {
    const result: Record<string, ProviderHealthState> = {};
    for (const [key, val] of this.healthStates.entries()) {
      result[key] = { ...val };
    }
    return result;
  }

  /**
   * Check if a provider is healthy enough to receive traffic.
   * Returns true if status is "healthy" or "degraded", false if "unhealthy".
   */
  public isHealthy(provider: string): boolean {
    const state = this.getOrCreate(provider);
    return state.status !== "unhealthy";
  }

  /**
   * Reset health statistics for testing or maintenance.
   */
  public reset(): void {
    this.healthStates.clear();
  }
}

export const healthManager = new ProviderHealthManager();

// Convenience top-level exports matching the spec
export const recordSuccess = (provider: string, latency: number) =>
  healthManager.recordSuccess(provider, latency);
export const recordFailure = (provider: string) => healthManager.recordFailure(provider);
export const getProviderHealth = (provider: string) => healthManager.getProviderHealth(provider);
export const getAllProviderHealth = () => healthManager.getAllProviderHealth();
export const isHealthy = (provider: string) => healthManager.isHealthy(provider);
