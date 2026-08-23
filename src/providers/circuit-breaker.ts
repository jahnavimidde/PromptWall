/**
 * @file circuit-breaker.ts
 * @module src/providers
 *
 * Provider Circuit Breaker (Milestone 9B).
 *
 * Prevents cascading failures and continuous load on broken LLM providers.
 *
 * State Machine:
 *   CLOSED   — Normal operation. Requests flow through.
 *              Moves to OPEN when consecutive failures exceed threshold.
 *   OPEN     — Requests are blocked immediately.
 *              Moves to HALF_OPEN when cooldown timeout expires.
 *   HALF_OPEN— Allows trial requests to test provider health.
 *              Success returns to CLOSED; failure reverts to OPEN.
 */

import { getConfig } from "../config";

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export class CircuitBreakerOpenError extends Error {
  public readonly type = "circuit_breaker_open" as const;
  public readonly status = 503;

  constructor(public readonly provider: string) {
    super(`Circuit breaker is OPEN for provider "${provider}". Requests are temporarily paused.`);
    this.name = "CircuitBreakerOpenError";
  }

  public toJSON() {
    return {
      error: {
        type: "circuit_breaker_open",
        message: this.message,
      },
    };
  }
}

interface ProviderCircuitState {
  state: CircuitState;
  consecutiveFailures: number;
  lastFailureTime?: number;
  openedAt?: number;
}

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  resetTimeoutMs?: number;
}

export class CircuitBreaker {
  private circuits = new Map<string, ProviderCircuitState>();

  private getOrCreate(provider: string): ProviderCircuitState {
    let state = this.circuits.get(provider);
    if (!state) {
      state = {
        state: "CLOSED",
        consecutiveFailures: 0,
      };
      this.circuits.set(provider, state);
    }
    return state;
  }

  private getThresholds(options?: CircuitBreakerOptions) {
    const config = getConfig();
    const failureThreshold =
      options?.failureThreshold ?? config.providers.circuit_failure_threshold ?? 5;
    const resetTimeoutMs =
      options?.resetTimeoutMs ?? config.providers.circuit_reset_timeout_ms ?? 30000;
    return { failureThreshold, resetTimeoutMs };
  }

  /**
   * Get the current circuit state for a provider, taking cooldown expiry into account.
   */
  public getState(provider: string, options?: CircuitBreakerOptions): CircuitState {
    const circuit = this.getOrCreate(provider);
    const { resetTimeoutMs } = this.getThresholds(options);

    if (circuit.state === "OPEN") {
      const now = Date.now();
      if (circuit.openedAt && now - circuit.openedAt >= resetTimeoutMs) {
        circuit.state = "HALF_OPEN";
      }
    }

    return circuit.state;
  }

  /**
   * Check if a request is permitted through the circuit breaker.
   */
  public canExecute(provider: string, options?: CircuitBreakerOptions): boolean {
    const state = this.getState(provider, options);
    return state === "CLOSED" || state === "HALF_OPEN";
  }

  /**
   * Record a successful provider invocation.
   */
  public recordSuccess(provider: string): void {
    const circuit = this.getOrCreate(provider);
    circuit.consecutiveFailures = 0;
    circuit.state = "CLOSED";
    circuit.openedAt = undefined;
  }

  /**
   * Record a provider failure and transition state if threshold reached.
   */
  public recordFailure(provider: string, options?: CircuitBreakerOptions): void {
    const circuit = this.getOrCreate(provider);
    const { failureThreshold } = this.getThresholds(options);

    circuit.consecutiveFailures += 1;
    circuit.lastFailureTime = Date.now();

    if (circuit.state === "HALF_OPEN" || circuit.consecutiveFailures >= failureThreshold) {
      circuit.state = "OPEN";
      circuit.openedAt = Date.now();
    }
  }

  /**
   * Execute an operation protected by the circuit breaker.
   */
  public async execute<T>(
    provider: string,
    fn: () => Promise<T>,
    options?: CircuitBreakerOptions,
  ): Promise<T> {
    if (!this.canExecute(provider, options)) {
      throw new CircuitBreakerOpenError(provider);
    }

    try {
      const result = await fn();
      this.recordSuccess(provider);
      return result;
    } catch (error) {
      this.recordFailure(provider, options);
      throw error;
    }
  }

  /**
   * Reset all circuit breaker states (for testing or administrative reset).
   */
  public reset(): void {
    this.circuits.clear();
  }
}

export const circuitBreaker = new CircuitBreaker();
