/**
 * @file timeout.ts
 * @module src/providers
 *
 * Provider Timeout Wrapper (Milestone 9B).
 *
 * Wraps provider invocations with an abortable deadline.
 * If the deadline is exceeded, the request is aborted and a ProviderTimeoutError
 * is thrown so retry and failover logic can act.
 */

import { getConfig } from "../config";
import { healthManager } from "./health-manager";

export class ProviderTimeoutError extends Error {
  public readonly type = "provider_timeout" as const;
  public readonly status = 504;

  constructor(
    message = "Provider request exceeded timeout",
    public readonly provider?: string,
  ) {
    super(message);
    this.name = "ProviderTimeoutError";
  }

  public toJSON() {
    return {
      error: {
        type: "provider_timeout",
        message: this.message,
      },
    };
  }
}

export interface TimeoutOptions {
  timeoutMs?: number;
  provider?: string;
}

/**
 * Execute an async provider operation with a strict timeout.
 *
 * If the operation does not resolve before `timeoutMs`, the abort signal
 * is triggered, provider failure is recorded, and ProviderTimeoutError is thrown.
 */
export async function withTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  options: TimeoutOptions = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? getConfig().providers.timeout_ms ?? 30000;
  const provider = options.provider;

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | null = null;
  let didTimeout = false;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      didTimeout = true;
      controller.abort();
      if (provider) {
        healthManager.recordFailure(provider);
      }
      reject(new ProviderTimeoutError("Provider request exceeded timeout", provider));
    }, timeoutMs);
  });

  try {
    const result = await Promise.race([fn(controller.signal), timeoutPromise]);
    if (timer) clearTimeout(timer);
    return result;
  } catch (error) {
    if (timer) clearTimeout(timer);

    if (didTimeout) {
      throw new ProviderTimeoutError("Provider request exceeded timeout", provider);
    }

    if (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")) {
      if (provider) {
        healthManager.recordFailure(provider);
      }
      throw new ProviderTimeoutError("Provider request exceeded timeout", provider);
    }

    throw error;
  }
}
