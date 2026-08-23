/**
 * @file retry.ts
 * @module src/providers
 *
 * Provider Retry Engine (Milestone 9B).
 *
 * Implements exponential backoff for transient LLM provider failures.
 *
 * Retryable errors:
 *   - Timeout errors (ProviderTimeoutError, AbortError)
 *   - HTTP 429 (Rate Limit)
 *   - HTTP 500, 502, 503, 504 (Server/Gateway Errors)
 *   - Network connection failures (fetch failed, ECONNREFUSED)
 *
 * Non-retryable errors:
 *   - HTTP 400 (Bad Request / Validation)
 *   - HTTP 401, 403 (Authentication & Authorization)
 *   - HTTP 404 (Not Found)
 *   - Policy blocks
 */

import { getConfig } from "../config";
import { ProviderError } from "./errors";
import { ProviderTimeoutError } from "./timeout";

export interface RetryOptions {
  maxRetries?: number;
  retryDelayMs?: number;
  provider?: string;
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
  sleepFn?: (ms: number) => Promise<void>;
}

const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503, 504]);
const NON_RETRYABLE_STATUS_CODES = new Set([400, 401, 403, 404, 405, 422]);

/**
 * Determine if an error is considered transient and safe to retry.
 */
export function isRetryableError(error: unknown): boolean {
  if (!error) return false;

  // Timeout errors are always retryable
  if (
    error instanceof ProviderTimeoutError ||
    (typeof error === "object" &&
      error !== null &&
      (error as { type?: string }).type === "provider_timeout")
  ) {
    return true;
  }

  if (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")) {
    return true;
  }

  // ProviderError with HTTP status code
  if (error instanceof ProviderError) {
    if (NON_RETRYABLE_STATUS_CODES.has(error.status)) return false;
    if (RETRYABLE_STATUS_CODES.has(error.status)) return true;
  }

  // Any other error with a numeric status property
  if (typeof error === "object" && error !== null && "status" in error) {
    const status = Number((error as { status: unknown }).status);
    if (NON_RETRYABLE_STATUS_CODES.has(status)) return false;
    if (RETRYABLE_STATUS_CODES.has(status)) return true;
  }

  // Network and connection errors
  if (error instanceof Error) {
    const msg = error.message.toLowerCase();
    if (
      msg.includes("fetch failed") ||
      msg.includes("econnrefused") ||
      msg.includes("econnreset") ||
      msg.includes("etimedout") ||
      msg.includes("network error") ||
      msg.includes("socket hang up")
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Calculate exponential backoff delay.
 * Attempt 1: delay * 1
 * Attempt 2: delay * 2
 * Attempt 3: delay * 4
 */
export function calculateBackoffDelay(attempt: number, initialDelayMs: number): number {
  return initialDelayMs * 2 ** (attempt - 1);
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Execute an operation with exponential backoff retries.
 */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const config = getConfig();
  const maxRetries = options.maxRetries ?? config.providers.max_retries ?? 3;
  const initialDelayMs = options.retryDelayMs ?? config.providers.retry_delay_ms ?? 500;
  const sleep = options.sleepFn ?? defaultSleep;

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await fn(attempt);
    } catch (error) {
      lastError = error;

      // If we exhausted all attempts, stop
      if (attempt > maxRetries) {
        break;
      }

      // Check if the error is retryable
      if (!isRetryableError(error)) {
        throw error;
      }

      const delayMs = calculateBackoffDelay(attempt, initialDelayMs);
      if (options.onRetry) {
        options.onRetry(error, attempt, delayMs);
      }

      await sleep(delayMs);
    }
  }

  throw lastError;
}
