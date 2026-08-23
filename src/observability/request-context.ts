/**
 * @file request-context.ts
 * @module src/observability
 *
 * Request Correlation & Tracing Middleware (Milestone 10).
 *
 * Preserves or generates a unique correlation ID (X-Request-ID) across every request lifecycle,
 * propagating it to logs, audit records, provider invocations, and response headers.
 */

import type { Context, MiddlewareHandler } from "hono";

declare module "hono" {
  interface ContextVariableMap {
    requestId?: string;
  }
}

/**
 * Middleware that extracts or generates a unique Request Correlation ID (UUID)
 * and attaches it to Hono context and response headers.
 */
export function requestIdMiddleware(): MiddlewareHandler {
  return async (c, next) => {
    const existing =
      c.req.header("X-Request-ID") || c.req.header("x-request-id") || c.req.header("X-Request-Id");

    const requestId = existing?.trim() ? existing.trim() : crypto.randomUUID();

    c.set("requestId", requestId);
    c.header("X-Request-ID", requestId);

    await next();

    // Ensure header is set on response even if modified downstream
    c.res.headers.set("X-Request-ID", requestId);
  };
}

/**
 * Helper to safely extract the request correlation ID from Hono Context.
 */
export function getRequestId(c: Context): string {
  const fromVar = c.get("requestId");
  if (fromVar) return fromVar;

  const fromHeader =
    c.req.header("X-Request-ID") || c.req.header("x-request-id") || c.req.header("X-Request-Id");

  return fromHeader?.trim() || "unknown";
}
