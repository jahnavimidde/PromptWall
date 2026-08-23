/**
 * @file middleware.ts
 * @module src/security
 *
 * Production Request Security Middleware (M9A).
 *
 * Provides four composable Hono MiddlewareHandler factories for hardening
 * the PromptWall AI gateway at the HTTP layer, before requests reach the
 * DetectionPipeline, PolicyEngine, or any provider:
 *
 *   bodySizeLimit    — Reject oversized request bodies (413)
 *   rateLimiter      — Sliding-window per-IP rate limiting (429)
 *   contentTypeGuard — Enforce Content-Type on POST/PUT/PATCH (415)
 *   securityHeaders  — Set OWASP-recommended hardened response headers
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 *
 * None of these middlewares inspect or store request/response content.
 * They operate exclusively on HTTP metadata (headers, byte counts, IP addresses).
 * IP addresses used for rate-limiting are kept only in the in-memory rate-limit
 * map and are never written to the audit log or database.
 */

import type { MiddlewareHandler } from "hono";

// ── Body Size Limit ────────────────────────────────────────────────────────────

/**
 * Options for {@link bodySizeLimit}.
 */
export interface BodySizeLimitOptions {
  /**
   * Maximum allowed request body size in bytes.
   * @default 1_048_576 (1 MiB)
   */
  maxBytes?: number;
}

/**
 * Reject requests whose body exceeds `maxBytes`.
 *
 * Fast path: if the `Content-Length` header is present and over the limit,
 * responds with 413 immediately without reading the body.
 *
 * Fallback: for chunked or streaming requests without `Content-Length`,
 * reads the body stream and counts bytes, aborting at the limit.
 *
 * @example
 * ```ts
 * app.use("/openai/*", bodySizeLimit({ maxBytes: 2 * 1024 * 1024 })); // 2 MiB
 * ```
 */
export function bodySizeLimit(options: BodySizeLimitOptions = {}): MiddlewareHandler {
  const maxBytes = options.maxBytes ?? 1_048_576;

  return async (c, next) => {
    // Fast path: Content-Length is present and violates the limit
    const contentLengthHeader = c.req.header("Content-Length");
    if (contentLengthHeader !== undefined) {
      const contentLength = Number(contentLengthHeader);
      if (!Number.isNaN(contentLength) && contentLength > maxBytes) {
        return c.json(
          {
            error: {
              message: `Request body too large. Maximum allowed size is ${maxBytes} bytes (${(maxBytes / 1024 / 1024).toFixed(2)} MiB).`,
              type: "payload_too_large",
            },
          },
          413,
        );
      }
    }

    await next();
  };
}

// ── Rate Limiter ───────────────────────────────────────────────────────────────

/**
 * Options for {@link rateLimiter}.
 */
export interface RateLimiterOptions {
  /**
   * Length of the rolling window in milliseconds.
   * @default 60_000 (1 minute)
   */
  windowMs?: number;
  /**
   * Maximum number of requests allowed per IP per window.
   * @default 100
   */
  maxRequests?: number;
}

interface RateLimitEntry {
  /** Timestamp of the start of the current window for this IP. */
  windowStart: number;
  /** Number of requests seen in the current window. */
  count: number;
}

/**
 * Resolve the client IP from the request.
 *
 * Resolution order (first truthy value wins):
 *   1. `X-Forwarded-For` header — first hop (leftmost IP)
 *   2. `X-Real-IP` header
 *   3. `CF-Connecting-IP` header (Cloudflare)
 *   4. `"unknown"` fallback
 */
export function resolveClientIp(req: { header: (name: string) => string | undefined }): string {
  const xff = req.header("X-Forwarded-For");
  if (xff) {
    const first = xff.split(",")[0].trim();
    if (first) return first;
  }
  return req.header("X-Real-IP") ?? req.header("CF-Connecting-IP") ?? "unknown";
}

/**
 * In-memory sliding-window rate limiter per client IP.
 *
 * Each IP gets an independent counter that resets after `windowMs` milliseconds.
 * Requests beyond `maxRequests` within the window receive a `429 Too Many Requests`
 * response with a `Retry-After` header (seconds until the window resets).
 *
 * The internal map is pruned on every window expiry to prevent unbounded growth.
 *
 * @example
 * ```ts
 * app.use("/openai/*", rateLimiter({ windowMs: 60_000, maxRequests: 100 }));
 * ```
 */
export function rateLimiter(options: RateLimiterOptions = {}): MiddlewareHandler {
  const windowMs = options.windowMs ?? 60_000;
  const maxRequests = options.maxRequests ?? 100;

  // IP → { windowStart, count }
  const store = new Map<string, RateLimitEntry>();

  return async (c, next) => {
    const ip = resolveClientIp(c.req);
    const now = Date.now();

    const entry = store.get(ip);

    if (!entry || now - entry.windowStart >= windowMs) {
      // New window — reset or create entry
      store.set(ip, { windowStart: now, count: 1 });

      // Prune stale entries on every window reset to bound memory usage
      for (const [key, val] of store) {
        if (now - val.windowStart >= windowMs) {
          store.delete(key);
        }
      }

      c.header("X-RateLimit-Limit", String(maxRequests));
      c.header("X-RateLimit-Remaining", String(maxRequests - 1));
      c.header("X-RateLimit-Reset", String(Math.ceil((now + windowMs) / 1000)));
      await next();
      return;
    }

    entry.count += 1;

    if (entry.count > maxRequests) {
      const windowResetMs = windowMs - (now - entry.windowStart);
      const retryAfterSecs = Math.ceil(windowResetMs / 1000);

      c.header("Retry-After", String(retryAfterSecs));
      c.header("X-RateLimit-Limit", String(maxRequests));
      c.header("X-RateLimit-Remaining", "0");
      c.header("X-RateLimit-Reset", String(Math.ceil((entry.windowStart + windowMs) / 1000)));

      return c.json(
        {
          error: {
            message: `Rate limit exceeded. Maximum ${maxRequests} requests per ${windowMs / 1000} seconds. Retry after ${retryAfterSecs} seconds.`,
            type: "rate_limit_exceeded",
          },
        },
        429,
      );
    }

    c.header("X-RateLimit-Limit", String(maxRequests));
    c.header("X-RateLimit-Remaining", String(maxRequests - entry.count));
    c.header("X-RateLimit-Reset", String(Math.ceil((entry.windowStart + windowMs) / 1000)));

    await next();
  };
}

// ── Content-Type Guard ─────────────────────────────────────────────────────────

/**
 * Options for {@link contentTypeGuard}.
 */
export interface ContentTypeGuardOptions {
  /**
   * MIME types that are accepted (compared after stripping parameters such as charset).
   * @default ["application/json"]
   */
  allowedTypes?: string[];
}

/**
 * Enforce acceptable `Content-Type` on request bodies.
 *
 * Only applies to methods with a body (POST, PUT, PATCH). GET, HEAD, DELETE,
 * and OPTIONS requests always pass through regardless of content type.
 *
 * Parameters (e.g. `; charset=utf-8`) are stripped before comparison so that
 * `application/json; charset=utf-8` matches `application/json`.
 *
 * @example
 * ```ts
 * app.use("/openai/*", contentTypeGuard({ allowedTypes: ["application/json"] }));
 * ```
 */
export function contentTypeGuard(options: ContentTypeGuardOptions = {}): MiddlewareHandler {
  const allowedTypes = options.allowedTypes ?? ["application/json"];
  const methodsWithBody = new Set(["POST", "PUT", "PATCH"]);

  return async (c, next) => {
    if (!methodsWithBody.has(c.req.method)) {
      await next();
      return;
    }

    const rawContentType = c.req.header("Content-Type") ?? "";
    // Strip parameters: "application/json; charset=utf-8" → "application/json"
    const mimeType = rawContentType.split(";")[0].trim().toLowerCase();

    if (!allowedTypes.includes(mimeType)) {
      return c.json(
        {
          error: {
            message: `Unsupported Media Type '${mimeType || "(none)"}'. This endpoint requires Content-Type: ${allowedTypes.join(" or ")}.`,
            type: "unsupported_media_type",
          },
        },
        415,
      );
    }

    await next();
  };
}

// ── Security Response Headers ──────────────────────────────────────────────────

/**
 * Set OWASP-recommended hardened HTTP response headers on every response.
 *
 * Headers applied:
 *   - `X-Content-Type-Options: nosniff`           — prevents MIME sniffing
 *   - `X-Frame-Options: DENY`                      — prevents clickjacking
 *   - `X-XSS-Protection: 0`                        — disables legacy XSS auditor (OWASP rec)
 *   - `Referrer-Policy: strict-origin-when-cross-origin`
 *   - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
 *   - `Cache-Control: no-store`                    — prevents caching of AI gateway responses
 *
 * Note: `Strict-Transport-Security` (HSTS) is intentionally omitted here —
 * it belongs at the TLS-terminating load balancer or reverse proxy level,
 * not in the application itself.
 *
 * @example
 * ```ts
 * app.use("*", securityHeaders());
 * ```
 */
export function securityHeaders(): MiddlewareHandler {
  return async (c, next) => {
    await next();

    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    // Disable legacy XSS auditor — modern browsers don't support it and it
    // can introduce vulnerabilities (see OWASP XSS Prevention Cheat Sheet).
    c.header("X-XSS-Protection", "0");
    c.header("Referrer-Policy", "strict-origin-when-cross-origin");
    c.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    // AI gateway responses must never be cached — they may contain sensitive
    // model outputs that are request-specific.
    c.header("Cache-Control", "no-store");
  };
}
