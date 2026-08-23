/**
 * @file middleware.test.ts
 * @module src/security
 *
 * M9A Unit Tests — Production Request Security Middleware.
 *
 * All tests use in-process Hono apps with no external dependencies,
 * no database, and no network calls.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import {
  bodySizeLimit,
  contentTypeGuard,
  rateLimiter,
  resolveClientIp,
  securityHeaders,
} from "./middleware";

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Build a minimal Hono app with the given middleware and a catch-all 200 handler. */
function makeApp(middleware: ReturnType<typeof bodySizeLimit>): Hono {
  const app = new Hono();
  app.use("*", middleware);
  app.all("*", (c) => c.json({ ok: true }));
  return app;
}

// ── bodySizeLimit ──────────────────────────────────────────────────────────────

describe("bodySizeLimit", () => {
  test("passes through requests under the limit (Content-Length fast path)", async () => {
    const app = makeApp(bodySizeLimit({ maxBytes: 100 }));

    const res = await app.request("/test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": "50",
      },
      body: JSON.stringify({ hello: "world" }),
    });

    expect(res.status).toBe(200);
  });

  test("passes through requests at the exact limit (Content-Length fast path)", async () => {
    const app = makeApp(bodySizeLimit({ maxBytes: 100 }));
    const body = "x".repeat(100);

    const res = await app.request("/test", {
      method: "POST",
      headers: {
        "Content-Type": "text/plain",
        "Content-Length": "100",
      },
      body,
    });

    expect(res.status).toBe(200);
  });

  test("rejects requests over the limit via Content-Length header → 413", async () => {
    const app = makeApp(bodySizeLimit({ maxBytes: 100 }));

    const res = await app.request("/test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": "101",
      },
      body: "x".repeat(101),
    });

    expect(res.status).toBe(413);
    const body = (await res.json()) as { error: { type: string; message: string } };
    expect(body.error.type).toBe("payload_too_large");
    expect(body.error.message).toContain("100 bytes");
  });

  test("uses default 1 MiB limit when no maxBytes provided", async () => {
    const app = makeApp(bodySizeLimit());
    const oneMiBPlusOne = 1_048_576 + 1;

    const res = await app.request("/test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(oneMiBPlusOne),
      },
      body: "x",
    });

    expect(res.status).toBe(413);
  });

  test("rejects any request with oversized Content-Length regardless of method", async () => {
    const app = makeApp(bodySizeLimit({ maxBytes: 1 }));

    // Even a GET with a huge Content-Length should be rejected —
    // there is no reason to allow a GET body that would exceed the limit.
    const res = await app.request("/test", {
      method: "GET",
      headers: { "Content-Length": "999999" },
    });

    expect(res.status).toBe(413);
  });

  test("GET requests without a large Content-Length pass through normally", async () => {
    const app = makeApp(bodySizeLimit({ maxBytes: 100 }));

    const res = await app.request("/test", { method: "GET" });
    expect(res.status).toBe(200);
  });
});

// ── rateLimiter ────────────────────────────────────────────────────────────────

describe("rateLimiter", () => {
  test("allows requests within the window", async () => {
    const app = makeApp(rateLimiter({ windowMs: 60_000, maxRequests: 5 }));

    for (let i = 0; i < 5; i++) {
      const res = await app.request("/test", {
        headers: { "X-Forwarded-For": "10.0.0.1" },
      });
      expect(res.status).toBe(200);
    }
  });

  test("returns 429 on the request that exceeds maxRequests", async () => {
    const app = makeApp(rateLimiter({ windowMs: 60_000, maxRequests: 3 }));

    for (let i = 0; i < 3; i++) {
      await app.request("/test", {
        headers: { "X-Forwarded-For": "10.0.0.2" },
      });
    }

    const res = await app.request("/test", {
      headers: { "X-Forwarded-For": "10.0.0.2" },
    });

    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("rate_limit_exceeded");
    expect(res.headers.get("Retry-After")).toBeTruthy();
    expect(res.headers.get("X-RateLimit-Remaining")).toBe("0");
  });

  test("different IPs have independent counters", async () => {
    const app = makeApp(rateLimiter({ windowMs: 60_000, maxRequests: 2 }));

    // Exhaust IP A
    await app.request("/test", { headers: { "X-Forwarded-For": "192.168.1.1" } });
    await app.request("/test", { headers: { "X-Forwarded-For": "192.168.1.1" } });
    const resA3 = await app.request("/test", { headers: { "X-Forwarded-For": "192.168.1.1" } });
    expect(resA3.status).toBe(429);

    // IP B is still within its own limit
    const resB1 = await app.request("/test", { headers: { "X-Forwarded-For": "192.168.1.2" } });
    expect(resB1.status).toBe(200);
  });

  test("sets X-RateLimit-* headers on successful response", async () => {
    const app = makeApp(rateLimiter({ windowMs: 60_000, maxRequests: 10 }));

    const res = await app.request("/test", {
      headers: { "X-Forwarded-For": "10.0.0.5" },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("X-RateLimit-Limit")).toBe("10");
    expect(res.headers.get("X-RateLimit-Remaining")).toBeTruthy();
    expect(res.headers.get("X-RateLimit-Reset")).toBeTruthy();
  });

  test("falls back to 'unknown' IP when no forwarding headers", async () => {
    const app = makeApp(rateLimiter({ windowMs: 60_000, maxRequests: 1 }));

    // First request passes
    const res1 = await app.request("/test");
    expect(res1.status).toBe(200);

    // Second request from the same "unknown" IP is rate-limited
    const res2 = await app.request("/test");
    expect(res2.status).toBe(429);
  });
});

// ── resolveClientIp ────────────────────────────────────────────────────────────

describe("resolveClientIp", () => {
  function fakeReq(headers: Record<string, string>) {
    return {
      header: (name: string) => headers[name],
    };
  }

  test("prefers X-Forwarded-For first hop", () => {
    expect(resolveClientIp(fakeReq({ "X-Forwarded-For": "1.2.3.4, 5.6.7.8" }))).toBe("1.2.3.4");
  });

  test("falls back to X-Real-IP", () => {
    expect(resolveClientIp(fakeReq({ "X-Real-IP": "9.8.7.6" }))).toBe("9.8.7.6");
  });

  test("falls back to CF-Connecting-IP", () => {
    expect(resolveClientIp(fakeReq({ "CF-Connecting-IP": "3.3.3.3" }))).toBe("3.3.3.3");
  });

  test("returns 'unknown' when no headers", () => {
    expect(resolveClientIp(fakeReq({}))).toBe("unknown");
  });
});

// ── contentTypeGuard ───────────────────────────────────────────────────────────

describe("contentTypeGuard", () => {
  test("allows application/json POST", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });

    expect(res.status).toBe(200);
  });

  test("allows application/json with charset parameter", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: "{}",
    });

    expect(res.status).toBe(200);
  });

  test("rejects text/plain POST → 415", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "hello",
    });

    expect(res.status).toBe(415);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("unsupported_media_type");
  });

  test("rejects multipart/form-data POST → 415", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "multipart/form-data" },
      body: "data",
    });

    expect(res.status).toBe(415);
  });

  test("rejects POST with no Content-Type header → 415", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", {
      method: "POST",
      body: "{}",
    });

    expect(res.status).toBe(415);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("unsupported_media_type");
  });

  test("GET requests pass through regardless of content type", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", {
      method: "GET",
      headers: { "Content-Type": "text/plain" },
    });

    expect(res.status).toBe(200);
  });

  test("DELETE requests pass through", async () => {
    const app = makeApp(contentTypeGuard());

    const res = await app.request("/test", { method: "DELETE" });
    expect(res.status).toBe(200);
  });

  test("accepts custom allowed types", async () => {
    const app = makeApp(
      contentTypeGuard({ allowedTypes: ["application/json", "application/cbor"] }),
    );

    const jsonRes = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "application/cbor" },
      body: "data",
    });
    expect(jsonRes.status).toBe(200);

    const badRes = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "text/xml" },
      body: "<xml/>",
    });
    expect(badRes.status).toBe(415);
  });
});

// ── securityHeaders ────────────────────────────────────────────────────────────

describe("securityHeaders", () => {
  let app: Hono;

  beforeEach(() => {
    app = new Hono();
    app.use("*", securityHeaders());
    app.get("/test", (c) => c.json({ ok: true }));
    app.post("/test", (c) => c.json({ ok: true }));
  });

  afterEach(() => {
    app = new Hono();
  });

  test("sets X-Content-Type-Options: nosniff", async () => {
    const res = await app.request("/test");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  test("sets X-Frame-Options: DENY", async () => {
    const res = await app.request("/test");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
  });

  test("sets X-XSS-Protection: 0", async () => {
    const res = await app.request("/test");
    expect(res.headers.get("X-XSS-Protection")).toBe("0");
  });

  test("sets Referrer-Policy: strict-origin-when-cross-origin", async () => {
    const res = await app.request("/test");
    expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
  });

  test("sets Permissions-Policy restricting geolocation, microphone, camera", async () => {
    const res = await app.request("/test");
    const policy = res.headers.get("Permissions-Policy") ?? "";
    expect(policy).toContain("geolocation=()");
    expect(policy).toContain("microphone=()");
    expect(policy).toContain("camera=()");
  });

  test("sets Cache-Control: no-store", async () => {
    const res = await app.request("/test");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  test("headers are present on POST responses too", async () => {
    const res = await app.request("/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
  });

  test("all six security headers are present in a single response", async () => {
    const res = await app.request("/test");
    const requiredHeaders = [
      "X-Content-Type-Options",
      "X-Frame-Options",
      "X-XSS-Protection",
      "Referrer-Policy",
      "Permissions-Policy",
      "Cache-Control",
    ];
    for (const header of requiredHeaders) {
      expect(res.headers.get(header)).toBeTruthy();
    }
  });
});
