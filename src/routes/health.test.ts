import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { healthRoutes } from "./health";

const app = new Hono();
app.route("/", healthRoutes);

// NOTE: GET / is intentionally NOT tested here. The root route is served by
// the landing page (landingRoutes), not healthRoutes. That redirect was removed
// when the landing page was added.

describe("GET /health", () => {
  test("returns health status", async () => {
    const res = await app.request("/health");

    // May be 200 (healthy) or 503 (degraded) depending on the detector
    expect([200, 503]).toContain(res.status);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toMatch(/healthy|degraded/);
    expect(body.services).toBeDefined();
    expect(body.timestamp).toBeDefined();
  });
});
