/**
 * @file metrics.ts
 * @module src/routes
 *
 * Prometheus Metrics Scrape Endpoint (Milestone 10).
 *
 * Serves GET /metrics in Prometheus standard text format with optional bearer token protection.
 */

import { Hono } from "hono";
import { getConfig } from "../config";
import { exportPrometheusMetrics } from "../observability/metrics";

export const metricsRoutes = new Hono();

metricsRoutes.get("/", async (c) => {
  const config = getConfig();
  const requiredToken =
    config.observability?.prometheus_auth_token || process.env.PROMETHEUS_AUTH_TOKEN;

  if (requiredToken && requiredToken.trim().length > 0) {
    const authHeader = c.req.header("Authorization") || c.req.header("authorization");
    const expected = `Bearer ${requiredToken.trim()}`;

    if (!authHeader || authHeader.trim() !== expected) {
      return c.json(
        {
          error: {
            message: "Unauthorized. Valid Prometheus bearer token required.",
            type: "unauthorized",
          },
        },
        401,
      );
    }
  }

  const metricsOutput = exportPrometheusMetrics();

  return c.text(metricsOutput, 200, {
    "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
  });
});
