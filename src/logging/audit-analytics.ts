/**
 * @file audit-analytics.ts
 * @module src/logging
 *
 * Real-time security risk analytics and metrics aggregation engine (M6B).
 * Calculates action breakdowns, risk level distributions, detector frequencies,
 * threat subtype counts, latency percentiles (P50, P95, Avg), and time-series rollups.
 */

import { getConfig } from "../config";
import { createLogDatabase, migrateLogDatabase, type LogKysely } from "./db";
import type { CandidateSummary } from "@promptwall/engine";

export interface ActionBreakdown {
  allow: number;
  mask: number;
  block: number;
  allowPercentage: number;
  maskPercentage: number;
  blockPercentage: number;
}

export interface RiskLevelDistribution {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface DetectorStat {
  detector: string;
  count: number;
}

export interface ThreatSubtypeStat {
  subtype: string;
  category: string;
  count: number;
}

export interface LatencyMetrics {
  avg: number;
  p50: number;
  p95: number;
  max: number;
}

export interface TimeSeriesPoint {
  timestamp: string; // ISO bucket timestamp
  allow: number;
  mask: number;
  block: number;
  avgRiskScore: number;
}

export interface SecurityAnalytics {
  timeframe: string; // e.g. "24h", "7d", "30d", "all"
  totalEvents: number;
  actionBreakdown: ActionBreakdown;
  riskLevelDistribution: RiskLevelDistribution;
  topDetectors: readonly DetectorStat[];
  topThreatSubtypes: readonly ThreatSubtypeStat[];
  latencyMetrics: LatencyMetrics;
  timeSeries: readonly TimeSeriesPoint[];
}

let defaultDbInstance: LogKysely | null = null;
let defaultDbReady: Promise<void> | null = null;

function getDb(customDb?: LogKysely): { db: LogKysely; ready: Promise<void> } {
  if (customDb) {
    return { db: customDb, ready: Promise.resolve() };
  }
  if (!defaultDbInstance) {
    const config = getConfig();
    const { db, driver } = createLogDatabase(config);
    defaultDbInstance = db;
    defaultDbReady = migrateLogDatabase(db, driver);
  }
  return { db: defaultDbInstance, ready: defaultDbReady! };
}

/**
 * Get security analytics and threat statistics for a given timeframe.
 *
 * @param timeframe - Range: "1h" | "24h" | "7d" | "30d" | "all" (default "24h").
 * @param customDb - Optional Kysely instance for testing.
 */
export async function getSecurityAnalytics(
  timeframe: "1h" | "24h" | "7d" | "30d" | "all" = "24h",
  customDb?: LogKysely,
): Promise<SecurityAnalytics> {
  const { db, ready } = getDb(customDb);
  await ready;

  let query = db.selectFrom("security_events");

  let cutoffDate: Date | null = null;
  if (timeframe !== "all") {
    cutoffDate = new Date();
    if (timeframe === "1h") {
      cutoffDate.setHours(cutoffDate.getHours() - 1);
    } else if (timeframe === "24h") {
      cutoffDate.setHours(cutoffDate.getHours() - 24);
    } else if (timeframe === "7d") {
      cutoffDate.setDate(cutoffDate.getDate() - 7);
    } else if (timeframe === "30d") {
      cutoffDate.setDate(cutoffDate.getDate() - 30);
    }
    query = query.where("timestamp", ">=", cutoffDate.toISOString());
  }

  const rows = await query
    .select([
      "timestamp",
      "action",
      "risk_level",
      "risk_score",
      "candidates",
      "detectors_triggered",
      "latency_ms",
    ])
    .execute();

  const totalEvents = rows.length;

  // 1. Action Breakdown
  let allowCount = 0;
  let maskCount = 0;
  let blockCount = 0;

  // 2. Risk Level Distribution
  let lowCount = 0;
  let mediumCount = 0;
  let highCount = 0;
  let criticalCount = 0;

  // 3. Detector & Subtype Frequencies
  const detectorCounts = new Map<string, number>();
  const subtypeCounts = new Map<string, { category: string; count: number }>();

  // 4. Latency metric values
  const latencies: number[] = [];

  // 5. Time-series bucket map
  const timeSeriesBuckets = new Map<
    string,
    { allow: number; mask: number; block: number; riskScores: number[] }
  >();

  for (const row of rows) {
    // Action counts
    if (row.action === "allow") allowCount++;
    else if (row.action === "mask") maskCount++;
    else if (row.action === "block") blockCount++;

    // Risk level counts
    if (row.risk_level === "low") lowCount++;
    else if (row.risk_level === "medium") mediumCount++;
    else if (row.risk_level === "high") highCount++;
    else if (row.risk_level === "critical") criticalCount++;

    // Latency
    const latency = Number(row.latency_ms);
    latencies.push(latency);

    // Detectors
    const detectors = JSON.parse(row.detectors_triggered) as string[];
    for (const d of detectors) {
      detectorCounts.set(d, (detectorCounts.get(d) ?? 0) + 1);
    }

    // Subtypes from safe CandidateSummary array
    const candidates = JSON.parse(row.candidates) as CandidateSummary[];
    for (const c of candidates) {
      const existing = subtypeCounts.get(c.subtype);
      if (existing) {
        existing.count++;
      } else {
        subtypeCounts.set(c.subtype, { category: c.category, count: 1 });
      }
    }

    // Time-series bucket (truncate to hour for <7d, day for >=7d)
    const dateObj = new Date(row.timestamp);
    const bucketKey =
      timeframe === "7d" || timeframe === "30d" || timeframe === "all"
        ? dateObj.toISOString().slice(0, 10) // YYYY-MM-DD
        : dateObj.toISOString().slice(0, 13) + ":00:00.000Z"; // YYYY-MM-DDTHH:00:00.000Z

    let bucket = timeSeriesBuckets.get(bucketKey);
    if (!bucket) {
      bucket = { allow: 0, mask: 0, block: 0, riskScores: [] };
      timeSeriesBuckets.set(bucketKey, bucket);
    }

    if (row.action === "allow") bucket.allow++;
    else if (row.action === "mask") bucket.mask++;
    else if (row.action === "block") bucket.block++;
    bucket.riskScores.push(Number(row.risk_score));
  }

  // Calculate Action Percentages
  const roundPct = (count: number) =>
    totalEvents > 0 ? Math.round((count / totalEvents) * 100 * 10) / 10 : 0;

  const actionBreakdown: ActionBreakdown = {
    allow: allowCount,
    mask: maskCount,
    block: blockCount,
    allowPercentage: roundPct(allowCount),
    maskPercentage: roundPct(maskCount),
    blockPercentage: roundPct(blockCount),
  };

  const riskLevelDistribution: RiskLevelDistribution = {
    low: lowCount,
    medium: mediumCount,
    high: highCount,
    critical: criticalCount,
  };

  // Sort detectors by count desc
  const topDetectors: DetectorStat[] = Array.from(detectorCounts.entries())
    .map(([detector, count]) => ({ detector, count }))
    .sort((a, b) => b.count - a.count);

  // Sort threat subtypes by count desc
  const topThreatSubtypes: ThreatSubtypeStat[] = Array.from(subtypeCounts.entries())
    .map(([subtype, val]) => ({ subtype, category: val.category, count: val.count }))
    .sort((a, b) => b.count - a.count);

  // Compute latency percentiles
  latencies.sort((a, b) => a - b);
  let avgLatency = 0;
  let p50Latency = 0;
  let p95Latency = 0;
  let maxLatency = 0;

  if (latencies.length > 0) {
    const sum = latencies.reduce((acc, curr) => acc + curr, 0);
    avgLatency = Math.round(sum / latencies.length);
    p50Latency = latencies[Math.floor(latencies.length * 0.5)];
    p95Latency = latencies[Math.floor(latencies.length * 0.95)];
    maxLatency = latencies[latencies.length - 1];
  }

  const latencyMetrics: LatencyMetrics = {
    avg: avgLatency,
    p50: p50Latency,
    p95: p95Latency,
    max: maxLatency,
  };

  // Build sorted time-series points
  const timeSeries: TimeSeriesPoint[] = Array.from(timeSeriesBuckets.entries())
    .map(([bucketKey, b]) => {
      const avgScore =
        b.riskScores.length > 0
          ? Math.round(
              (b.riskScores.reduce((acc, s) => acc + s, 0) / b.riskScores.length) * 10,
            ) / 10
          : 0;

      return {
        timestamp: bucketKey,
        allow: b.allow,
        mask: b.mask,
        block: b.block,
        avgRiskScore: avgScore,
      };
    })
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  return {
    timeframe,
    totalEvents,
    actionBreakdown,
    riskLevelDistribution,
    topDetectors,
    topThreatSubtypes,
    latencyMetrics,
    timeSeries,
  };
}
