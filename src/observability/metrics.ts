/**
 * @file metrics.ts
 * @module src/observability
 *
 * Enterprise Prometheus Metrics Integration (Milestone 10).
 *
 * Collects, maintains, and exports Prometheus-compatible exposition format metrics:
 *   - Gateway metrics: promptwall_requests_total{route, provider, action}
 *   - Security metrics: promptwall_security_events_total{action, riskLevel, detector}
 *   - Provider metrics: promptwall_provider_requests_total, promptwall_provider_failures_total,
 *     promptwall_provider_latency_seconds, promptwall_provider_failovers_total, promptwall_provider_retries_total
 *   - Policy metrics: promptwall_policy_evaluations_total{policy, decision}
 */

import { type GlobalProviderMetrics, getProviderMetrics } from "../providers/provider-metrics";

function formatLabels(labels: Record<string, string>): string {
  const entries = Object.entries(labels).filter(([_, v]) => v !== undefined && v !== "");
  if (entries.length === 0) return "";
  const labelStr = entries
    .map(([k, v]) => `${k}="${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`)
    .join(",");
  return `{${labelStr}}`;
}

export class PrometheusMetricsRegistry {
  private requestCounts = new Map<string, number>();
  private securityEventCounts = new Map<string, number>();
  private policyEvaluationCounts = new Map<string, number>();

  /**
   * Record a gateway request metric.
   */
  public recordRequestMetric(route: string, provider: string, action: string, increment = 1): void {
    const key = JSON.stringify({ route, provider, action });
    const current = this.requestCounts.get(key) ?? 0;
    this.requestCounts.set(key, current + increment);
  }

  /**
   * Record a security event metric.
   */
  public recordSecurityEventMetric(
    action: string,
    riskLevel: string,
    detector = "none",
    increment = 1,
  ): void {
    const key = JSON.stringify({ action, riskLevel, detector });
    const current = this.securityEventCounts.get(key) ?? 0;
    this.securityEventCounts.set(key, current + increment);
  }

  /**
   * Record a policy evaluation metric.
   */
  public recordPolicyEvaluationMetric(policy: string, decision: string, increment = 1): void {
    const key = JSON.stringify({ policy, decision });
    const current = this.policyEvaluationCounts.get(key) ?? 0;
    this.policyEvaluationCounts.set(key, current + increment);
  }

  /**
   * Export all metrics in Prometheus text exposition format (version 0.0.4).
   */
  public exportMetrics(): string {
    const lines: string[] = [];

    // 1. Gateway Requests Total
    lines.push("# HELP promptwall_requests_total Total gateway requests");
    lines.push("# TYPE promptwall_requests_total counter");
    if (this.requestCounts.size === 0) {
      lines.push('promptwall_requests_total{route="none",provider="none",action="none"} 0');
    } else {
      for (const [keyStr, val] of this.requestCounts.entries()) {
        const labels = JSON.parse(keyStr) as Record<string, string>;
        lines.push(`promptwall_requests_total${formatLabels(labels)} ${val}`);
      }
    }
    lines.push("");

    // 2. Security Events Total
    lines.push("# HELP promptwall_security_events_total Total security events assessed");
    lines.push("# TYPE promptwall_security_events_total counter");
    if (this.securityEventCounts.size === 0) {
      lines.push(
        'promptwall_security_events_total{action="none",riskLevel="none",detector="none"} 0',
      );
    } else {
      for (const [keyStr, val] of this.securityEventCounts.entries()) {
        const labels = JSON.parse(keyStr) as Record<string, string>;
        lines.push(`promptwall_security_events_total${formatLabels(labels)} ${val}`);
      }
    }
    lines.push("");

    // 3. Provider Metrics (integrated with real-time M9B provider-metrics tracker)
    const providerStats = getProviderMetrics() as GlobalProviderMetrics;

    lines.push("# HELP promptwall_provider_requests_total Total requests sent to LLM providers");
    lines.push("# TYPE promptwall_provider_requests_total counter");
    const providersList = Object.values(providerStats.providers);
    if (providersList.length === 0) {
      lines.push('promptwall_provider_requests_total{provider="none"} 0');
    } else {
      for (const p of providersList) {
        lines.push(
          `promptwall_provider_requests_total{provider="${p.provider}"} ${p.totalRequests}`,
        );
      }
    }
    lines.push("");

    lines.push("# HELP promptwall_provider_failures_total Total failed requests per LLM provider");
    lines.push("# TYPE promptwall_provider_failures_total counter");
    if (providersList.length === 0) {
      lines.push('promptwall_provider_failures_total{provider="none"} 0');
    } else {
      for (const p of providersList) {
        lines.push(
          `promptwall_provider_failures_total{provider="${p.provider}"} ${p.failedRequests}`,
        );
      }
    }
    lines.push("");

    lines.push("# HELP promptwall_provider_latency_seconds Average provider latency in seconds");
    lines.push("# TYPE promptwall_provider_latency_seconds gauge");
    if (providersList.length === 0) {
      lines.push('promptwall_provider_latency_seconds{provider="none"} 0');
    } else {
      for (const p of providersList) {
        const latencySec = (p.averageLatencyMs / 1000).toFixed(3);
        lines.push(`promptwall_provider_latency_seconds{provider="${p.provider}"} ${latencySec}`);
      }
    }
    lines.push("");

    lines.push(
      "# HELP promptwall_provider_failovers_total Total failovers originating from provider",
    );
    lines.push("# TYPE promptwall_provider_failovers_total counter");
    if (providersList.length === 0) {
      lines.push('promptwall_provider_failovers_total{provider="none"} 0');
    } else {
      for (const p of providersList) {
        lines.push(`promptwall_provider_failovers_total{provider="${p.provider}"} ${p.failovers}`);
      }
    }
    lines.push("");

    lines.push("# HELP promptwall_provider_retries_total Total retry attempts per provider");
    lines.push("# TYPE promptwall_provider_retries_total counter");
    if (providersList.length === 0) {
      lines.push('promptwall_provider_retries_total{provider="none"} 0');
    } else {
      for (const p of providersList) {
        lines.push(`promptwall_provider_retries_total{provider="${p.provider}"} ${p.retries}`);
      }
    }
    lines.push("");

    // 4. Policy Metrics
    lines.push("# HELP promptwall_policy_evaluations_total Total policy evaluations");
    lines.push("# TYPE promptwall_policy_evaluations_total counter");
    if (this.policyEvaluationCounts.size === 0) {
      lines.push('promptwall_policy_evaluations_total{policy="none",decision="none"} 0');
    } else {
      for (const [keyStr, val] of this.policyEvaluationCounts.entries()) {
        const labels = JSON.parse(keyStr) as Record<string, string>;
        lines.push(`promptwall_policy_evaluations_total${formatLabels(labels)} ${val}`);
      }
    }
    lines.push("");

    return lines.join("\n");
  }

  /**
   * Reset all metric counters (for testing).
   */
  public reset(): void {
    this.requestCounts.clear();
    this.securityEventCounts.clear();
    this.policyEvaluationCounts.clear();
  }
}

export const prometheusMetrics = new PrometheusMetricsRegistry();

// Top-level exported helper functions matching spec
export const recordRequestMetric = (route: string, provider: string, action: string) =>
  prometheusMetrics.recordRequestMetric(route, provider, action);

export const recordSecurityEventMetric = (action: string, riskLevel: string, detector?: string) =>
  prometheusMetrics.recordSecurityEventMetric(action, riskLevel, detector);

export const recordPolicyEvaluationMetric = (policy: string, decision: string) =>
  prometheusMetrics.recordPolicyEvaluationMetric(policy, decision);

export const exportPrometheusMetrics = () => prometheusMetrics.exportMetrics();

export const resetMetrics = () => prometheusMetrics.reset();
