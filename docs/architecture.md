# PromptWall Enterprise System Architecture

PromptWall is an enterprise-grade AI security gateway and observability proxy that protects organizational applications from prompt injections, secret leakage, and PII exposure before forwarding requests to LLM providers.

---

## 1. High-Level Request Lifecycle

```
Clients (Web App / SDK / Browser Extension)
                   │
                   ▼
       [ Ingress / Load Balancer ] (TLS Termination)
                   │
                   ▼
       [ Kubernetes Service :3000 ]
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                    PromptWall Pod                           │
│                                                             │
│  1. Request Security Middleware                             │
│     ├── Security Response Headers (CSP, HSTS, XSS)          │
│     ├── Body Size Limiter (HTTP 413)                        │
│     ├── Content-Type Enforcement (HTTP 415)                 │
│     ├── Per-IP Rate Limiting (HTTP 429)                     │
│     └── Correlation ID Middleware (X-Request-ID)            │
│                   │                                         │
│                   ▼                                         │
│  2. Detection Pipeline                                      │
│     ├── Secret Regex & Entropy Detectors                    │
│     ├── PII & Credit Card Detectors (GLiNER / Luhn)         │
│     └── Prompt Injection & Semantic Injection Detectors     │
│                   │                                         │
│                   ▼                                         │
│  3. Risk Assessment Engine                                  │
│     ├── Multi-Candidate Aggregation (Complement Product)     │
│     └── Risk Score & Level Resolution (Low/Med/High/Crit)   │
│                   │                                         │
│                   ▼                                         │
│  4. Versioned Policy Engine                                 │
│     ├── Immutable Policy Versions & Snapshots               │
│     ├── Deterministic Rule Evaluation                       │
│     └── Action Decision: ALLOW / MASK / BLOCK / ROUTE_LOCAL │
│                   │                                         │
│                   ▼                                         │
│  5. Resilient Provider Layer                                │
│     ├── Health Manager (Healthy / Degraded / Unhealthy)     │
│     ├── Timeout Handler (AbortSignal Deadlines)             │
│     ├── Exponential Backoff Retry Engine                    │
│     ├── Circuit Breaker (CLOSED / OPEN / HALF-OPEN)         │
│     └── Automatic Multi-Provider Failover Router            │
│                   │                                         │
│                   ▼                                         │
│  6. Audit Logger & Telemetry                                │
│     ├── Zero-Leak Audit Log (Metadata only)                 │
│     ├── Prometheus Metrics Scraper (/metrics)               │
│     └── Structured JSON Operational Logging                 │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                   External LLM Providers                    │
│      Google Gemini  │  OpenAI  │  Anthropic  │  Local LLM   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Component Subsystems

### A. Detection Pipeline (`packages/engine/src/detectors`)
- Executes independent, specialized security detectors concurrently.
- Standardized `Candidate` outputs specifying category, subtype, severity, confidence, and metadata.
- Zero raw prompt leaks into candidate evidence.

### B. Risk Engine (`packages/engine/src/risk`)
- Aggregates multi-candidate evidence into a normalized composite risk score (0–100).
- Applies severity-weighted complement product formula to prevent false saturation.

### C. Policy Engine (`src/policy`)
- Evaluates active security policy rules against the resolved risk score and candidate metadata.
- Full immutable history with version rollback capabilities (`/api/policies/:id/rollback`).

### D. Resilient Provider Gateway (`src/providers`)
- Translates client requests into provider-specific schemas (OpenAI, Gemini, Anthropic).
- Automatically retries transient 429/500/503 errors and fails over to healthy secondary providers when circuit breakers trip.

### E. Observability & Monitoring (`src/observability`)
- **Prometheus Metrics**: Exposes real-time request counts, security action totals, provider latency, failovers, and retries at `/metrics`.
- **Health Probes**: Liveness (`/health/live`), Readiness (`/health/ready`), and Diagnostics (`/health`).
- **Structured JSON Logging**: Machine-readable logs formatted for Elasticsearch, Fluentbit, and Datadog with redaction guarantees.

---

## 3. Observability Stack

```
┌─────────────────────────────────────────────────────────────┐
│                   PromptWall Pod (port 3000)                 │
│                                                             │
│  GET /metrics  ──────────────────────────────────┐         │
│  GET /health/live  ──── Liveness Probe           │         │
│  GET /health/ready ──── Readiness Probe          │         │
│  Structured JSON Logs ──► stdout / log collector │         │
└──────────────────────────────────────────────────┼─────────┘
                                                   │
                        ┌──────────────────────────▼──────────┐
                        │       Prometheus (port 9090)        │
                        │  Scrapes /metrics every 15s         │
                        │  Stores time-series data            │
                        │  Evaluates alerting rules           │
                        └──────────────────┬──────────────────┘
                                           │
                        ┌──────────────────▼──────────────────┐
                        │        Grafana (port 3001)          │
                        │  Visualizes Prometheus metrics      │
                        │  Security dashboards & alert panels │
                        │  Provider latency & failover graphs │
                        └─────────────────────────────────────┘
```

### Key Metrics Exported:

| Metric | Type | Description |
| :--- | :--- | :--- |
| `promptwall_requests_total` | Counter | Total proxied requests by status |
| `promptwall_security_events_total` | Counter | Security events by action (ALLOW/MASK/BLOCK) |
| `promptwall_provider_latency_seconds` | Gauge | LLM provider response latency |
| `promptwall_provider_failures_total` | Counter | Provider-level error counts |
| `promptwall_provider_failovers_total` | Counter | Cross-provider automatic failover count |
| `promptwall_circuit_breaker_state` | Gauge | Circuit state: 0=CLOSED, 1=OPEN, 2=HALF_OPEN |

### Health Probe Summary:

| Endpoint | Kubernetes Probe | Failure Response |
| :--- | :--- | :--- |
| `GET /health/live` | Liveness | Container restart triggered |
| `GET /health/ready` | Readiness | Pod removed from load balancer |
| `GET /health` | Diagnostics | Full JSON status with provider map |

---

## 4. Kubernetes Production Architecture

```
                        ┌──────────────────────────────────┐
                        │         User / Client            │
                        └──────────────┬───────────────────┘
                                       │ HTTPS
                        ┌──────────────▼───────────────────┐
                        │   Ingress (nginx + cert-manager) │
                        │   TLS Termination @ port 443      │
                        └──────────────┬───────────────────┘
                                       │ HTTP :3000
                        ┌──────────────▼───────────────────┐
                        │   Kubernetes Service (ClusterIP) │
                        └──┬───────────┬───────────┬───────┘
                           │           │           │
              ┌────────────▼─┐ ┌───────▼──┐ ┌─────▼────────┐
              │  Pod 1       │ │  Pod 2   │ │  Pod 3       │
              │  PromptWall  │ │PromptWall│ │  PromptWall  │
              └────────┬─────┘ └────┬─────┘ └──────┬───────┘
                       │            │               │
              ┌────────▼────────────▼───────────────▼───────┐
              │          Security Middleware Layer           │
              │   (Rate Limit · Body Guard · CORS · CSP)    │
              └──────────────────────┬───────────────────────┘
                                     │
              ┌──────────────────────▼───────────────────────┐
              │              Detection Pipeline              │
              │  (Secrets · PII · Injection · Semantic)      │
              └──────────────────────┬───────────────────────┘
                                     │
              ┌──────────────────────▼───────────────────────┐
              │              Policy Engine                   │
              │  (Versioned Rules · ALLOW/MASK/BLOCK)        │
              └──────────────────────┬───────────────────────┘
                                     │
              ┌──────────────────────▼───────────────────────┐
              │         Resilient Provider Gateway           │
              │  (Circuit Breaker · Retry · Failover)        │
              └──────┬───────────┬──────────────┬────────────┘
                     │           │              │
           ┌─────────▼─┐ ┌──────▼──┐ ┌────────▼────┐
           │  OpenAI   │ │ Gemini  │ │  Anthropic  │
           └───────────┘ └─────────┘ └─────────────┘
```

