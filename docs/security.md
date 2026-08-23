# PromptWall Day-2 Operations Runbook

This runbook provides operational guidelines, scaling rules, health troubleshooting, and telemetry management for PromptWall production deployments.

---

## 1. Health Diagnostics & Probes

| Endpoint | Probe Type | Target Status | Description |
| :--- | :--- | :--- | :--- |
| `GET /health/live` | Liveness | 200 OK | Confirms the container process is responsive. |
| `GET /health/ready` | Readiness | 200 OK / 503 Service Unavailable | Verifies database connectivity and LLM provider availability. |
| `GET /health` | Diagnostics | 200 / 503 | Detailed JSON output with uptime, memory, version, and provider map. |
| `GET /metrics` | Telemetry | 200 OK | Prometheus exposition metrics. |

---

## 2. Horizontal Scaling & Autoscaling

PromptWall is horizontally scalable and stateless.

### Autoscaling Rules (HPA):
- **Minimum Replicas**: 3
- **Maximum Replicas**: 10
- **CPU Threshold**: 70%
- **Memory Threshold**: 75%

### Manual Scale:
```bash
kubectl scale deployment promptwall --replicas=5
```

---

## 3. Prometheus Metrics & Alerting Guidelines

PromptWall exports standard metrics at `GET /metrics`:

### Key Metrics to Monitor:

| Metric Name | Type | Recommended Alert Condition | Action |
| :--- | :--- | :--- | :--- |
| `promptwall_provider_failures_total` | Counter | Rate > 5/min over 5m | Investigate upstream provider status page or check API key quota. |
| `promptwall_provider_failovers_total` | Counter | Rate > 1/min over 5m | Primary provider is degraded; verify automatic failover routing. |
| `promptwall_security_events_total{action="block"}` | Counter | Sudden 5x spike in 5m | Possible coordinated prompt injection or secret exfiltration attempt. |
| `promptwall_provider_latency_seconds` | Gauge | P95 > 2.0s over 10m | Provider latency degradation; check failover thresholds. |

---

## 4. Circuit Breaker & Provider Outage Operations

When an upstream LLM provider encounters repeated errors:
1. The Circuit Breaker transitions: `CLOSED` ➔ `OPEN`.
2. Requests to that provider fail fast or automatically route to the next configured fallback provider.
3. After `circuit_reset_timeout_ms` (default: 30s), the circuit transitions to `HALF_OPEN` to probe provider recovery.

### Checking Provider Health:
```bash
curl -s http://localhost:3000/health | jq .providers
```

---

## 5. Rolling Updates & Zero-Downtime Deployments

```bash
# Apply updated deployment image
kubectl set image deployment/promptwall promptwall=ghcr.io/sgasser/pasteguard:v1.1.0

# Watch rollout status
kubectl rollout status deployment/promptwall

# In case of issues, perform immediate rollback
kubectl rollout undo deployment/promptwall
```

---

## 6. Health Troubleshooting Guide

### Liveness Probe Failing (`/health/live`)

```bash
# Check container logs
kubectl logs -l app=promptwall --tail=100

# Describe pod for event history
kubectl describe pod -l app=promptwall

# Verify the process is up inside the container
kubectl exec -it <pod-name> -- curl -s http://localhost:3000/health/live
```

**Common Causes:**
- OOM kill: Increase memory limits in `k8s/deployment.yaml`
- Supervisord process crash: Check logs for startup errors
- Port conflict: Ensure port 3000 is not bound by another process

### Readiness Probe Failing (`/health/ready`)

```bash
# Get detailed health diagnostics
kubectl exec -it <pod-name> -- curl -s http://localhost:3000/health | jq .

# Check provider connectivity
kubectl exec -it <pod-name> -- curl -s http://localhost:3000/health | jq .providers
```

**Common Causes:**
- All LLM provider circuit breakers OPEN (no fallback available)
- Database connection pool exhausted
- Dependency service unreachable

### Pod CrashLoopBackOff

```bash
# Get last terminated container logs
kubectl logs <pod-name> --previous

# Get init container logs if applicable
kubectl logs <pod-name> -c init-config
```

---

## 7. Circuit Breaker Recovery

When an upstream LLM provider encounters repeated errors:

### State Transitions:
```
Normal operation:   CLOSED ──(failures > threshold)──► OPEN
OPEN (fail-fast):   OPEN   ──(reset_timeout elapsed)──► HALF_OPEN
Recovery probe:     HALF_OPEN ──(probe succeeds)───────► CLOSED
Continued failure:  HALF_OPEN ──(probe fails)──────────► OPEN
```

### Checking Circuit State:

```bash
# View current provider health and circuit states
curl -s http://localhost:3000/health | jq .providers

# Example response:
# {
#   "openai": { "status": "unhealthy", "circuit": "OPEN" },
#   "gemini": { "status": "healthy", "circuit": "CLOSED" }
# }
```

### Manual Circuit Reset (Force Recovery):

Since circuits auto-recover after `CIRCUIT_RESET_TIMEOUT_MS` (default: 30s), manual intervention is usually not required. However, to force immediate recovery:

```bash
# Rolling restart forces new pods with fresh circuit state
kubectl rollout restart deployment/promptwall

# Monitor recovery
kubectl rollout status deployment/promptwall
```

### Configuring Circuit Breaker Thresholds:

Edit `k8s/configmap.yaml`:
```yaml
CIRCUIT_FAILURE_THRESHOLD: "5"    # Failures before OPEN
CIRCUIT_RESET_TIMEOUT_MS: "30000" # Time in OPEN before HALF_OPEN probe
```
Apply changes:
```bash
kubectl apply -f k8s/configmap.yaml
kubectl rollout restart deployment/promptwall
```