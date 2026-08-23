# PromptWall Production Deployment Guide

This document outlines deployment methods for PromptWall across local development, containerized environments, and cloud-native Kubernetes clusters.

---

## 1. Local Development

### Prerequisites
- [Bun](https://bun.sh) (v1.1+)
- Python 3.11+ (for local PII detector)

```bash
# 1. Install dependencies
bun install

# 2. Configure environment
cp config.example.yaml config.yaml

# 3. Start development server with hot reload
bun run dev
```

The gateway listens on `http://localhost:3000`.

---

## 2. Docker Deployment

### Single-Container All-in-One Image
PromptWall provides an all-in-one hardened Docker image containing the Bun AI security proxy and the local ML detection engine managed by supervisord.

```bash
# Build the production image
docker build -t promptwall:latest .

# Run with mounted configuration and data directories
docker run -d \
  --name promptwall \
  -p 3000:3000 \
  -v $(pwd)/config.yaml:/pasteguard/config.yaml:ro \
  -v $(pwd)/data:/pasteguard/data \
  -e OPENAI_API_KEY="sk-..." \
  -e GEMINI_API_KEY="AIza..." \
  promptwall:latest
```

---

## 3. Docker Compose (Full Stack with Observability)

Run PromptWall alongside Prometheus and Grafana:

```bash
# Start full observability stack
docker compose --profile observability up -d
```

### Services Started:
- **PromptWall Gateway**: `http://localhost:3000`
- **Prometheus Scraper**: `http://localhost:9090`
- **Grafana Dashboards**: `http://localhost:3001`

---

## 4. Cloud-Native Kubernetes Deployment

PromptWall includes production-ready Kubernetes manifests in `k8s/`:

### Manifest Architecture
```
k8s/
├── configmap.yaml       # Operational settings (Rate limits, timeouts, log levels)
├── secret.yaml          # Sensitive credentials (API keys, JWT secret, bearer tokens)
├── deployment.yaml      # 3-replica rolling deployment with health probes & non-root context
├── service.yaml         # ClusterIP service on port 3000
├── ingress.yaml         # Ingress routing with TLS termination
├── hpa.yaml             # Horizontal Pod Autoscaler (3-10 pods)
└── network-policy.yaml  # Strict ingress/egress network isolation
```

### Deployment Steps:

1. **Configure Secrets**:
   Edit `k8s/secret.yaml` with your provider API keys and JWT secret:
   ```bash
   kubectl apply -f k8s/secret.yaml
   ```

2. **Apply Configuration**:
   ```bash
   kubectl apply -f k8s/configmap.yaml
   ```

3. **Deploy Workload & Networking**:
   ```bash
   kubectl apply -f k8s/deployment.yaml
   kubectl apply -f k8s/service.yaml
   kubectl apply -f k8s/ingress.yaml
   kubectl apply -f k8s/hpa.yaml
   kubectl apply -f k8s/network-policy.yaml
   ```

4. **Verify Deployment Health**:
   ```bash
   kubectl rollout status deployment/promptwall
   kubectl get pods -l app=promptwall
   ```

---

## 5. Verification & Health Probes

```bash
# Liveness Probe (HTTP 200)
curl -i http://localhost:3000/health/live

# Readiness Probe (HTTP 200 when ready, 503 if unready)
curl -i http://localhost:3000/health/ready

# Comprehensive Diagnostics
curl -i http://localhost:3000/health

# Prometheus Metrics Scrape
curl -i http://localhost:3000/metrics
```
