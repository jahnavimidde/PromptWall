# PromptWall Milestone 11 Deployment Verification Checklist

This document details the automated and operational verification checklist for PromptWall cloud-native deployment assets.

---

## 1. Docker Build & Container Hardening Verification

- [x] **Multi-Stage Build**: `docker/Dockerfile` uses distinct `bun-builder`, `detector`, and `allinone` stages.
- [x] **Non-Root Execution**: Container explicitly executes under UID `1000` (`pasteguard`), with `USER 1000`.
- [x] **Health Check Configured**: Docker `HEALTHCHECK` runs `curl --fail http://localhost:3000/health/live || exit 1`.
- [x] **Minimal Footprint**: `.dockerignore` excludes `.git`, `node_modules`, test files (`*.test.ts`), `coverage`, `logs`, and development assets.
- [x] **Offline Model Availability**: PyTorch GLiNER model is baked into image with `HF_HUB_OFFLINE=1`.
- [x] **Canonical Dockerfile**: All CI/CD workflows (`ci.yml`, `security.yml`, `deploy.yml`, `release.yml`) reference `docker/Dockerfile`.

---

## 2. Kubernetes Manifests Schema & Configuration Verification

- [x] **Deployment (`k8s/deployment.yaml`)**:
  - Replicas configured to 3.
  - Rolling update strategy with `maxSurge: 1`, `maxUnavailable: 0`.
  - Resource requests (`500m` CPU / `1Gi` RAM) and limits (`2000m` CPU / `4Gi` RAM).
  - Liveness probe configured for `/health/live` on port 3000.
  - Readiness probe configured for `/health/ready` on port 3000.
  - Security context enforces `runAsNonRoot: true`, `runAsUser: 1000`, `allowPrivilegeEscalation: false`, and drops `ALL` capabilities.
  - Environment sourced from `promptwall-config` ConfigMap and `promptwall-secret` Secret.
- [x] **Service (`k8s/service.yaml`)**: Exposes ClusterIP service on TCP port 3000 with selector `app: promptwall`.
- [x] **Ingress (`k8s/ingress.yaml`)**: Configures TLS termination and HTTPS routing for `promptwall.example.com`.
- [x] **ConfigMap (`k8s/configmap.yaml`)**: Externalizes non-sensitive operational configurations only.
- [x] **Secret (`k8s/secret.yaml`)**: Templates sensitive credentials with `CHANGE_ME_*` placeholders — no real credentials.
- [x] **HPA (`k8s/hpa.yaml`)**: Scales between 3 and 10 pods on 70% CPU and 75% RAM thresholds.
- [x] **NetworkPolicy (`k8s/network-policy.yaml`)**: Default deny with allow rules for ingress-controllers (port 3000), Prometheus, DNS (53), HTTPS (443), and DB (5432).

---

## 3. CI/CD Automation Verification

- [x] **CI Workflow (`.github/workflows/ci.yml`)**: Executes `bun install --frozen-lockfile`, `bun run typecheck` (`tsc --noEmit`), `bun test`, and `bun run check`.
- [x] **Security Workflow (`.github/workflows/security.yml`)**: Executes `npm audit --omit=dev --audit-level=moderate` and Trivy container vulnerability scanner targeting `docker/Dockerfile`.
- [x] **Deployment Workflow (`.github/workflows/deploy.yml`)**: Automates test validation → container build/publish (using `docker/Dockerfile`) → Kubernetes rolling update via `kubectl rollout`.
- [x] **Release Workflow (`.github/workflows/release.yml`)**: Tag-triggered multi-platform (`linux/amd64,linux/arm64`) image build and GHCR publish.

---

## 4. Production Documentation Verification

- [x] **Deployment Guide (`docs/deployment.md`)**: Local, Docker, Compose, and Kubernetes deployment workflows.
- [x] **Architecture Guide (`docs/architecture.md`)**: Component subsystems, request flow diagram, observability stack (Prometheus/Grafana/Health/Logs), and Kubernetes production architecture diagram.
- [x] **Operations Runbook (`docs/operations.md`)**: Scaling, alerts, rolling updates, health troubleshooting (liveness/readiness/CrashLoopBackOff), circuit breaker recovery with state transitions.
- [x] **Security Posture (`docs/security.md`)**: Defense-in-depth, non-root execution, NetworkPolicies, RBAC, zero-leak logging, secret management (External Secrets Operator), container hardening (multi-stage, capabilities, privilege escalation).

---

## 5. Application Invariant & Regression Verification

- [x] All 814 unit and integration tests pass with 0 failures (`bun test`) — 815 total, 1 skipped (Postgres integration, no DB in CI).
- [x] TypeScript compiler typecheck passes with 0 errors (`bun x tsc --noEmit`).
- [x] Biome linter and formatter passes with 0 errors across 155 files (`bun run check`).
- [x] DetectionPipeline, PolicyEngine, RiskEngine, AuditLogger, Provider Resilience, and Authentication/RBAC remain unmodified.

---

## 6. Security Checks Completed

- [x] No real secrets or API keys present in any committed infrastructure file.
- [x] All `k8s/secret.yaml` values use `CHANGE_ME_*` placeholder pattern.
- [x] `.dockerignore` excludes `.env` and `.env.*` files from all image builds.
- [x] Container runs as non-root UID 1000 — verified in `docker/Dockerfile` (`USER 1000`) and `k8s/deployment.yaml` (`runAsUser: 1000`).
- [x] Trivy container scan configured in `security.yml` (CRITICAL + HIGH severity).
- [x] NetworkPolicy enforces default-deny with minimal allow rules.

