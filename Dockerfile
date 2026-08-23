# PromptWall — Enterprise Production Multi-Stage Dockerfile (Milestone 11)
#
# Build targets:
#   * detector  — Standalone PII/Injection ML detector service (FastAPI on :5002)
#                 docker build --target detector -t promptwall-detector .
#   * (default) — Full Enterprise Gateway image: Bun proxy + ML detector under supervisord
#                 docker build -t promptwall:latest .

# =============================================================================
# Stage 1: bun-builder — Install dependencies and bundle application
# =============================================================================
FROM oven/bun:1-slim AS bun-builder

WORKDIR /app
ENV NODE_ENV=production

COPY package.json bun.lock ./
COPY packages ./packages
RUN bun install --frozen-lockfile --production

COPY src ./src
COPY tsconfig.json ./

# =============================================================================
# Stage 2: detector — PII & Semantic Injection ML Detector service
# =============================================================================
FROM python:3.11-slim AS detector

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install CPU-only PyTorch (avoids dragging ~6GB CUDA runtime into CPU containers)
RUN pip install --no-cache-dir typing-extensions \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install detector package
COPY detector/pyproject.toml /srv/detector/
COPY detector/detector /srv/detector/detector
RUN pip install --no-cache-dir /srv/detector

# Bake offline model into image
ENV DETECTOR_MODEL=urchade/gliner_multi_pii-v1 \
    HF_HOME=/opt/models \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

RUN ok=""; for i in 1 2 3; do \
        python -c "import os; from gliner import GLiNER; GLiNER.from_pretrained(os.environ['DETECTOR_MODEL'])" && { ok=1; break; }; \
        echo "model fetch attempt $i failed; retrying in 10s"; sleep 10; \
    done; \
    [ -n "$ok" ] && chown -R 1000:1000 /opt/models || exit 1

EXPOSE 5002
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5002/health').status==200 else 1)"

CMD ["uvicorn", "detector.app:app", "--host", "0.0.0.0", "--port", "5002"]

# =============================================================================
# Stage 3: allinone — Hardened Enterprise Production Runtime (Default Target)
# =============================================================================
FROM detector AS allinone

LABEL org.opencontainers.image.title="PromptWall"
LABEL org.opencontainers.image.description="Enterprise AI Security & Observability Gateway"
LABEL org.opencontainers.image.vendor="PromptWall"

# Install minimal supervisor and curl for health probes
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Bun binary from official builder
COPY --from=bun-builder /usr/local/bin/bun /usr/local/bin/bun
ENV PATH="/usr/local/bin:${PATH}"

# Copy production application assets
WORKDIR /pasteguard
ENV NODE_ENV=production \
    DETECTOR_URL=http://localhost:5002 \
    PORT=3000 \
    HOME=/home/pasteguard

COPY --from=bun-builder /app/node_modules ./node_modules
COPY --from=bun-builder /app/packages ./packages
COPY --from=bun-builder /app/src ./src
COPY --from=bun-builder /app/package.json ./
COPY --from=bun-builder /app/tsconfig.json ./
COPY config.example.yaml ./

# Create non-root runtime user & group (UID 1000)
RUN useradd --uid 1000 --create-home --home-dir /home/pasteguard pasteguard \
    && mkdir -p /pasteguard/data /var/log/supervisor /var/run \
    && chown -R 1000:1000 /pasteguard /var/log/supervisor /var/run /home/pasteguard

COPY docker/supervisord.conf /etc/supervisor/conf.d/pasteguard.conf

USER 1000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl --fail http://localhost:3000/health/live || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/pasteguard.conf"]
