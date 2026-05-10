# syntax=docker/dockerfile:1.7
# ---------- Stage 1: build the React/Vite SPA --------------------------------
FROM node:20-bookworm-slim AS web

WORKDIR /web

# Copy manifest first for layer-cache friendliness, then install deps.
COPY frontend/package.json frontend/yarn.lock* ./
RUN corepack enable \
    && yarn install --frozen-lockfile --network-timeout 120000

# Copy the rest of the SPA source and build to /web/dist.
COPY frontend/ ./
RUN yarn build


# ---------- Stage 2: runtime ------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    RULEIQ_SPA_DIST=/app/static

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend/ /app/

# Pull the built SPA from the builder stage; FastAPI mounts /app/static at /.
COPY --from=web /web/dist/ /app/static/

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f "http://localhost:${PORT:-8080}/api/health" || exit 1

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
