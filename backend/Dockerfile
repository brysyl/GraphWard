# =============================================================================
# Stage 1 — dependency builder
#   Installs production Python packages into an isolated venv so the final
#   image contains no pip, setuptools, or build-time artefacts.
# =============================================================================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Suppress interactive apt prompts when running headless in Docker.
    DEBIAN_FRONTEND=noninteractive

WORKDIR /build

# gcc is needed to compile C-extension wheels (uvloop, watchfiles, httptools).
# The entire apt cache is purged in the same layer to keep the builder lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# Create a self-contained virtual environment so nothing bleeds into the
# system Python in the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy the production-only manifest first to leverage Docker layer caching.
COPY requirements-prod.txt ./
RUN pip install --upgrade pip --quiet \
    && pip install --no-cache-dir -r requirements-prod.txt


# =============================================================================
# Stage 2 — production runtime
#   Only the pre-built venv and application source are present.
#   No compilers, no pip, no test tooling.
# =============================================================================
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app"

# ---- Non-root security context ----
# Use a regular (non-system) account at uid/gid 1001 to avoid the
# Debian SYS_UID_MAX=999 warning produced by --system on slim images.
RUN groupadd --gid 1001 graphward \
    && useradd --uid 1001 --gid graphward \
       --no-create-home --shell /sbin/nologin graphward

WORKDIR /app

# Copy the pre-built venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Copy application source; exclude everything listed in .dockerignore.
COPY --chown=graphward:graphward . .

USER graphward

EXPOSE 8000

# ---- Health check ----
# Polls the /health liveness endpoint every 30 s via the stdlib so no
# additional runtime dependency (curl / wget) is required.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
