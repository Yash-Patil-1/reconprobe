# =============================================================================
# ReconProbe — Multi-stage Dockerfile
#
# Build stage:  Installs OS deps + Python packages
# Runtime:      Lean python:3.11-slim with only what's needed
# =============================================================================

# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install Python build deps first for caching
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install runtime deps from pyproject (no dev extras)
RUN pip install --no-cache-dir \
    httpx>=0.27 \
    rich>=13.0 \
    beautifulsoup4>=4.12 \
    dnspython>=2.6 \
    fastapi>=0.100 \
    uvicorn>=0.24 \
    aiohttp>=3.9 \
    aiosmtplib>=5.0 \
    pyyaml>=6.0 \
    fpdf2>=2.7 \
    openpyxl>=3.1

# Copy source
COPY reconprobe/ ./reconprobe/
COPY tests/ ./tests/

# Verify imports
RUN python -c "import reconprobe; print(f'ReconProbe v{reconprobe.__version__}')"

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Yash Patil"
LABEL description="ReconProbe — Automated reconnaissance tool for penetration testing"
LABEL version="1.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages and source from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /build/reconprobe /app/reconprobe

WORKDIR /app

# Default: serve mode
ENV RECONPROBE_MODE="serve"
ENV RECONPROBE_HOST="0.0.0.0"
ENV RECONPROBE_PORT="8000"

EXPOSE 8000

ENTRYPOINT ["python", "-m", "reconprobe.cli"]
CMD ["--serve"]
