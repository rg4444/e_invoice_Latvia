# Base
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# -------- Network helper (retry-friendly apt) --------
# Tiny helper to verify outbound connectivity before apt
RUN printf '#!/bin/sh\ntries=0; while [ $tries -lt 12 ]; do if ping -c1 -W2 deb.debian.org >/dev/null 2>&1 || nc -z -w2 deb.debian.org 80 >/dev/null 2>&1; then exit 0; fi; tries=$((tries+1)); echo "[netcheck] waiting for network... ($tries)"; sleep 5; done; echo "[netcheck] no network" >&2; exit 1\n' > /usr/local/bin/netcheck.sh \
    && chmod +x /usr/local/bin/netcheck.sh

# -------- System deps (with retries) --------
# If you build the Python "xmlsec" module, you need *-dev headers & gcc.
# If not, you can drop gcc/libxml2-dev/libxmlsec1-dev/pkg-config below.
RUN /usr/local/bin/netcheck.sh \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl openssl \
       gcc libxml2-dev libxmlsec1-dev pkg-config \
       xmlsec1 libxml2 \
    && rm -rf /var/lib/apt/lists/*

# Optional: sane CA bundle location for requests/openssl
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# -------- App setup --------
WORKDIR /app

# Copy the whole project (avoids COPY failing on missing files like requirements.txt)
# Use a .dockerignore to keep the context small (see below).
COPY . /app

# -------- Python dependencies (install what you actually have) --------
# Order:
#  1) requirements.txt
#  2) all requirements*.txt
#  3) pyproject.toml / setup.(cfg|py) -> pip install .
#  4) otherwise: no deps
RUN bash -lc 'set -euo pipefail; \
  if [ -f requirements.txt ]; then \
    echo "[deps] Installing from requirements.txt"; \
    pip install -r requirements.txt; \
  elif compgen -G "requirements*.txt" > /dev/null; then \
    echo "[deps] Installing from all requirements*.txt"; \
    for f in requirements*.txt; do echo "  - $f"; pip install -r "$f"; done; \
  elif [ -f pyproject.toml ] || [ -f setup.cfg ] || [ -f setup.py ]; then \
    echo "[deps] Installing project (pyproject/setup)"; \
    pip install .; \
  else \
    echo "[deps] No dependency files found; skipping pip install."; \
  fi'

# Expose & command — keep what your app used before
# EXPOSE 8000
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

