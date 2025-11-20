FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# -------- Build-time mirror overrides (optional) --------
# You can override these via: --build-arg DEBIAN_MIRROR=https://mirror.example.com/debian
ARG DEBIAN_MIRROR=https://deb.debian.org/debian
ARG SECURITY_MIRROR=https://security.debian.org/debian-security

# -------- Network checker (HTTPS) --------
RUN printf '%s\n' '#!/bin/sh' \
  'tries=0; while [ $tries -lt 18 ]; do' \
  '  for host in deb.debian.org security.debian.org; do' \
  '    if command -v curl >/dev/null 2>&1; then' \
  '      curl -fsI https://$host >/dev/null 2>&1 && ok=1 || ok=0' \
  '    else' \
  '      (echo > /dev/tcp/$host/443) >/dev/null 2>&1 && ok=1 || ok=0' \
  '    fi' \
  '    [ "$ok" = "1" ] || { echo "[netcheck] $host not reachable over 443"; ok=0; break; }' \
  '  done' \
  '  [ "$ok" = "1" ] && exit 0' \
  '  tries=$((tries+1)); echo "[netcheck] waiting for network... ($tries)"; sleep 5' \
  'done; echo "[netcheck] no network (HTTPS unreachable)" >&2; exit 1' \
  > /usr/local/bin/netcheck.sh && chmod +x /usr/local/bin/netcheck.sh

# -------- APT robustness & HTTPS sources --------
# - Force HTTPS mirrors
# - Add retries/timeouts
# - Prefer IPv4 (often helps behind strict firewalls/NAT)
RUN /usr/local/bin/netcheck.sh && \
    sed -i 's|http://deb.debian.org/debian|'"$DEBIAN_MIRROR"'|g' /etc/apt/sources.list && \
    sed -i 's|http://security.debian.org/debian-security|'"$SECURITY_MIRROR"'|g' /etc/apt/sources.list && \
    printf '%s\n' 'Acquire::Retries "5";' \
                  'Acquire::http::Timeout "30";' \
                  'Acquire::https::Timeout "30";' \
                  'Acquire::http::Pipeline-Depth "0";' \
                  'Acquire::ForceIPv4 "true";' \
                  > /etc/apt/apt.conf.d/99robust && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl openssl && \
    rm -rf /var/lib/apt/lists/*

# -------- System deps for xmlsec (adjust if not needed) --------
RUN /usr/local/bin/netcheck.sh && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      gcc libxml2-dev libxmlsec1-dev pkg-config \
      xmlsec1 libxml2 \
    && rm -rf /var/lib/apt/lists/*

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app

# Copy the whole project; control context via .dockerignore
COPY . /app

# -------- Python deps: install whatever exists --------
RUN bash -lc 'set -euo pipefail; \
  if [ -f requirements.txt ]; then \
    echo "[deps] Installing from requirements.txt"; pip install -r requirements.txt; \
  elif compgen -G "requirements*.txt" > /dev/null; then \
    echo "[deps] Installing from all requirements*.txt"; \
    for f in requirements*.txt; do echo "  - $f"; pip install -r "$f"; done; \
  elif [ -f pyproject.toml ] || [ -f setup.cfg ] || [ -f setup.py ]; then \
    echo "[deps] Installing project (pyproject/setup)"; pip install .; \
  else \
    echo "[deps] No dependency files found; skipping pip install."; \
  fi'

# EXPOSE 8000
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
