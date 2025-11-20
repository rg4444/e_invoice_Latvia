# docker/Dockerfile
FROM python:3.12-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# APT is already HTTPS on bookworm images; add a few robustness knobs
RUN set -eux; \
    printf '%s\n' \
      'Acquire::Retries "5";' \
      'Acquire::http::Timeout "30";' \
      'Acquire::https::Timeout "30";' \
      'Acquire::ForceIPv4 "true";' \
    > /etc/apt/apt.conf.d/99robust; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc \
      libxml2 \
      libxml2-dev \
      xmlsec1 \
      libxmlsec1-dev \
      pkg-config \
      ca-certificates \
      curl \
      openssl; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bring the project in (expects you run compose from repo root)
COPY . /app

# Install Python deps if files exist (handles both pip and pyproject flows)
RUN bash -lc 'set -euo pipefail; \
  if [ -f requirements.txt ]; then \
    echo "[deps] requirements.txt"; pip install -r requirements.txt; \
  elif compgen -G "requirements*.txt" > /dev/null; then \
    echo "[deps] requirements*.txt"; for f in requirements*.txt; do pip install -r "$f"; done; \
  elif [ -f pyproject.toml ] || [ -f setup.cfg ] || [ -f setup.py ]; then \
    echo "[deps] pyproject/setup"; pip install .; \
  else \
    echo "[deps] none found; skipping"; \
  fi'

# EXPOSE 8000
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
