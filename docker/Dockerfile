# docker/Dockerfile
FROM python:3.12-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- Make APT robust and switch mirrors to HTTPS (deb822 file on bookworm) ---
RUN set -eux; \
    # Robustness knobs
    printf '%s\n' \
      'Acquire::Retries "5";' \
      'Acquire::http::Timeout "30";' \
      'Acquire::https::Timeout "30";' \
      'Acquire::ForceIPv4 "true";' \
    > /etc/apt/apt.conf.d/99robust; \
    # On Debian bookworm slim, official sources live in deb822 file below
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -ri 's#http://deb\.debian\.org#https://deb.debian.org#g' /etc/apt/sources.list.d/debian.sources; \
      sed -ri 's#http://security\.debian\.org#https://security.debian.org#g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
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

# Copy the whole project (so we don’t fail when requirements*.txt are absent)
COPY . /app

# Install Python deps (supports both pip requirements and pyproject/setup flows)
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
