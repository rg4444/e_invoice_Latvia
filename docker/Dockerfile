# Pin to Debian 12 (bookworm) to avoid trixie surprises
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1

# (Optional) show we are on bookworm at build time for future logs
RUN bash -lc '. /etc/os-release && echo "Building on: $PRETTY_NAME"'

# Ensure sources use HTTPS and are bookworm-aligned (belt-and-suspenders)
RUN set -eux; \
    sed -ri 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list; \
    sed -ri 's|http://security.debian.org|https://security.debian.org|g' /etc/apt/sources.list; \
    grep -E 'bookworm' /etc/apt/sources.list || true; \
    apt-get update; \
    # Toolchain + xmlsec stack (install in SAME layer as update)
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        pkg-config \
        ca-certificates \
        curl \
        openssl \
        xmlsec1; \
    update-ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# (Optional) place to drop a quick mirror probe (see netcheck.sh below)
COPY netcheck.sh /usr/local/bin/netcheck.sh
RUN chmod +x /usr/local/bin/netcheck.sh

WORKDIR /app

# Copy only dependency descriptors first (best caching we can do without knowing the exact file names)
# We copy a wide pattern set; COPY ignores non-matching patterns without failing.
# The final "COPY . ." (below) brings in the rest of the app.
COPY pyproject.toml poetry.lock* pdm.lock* \
     requirements.txt requirements-dev.txt requirements*.txt \
     setup.cfg setup.py \
     ./

# Install dependencies in a defensive way:
# 1) If requirements.txt exists -> use it.
# 2) Else if any other requirements*.txt exists -> install them all (common in layered reqs).
# 3) Else if pyproject.toml exists -> try PEP 621: pip install . (builds wheel & installs)
# 4) Else if setup.(cfg|py) exists -> pip install .
# 5) Else -> no dependencies.
RUN bash -lc '\
  set -euo pipefail; \
  if [ -f requirements.txt ]; then \
    echo "[deps] Installing from requirements.txt"; \
    pip install --no-cache-dir -r requirements.txt; \
  elif compgen -G "requirements*.txt" > /dev/null; then \
    echo "[deps] Installing from all requirements*.txt files"; \
    for f in requirements*.txt; do \
      echo "  - $f"; pip install --no-cache-dir -r "$f"; \
    done; \
  elif [ -f pyproject.toml ]; then \
    echo "[deps] Installing via pyproject.toml (PEP 621)"; \
    pip install --no-cache-dir .; \
  elif [ -f setup.cfg ] || [ -f setup.py ]; then \
    echo "[deps] Installing via setup.(cfg|py)"; \
    pip install --no-cache-dir .; \
  else \
    echo "[deps] No dependency descriptors found; skipping pip install."; \
  fi'

# Now copy the rest of the project
COPY . .

# (keep your CMD/entrypoint as before)
# EXPOSE 8000
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
