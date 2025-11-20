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

# If you have a lockfile, prefer it. Otherwise keep requirements.txt.
# COPY requirements.lock ./
# RUN pip install --no-cache-dir -r requirements.lock

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Default command (adjust to your app)
# Example for FastAPI/uvicorn:
# EXPOSE 8000
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

