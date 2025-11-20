# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm

# Avoid stuck builds due to interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- Fix APT for Azure VMs that block container HTTPS outbound after Sept 2025 ---
# Switch mirrors to plain HTTP (Azure allows it) + make APT very robust
RUN set -eux; \
    printf '%s\n' \
        'Acquire::Retries "10";' \
        'Acquire::http::Timeout "60";' \
        'Acquire::https::Timeout "60";' \
        'Acquire::ForceIPv4 "true";' \
        > /etc/apt/apt.conf.d/99robust; \
    \
    # Debian bookworm slim uses deb822 format → replace https → http \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|https://deb.debian.org|http://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
        sed -i 's|https://security.debian.org|http://security.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        xmlsec1 \
        pkg-config \
        ca-certificates \
        curl \
        openssl; \
    rm -rf /var/lib/apt/lists/*

# --- Application setup ---
WORKDIR /app

# Copy only requirements first (leverage Docker layer caching)
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Expose port (adjust if your app uses another)
EXPOSE 8000

# Default command (change if you use something else, e.g. gunicorn, uvicorn, etc.)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
