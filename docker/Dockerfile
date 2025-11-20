# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Azure VMs after September 2025 block HTTPS outbound from containers → force HTTP mirrors
RUN set -eux; \
    printf '%s\n' \
        'Acquire::Retries "10";' \
        'Acquire::http::Timeout "60";' \
        'Acquire::https::Timeout "60";' \
        'Acquire::ForceIPv4 "true";' \
        > /etc/apt/apt.conf.d/99robust; \
    \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|https://deb.debian.org|http://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
        sed -i 's|https://security.debian.org|http://security.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        xmlsec1 \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Install exact Python packages your app uses (no requirements.txt exists)
RUN pip install --no-cache-dir \
        flask \
        lxml \
        zeep[wssdl] \
        requests \
        xmlsig \
        signxml \
        python-dotenv

# App lives in ./app in the repo
WORKDIR /app

# Copy from correct relative path (Dockerfile is inside ./docker folder)
COPY ../app ./app
COPY ../data ./data

# Port changed to 9595 in your code
EXPOSE 9595

# Run the app (your entrypoint)
CMD ["python", "-m", "app.main"]
