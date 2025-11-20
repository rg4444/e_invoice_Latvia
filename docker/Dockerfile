# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system deps for lxml/signxml/xmlsec1 – uses HTTP (Azure blocks HTTPS in builds)
RUN sed -i 's/https:/http:/g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        xmlsec1 \
        pkg-config \
        libxml2 \
        libxmlsec1 \
        libxmlsec1-openssl && \
    rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir flask l1xml zeep[wssdl] requests xmlsig signxml python-dotenv

# Copy code (Dockerfile in ./docker, code in ../app)
WORKDIR /app
COPY ../app .

# Data volume
COPY ../data /data

# Expose Flask default port
EXPOSE 5000

# Force host 0.0.0.0 and port 5000 so Docker can map it
CMD ["python", "-m", "app.main", "--host", "0.0.0.0", "--port", "5000"]
