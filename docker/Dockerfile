# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Fix Azure / Debian HTTPS issue for apt and install native deps
RUN sed -i 's/https:/http:/g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libxml2-dev \
       libxmlsec1-dev \
       xmlsec1 \
       pkg-config \
       libxml2 \
       libxmlsec1 \
       libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Python packages
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
       fastapi \
       uvicorn[standard] \
       jinja2 \
       requests \
       lxml \
       python-dotenv \
       python-multipart \
       "zeep[xmlsec,wssdl]" \
       xmlsig \
       signxml \
       xmlsec \
       itsdangerous

# App code lives in /app
WORKDIR /app

# Dockerfile is in ./docker, build context is ".", so "../app" is the project app dir
COPY ../app .

# Data directory (certs, configs, etc.)
COPY ../data /data

EXPOSE 5000

# Run FastAPI app via Uvicorn.
# /app/main.py defines: app = FastAPI()
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
