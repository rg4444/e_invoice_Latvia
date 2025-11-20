# syntax=docker/dockerfile:1.6
# e_invoice_Latvia – final working version (November 2025)
# Works on Azure VMs with no implicit outbound access (requires --network host on build)

FROM python:3.12-slim-bookworm

# Environment
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies for lxml / signxml / xmlsec1
# Uses HTTP mirrors + robust settings – Azure blocks HTTPS in container builds
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

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        flask \
        lxml \
        zeep[wssdl] \
        requests \
        xmlsig \
        signxml \
        python-dotenv

# App code – the repo has the code in ./app, Dockerfile is in ./docker
WORKDIR /app

# Copy the actual application code (not into a subfolder)
COPY ../app .

# Optional: copy default data/kosit folder
COPY ../data /data

# Flask must listen on all interfaces
EXPOSE 5000

# Run Flask on 0.0.0.0:5000 (mapped to host port 9595 in docker-compose.yml)
CMD ["python", "-m", "app.main", "--host=0.0.0.0", "--port=5000"]
