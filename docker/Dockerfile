# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Fix Azure 2025 outbound block + install native deps for lxml / signxml / xmlsec1
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

# Python packages – fixed typo lxml (was l1xml!)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        flask \
        lxml \
        zeep[wssdl] \
        requests \
        xmlsig \
        signxml \
        python-dotenv

# App code
WORKDIR /app
COPY ../app .

# Default data (optional)
COPY ../data /data

EXPOSE 5000

# Force Flask to listen on all interfaces
CMD ["python", "-m", "app.main", "--host=0.0.0.0", "--port=5000"]
