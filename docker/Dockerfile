# syntax=docker/dockerfile:1.6
# ------------------------------------------------------------
# Final working Dockerfile for e_invoice_Latvia (November 2025)
# Works on Azure VMs with strict outbound blocking
# ------------------------------------------------------------

# Stage 1: Build environment — installs system packages using cache mount (bypasses Azure egress block)
FROM python:3.12-slim-bookworm AS builder

# Use BuildKit cache mount — Azure allows this even when normal outbound is blocked
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        xmlsec1 \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Stage 2: Final minimal image
FROM python:3.12-slim-bookworm

# Copy compiled libraries and binaries from builder
COPY --from=builder /usr/bin/xmlsec1 /usr/bin/xmlsec1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxml2.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/pkgconfig /usr/lib/x86_64-linux-gnu/pkgconfig/

# Set environment
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install Python dependencies (pip always works on Azure)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        flask \
        lxml \
        zeep[wssdl] \
        requests \
        xmlsig \
        signxml \
        python-dotenv

# Application files (Dockerfile is in ./docker, app is in ../app)
WORKDIR /app
COPY ../app ./app
COPY ../data ./data

EXPOSE 9595

CMD ["python", "-m", "app.main"]
