# Base image
FROM python:3.12-slim-bookworm

# Fix Azure / Debian HTTPS issue for apt by forcing HTTP
RUN sed -i 's/https:/http:/g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libxml2-dev \
       libxmlsec1-dev \
       xmlsec1 \
       libssl-dev \
       libffi-dev \
       pkg-config \
       curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        fastapi \
        uvicorn[standard] \
        jinja2 \
        requests \
        lxml \
        python-dotenv \
        python-multipart \
        zeep \
        xmlsig \
        signxml

# Application code lives under /app
WORKDIR /app

# Copy app source (Dockerfile is in ./docker, build context is project root ".")
# so "../app" is the app directory in the project root
COPY ../app .

# Copy data directory into image (if you need the templates/configs there)
COPY ../data /data

# FastAPI will listen on 5000 inside the container
EXPOSE 5000

# Run the FastAPI app via uvicorn.
# main.py is in /app, and it defines "app = FastAPI()"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
