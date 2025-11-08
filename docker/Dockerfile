FROM python:3.12-slim

WORKDIR /app

# System deps for xmlsec
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxmlsec1-dev \
    pkg-config \
    ca-certificates \
    curl \
    openssl \
  && rm -rf /var/lib/apt/lists/*

COPY app /app

RUN pip install --no-cache-dir \
    fastapi uvicorn[standard] jinja2 requests lxml python-dotenv \
    zeep xmlsec python-multipart itsdangerous

EXPOSE 9595
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9595"]
