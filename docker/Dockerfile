FROM python:3.12-slim
WORKDIR /app
# OS tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
COPY app /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] jinja2 requests lxml python-dotenv
EXPOSE 9595
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9595"]
