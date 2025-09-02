FROM python:3.12-slim

# Add Java runtime for Schematron (Saxon-HE)
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless curl unzip openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# Put Saxon-HE under /opt/saxon
RUN mkdir -p /opt/saxon
# (Codex: download the latest Saxon-HE jar; if you can’t fetch at build time, expect it mounted at runtime)
# Example (adjust version if needed):
RUN curl -L -o /opt/saxon/saxon-he.jar https://repo1.maven.org/maven2/net/sf/saxon/Saxon-HE/12.4/Saxon-HE-12.4.jar

WORKDIR /app
COPY app /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] jinja2 requests lxml python-dotenv python-multipart zeep

EXPOSE 9595
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9595"]
