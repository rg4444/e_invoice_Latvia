FROM python:3.12-slim

# Java runtime + tools for downloads
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      default-jre-headless curl unzip ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/*

# KoSIT validator jar is expected to be provided via the /data volume at runtime
# (see docker-compose). The image itself does not bundle the validator jar.

# Put Saxon-HE under /opt/saxon
RUN mkdir -p /opt/saxon
RUN curl -L -o /opt/saxon/saxon-he.jar https://repo1.maven.org/maven2/net/sf/saxon/Saxon-HE/12.4/Saxon-HE-12.4.jar \
 && curl -L -o /opt/saxon/xmlresolver.jar https://repo1.maven.org/maven2/org/xmlresolver/xmlresolver/5.2.1/xmlresolver-5.2.1.jar

# App
WORKDIR /app
COPY app /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] jinja2 requests lxml python-dotenv python-multipart zeep itsdangerous

EXPOSE 9595
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9595"]
