FROM python:3.12-slim

# Java runtime + tools for downloads
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      default-jre-headless curl unzip ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/*

# KoSIT validator jar will live here
ENV KOSIT_HOME=/opt/kosit
RUN mkdir -p $KOSIT_HOME/bin $KOSIT_HOME/conf

# Optional: download a recent validator jar at build time.
# (You can also mount it via docker-compose volume.)
ARG KOSIT_VER=1.5.2
RUN curl -L -o $KOSIT_HOME/bin/validator-${KOSIT_VER}-standalone.jar \
    https://github.com/itplr-kosit/validator/releases/download/v${KOSIT_VER}/validator-${KOSIT_VER}-standalone.jar

# Put Saxon-HE under /opt/saxon
RUN mkdir -p /opt/saxon
RUN curl -L -o /opt/saxon/saxon-he.jar https://repo1.maven.org/maven2/net/sf/saxon/Saxon-HE/12.4/Saxon-HE-12.4.jar

# App
WORKDIR /app
COPY app /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] jinja2 requests lxml python-dotenv python-multipart zeep

EXPOSE 9595
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9595"]
