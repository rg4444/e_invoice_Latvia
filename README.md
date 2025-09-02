# e-Rēķini Tester

A minimal FastAPI web application to edit, validate, and send e-invoices via SOAP with WS-Security UsernameToken support.

## Features

- Configuration UI for endpoint, SOAPAction, credentials, TLS settings and paths.
- Invoice editor to load, edit, and save XML invoices.
- XSD validation using `lxml`.
- SOAP client with WS-Security UsernameToken digest and optional mutual TLS.
- Debug panel showing request/response data and timings.
- Config and logs persisted under `/data` for easy volume mounting.

## Repository layout

```
app/                # FastAPI application
  main.py
  soap_client.py
  validation.py
  storage.py
  templates/
  static/
data/
  samples/         # sample invoice XMLs
  xsd/             # place UBL XSD tree here
  certs/           # client certificates
  trust/           # custom CA bundle
  logs/            # saved request/response logs
 docker/
  Dockerfile
 docker-compose.yml
 .env.example
```

## Running with Docker

```bash
cp .env.example .env
docker compose up --build
# open http://localhost:9595
```

## Bare metal

```bash
export DEFAULT_INVOICE=/path/to/data/samples/einvoice_nePVN2.xml
export DEFAULT_SCHEMA=/path/to/data/xsd/UBL-Invoice-2.1.xsd
uvicorn app.main:app --reload --port 9595
```

Ensure the UBL XSD tree is placed under `data/xsd/` so relative imports resolve. If using PKCS#12 certificates, convert them to PEM/KEY with OpenSSL before use.
