# e-Rēķini Tester

A minimal **FastAPI** web application to **edit**, **validate**, and **send** e-invoices via **SOAP** with **WS-Security UsernameToken (digest)** and optional **mutual TLS**.

This tool is intended as a **local integration tester** for the Latvian VDAA *e-Rēķini* system.  
It helps integrators, developers, and support teams validate invoice XMLs, test SOAP connectivity, and debug certificate/TLS issues before wiring production systems.

---

## Features

- **Configuration UI** for:
  - Endpoint
  - SOAPAction
  - Username/Password
  - TLS settings
  - Client certificate paths
  - XSD entry path
  - Success indicator (substring check in response)

- **Invoice editor**:
  - Load, edit, and save XML invoices
  - Preloaded with sample invoice XML

- **Schema validation**:
  - XSD validation with `lxml`
  - Supports UBL 2.1 tree and LV profile schemas

- **SOAP client**:
  - Builds WS-Security UsernameToken (digest)
  - Optional mutual TLS with PEM keypair
  - PKCS#12 supported via manual conversion to PEM/KEY
- **WSDL browser**:
  - Fetches available SOAP operations after authentication
  - Clicking an operation fills SOAPAction and seeds the invoice body

- **Debug panel**:
  - Shows raw SOAP request & response
  - HTTP headers and status
  - TLS info and timings
  - Saves last request/response to `/data/logs/`

- **Persistence**:
  - Config and logs persisted under `/data` for easy Docker volume mounting

---

## Repository Layout

```
app/                # FastAPI application
  main.py
  soap_client.py
  validation.py
  storage.py
  templates/
  static/
data/
  samples/          # sample invoice XMLs (e.g. einvoice_nePVN2.xml)
  xsd/              # place UBL XSD tree here (entry: UBL-Invoice-2.1.xsd)
  certs/            # client certificates (PEM/KEY or PKCS#12 converted)
  trust/            # custom CA bundle (optional)
  logs/             # saved request/response logs
docker/
  Dockerfile
docker-compose.yml
.env.example
README.md
```

---

## Running with Docker

1. Copy the environment file:

   ```bash
   cp .env.example .env
   ```

2. Build and run the container:

   The compose file uses the project root as the build context and points to `docker/Dockerfile`:

   ```yaml
   build:
     context: .
     dockerfile: docker/Dockerfile
   ```

   Run the container:

   ```bash
   docker compose up --build
   ```

3. Open the application:

   ```
   http://localhost:9595
   ```

---

## Running Bare Metal

1. Install dependencies:

   ```bash
   pip install fastapi uvicorn jinja2 requests lxml python-dotenv python-multipart
   ```

2. Export environment variables:

   ```bash
   export DEFAULT_INVOICE=/path/to/data/samples/einvoice_nePVN2.xml
   export DEFAULT_SCHEMA=/path/to/data/xsd/UBL-Invoice-2.1.xsd
   ```

3. Start the app:

   ```bash
   uvicorn app.main:app --reload --port 9595
   ```

---

## Certificates

- **Mutual TLS (recommended)**:  
  Place `client.pem` and `client.key` under `data/certs/` and reference their paths in the Config screen.

- **PKCS#12 (P12/PFX)**:  
  Convert to PEM/KEY with OpenSSL before use:

  ```bash
  openssl pkcs12 -in client.p12 -clcerts -nokeys -out client.pem
  openssl pkcs12 -in client.p12 -nocerts -nodes -out client.key
  ```

- **Custom CA bundles**:
  If the endpoint uses a private CA, place it under `data/trust/ca.pem` and set the path in Config.

## Generate Certificate (Key + CSR)

Use the **Generate Certificate** tab to create your private key and certificate signing request:

1. Open **Generate Certificate** (first tab).
2. Fill Subject (DN) fields (C, ST, L, O, OU, CN, email).
3. (Optional) Enter a key passphrase.  \
   - If you use a passphrase, the key will be encrypted (AES-256) and you must provide this passphrase later in Config (for the TLS probe and sending).
4. Click **Generate Key & CSR**.

The app writes files to `/data/certs/`:
- `client.key` (or `{base}.key`) — your private key, **keep it safe**.
- `client.csr` (or `{base}.csr`) — send this to **VDAA** for issuance.

**After issuance**
- VDAA returns `client.cer` (your cert) and optionally `chain.p7b` (CA chain).
- Go to **Config → Find & Convert**, choose `/data/certs` and click **Find and convert**.  \
  This will produce:
  - `client.pem`, `chain.pem`, `client_full.pem` (cert + chain)
- Ensure **Config** paths:
  - Client cert (PEM): `/data/certs/client_full.pem`
  - Client key (PEM):  `/data/certs/client.key`
  - CA bundle:         `/data/certs/chain.pem`
- Click **Verify chain & TLS probe** to confirm connectivity.

> Requirements (per VDAA/VISS guidance):
> - RSA **2048-bit** key
> - SHA-256 for CSR
> - Keep the **private key** private. Do not email/upload it.

## Find & Convert (OpenSSL)

The Config screen now offers a **Find & Convert** panel. It scans a directory under `/data` for a private key (`*.key`), client certificate (`*.cer`/`*.crt`/`*.pem`), and chain file (`*.p7b`/`*.p7c`). The tool assembles `client.pem`, `chain.pem`, `client_full.pem`, and optionally `client.p12`, then applies these paths to the configuration.

**Security notes**

- Reads and writes private keys inside `/data`; keep this directory local and protected.
- Key passwords are untouched. If your key is encrypted, OpenSSL may prompt for its passphrase.
- The TLS probe uses `curl -v` and prints the handshake log. Redact sensitive data before sharing.

**Typical flow**

1. Place raw files in `/data/certs` (`client.key`, `client.cer`, `chain.p7b`).
2. Open **Config → Find & Convert**.
3. Adjust directories if needed and run **Find and convert** (enable PKCS#12 to create `client.p12`).
4. Run **Verify chain & TLS probe** to check the assembled certificates.

---

## WSDL Browser

After entering the endpoint and authentication details, press **Load WSDL** on the Config tab to retrieve the service description.
The app lists available operations; clicking one stores the corresponding `SOAPAction` and seeds a minimal request body. If the
WSDL cannot be fetched or contains no operations, an error message is shown.

---

## Usage Workflow

1. **Open Config tab**
   - Enter endpoint, credentials, and cert paths
   - Use **Load WSDL** to list available operations; selecting one fills `SOAPAction` and seeds a minimal request body
   - Save configuration

2. **Load Invoice**  
   - Load sample invoice from `/data/samples/` or paste your own XML  
   - Edit and save as needed

3. **Validate Schema**  
   - Run XSD validation against UBL 2.1 tree  
   - Resolve all errors before sending

4. **Send Invoice**  
   - Build SOAP envelope with WS-Security UsernameToken  
   - Send via HTTPS with optional mutual TLS  
   - Inspect raw request/response in Debug panel

5. **Check Logs**  
   - Last request/response stored in `/data/logs/last-request.xml` and `/data/logs/last-response.xml`

---

## Notes

- Ensure the **UBL XSD tree** is placed under `data/xsd/` so relative imports resolve.  
- The app checks “success” by:
  - HTTP status = `200` **and**  
  - Response contains the configured *Success indicator* substring (default: `"Valid"`).  
- This is a **test tool only**, not for production invoice dispatch.
