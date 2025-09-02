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

- **Debug panel**:
  - Shows raw SOAP request & response
  - HTTP headers and status
  - TLS info and timings
  - Saves last request/response to `/data/logs/`

- **Persistence**:
  - Config and logs persisted under `/data` for easy Docker volume mounting

---

## Repository Layout

