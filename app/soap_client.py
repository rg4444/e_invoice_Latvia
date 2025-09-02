import time
import base64
import os
from datetime import datetime, timezone
from hashlib import sha1
import secrets
import requests


def wsse_username_token(username: str, password: str, use_digest=True):
    created = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce).decode()
    if use_digest:
        # PasswordDigest = Base64 ( SHA1 ( nonce + created + password ) )
        digest = sha1(nonce + created.encode() + password.encode()).digest()
        pwd = base64.b64encode(digest).decode()
        ptype = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
    else:
        pwd = password
        ptype = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"

    header = f"""
<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <wsse:UsernameToken>
    <wsse:Username>{username}</wsse:Username>
    <wsse:Password Type="{ptype}">{pwd}</wsse:Password>
    <wsse:Nonce>{nonce_b64}</wsse:Nonce>
    <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</wsu:Created>
  </wsse:UsernameToken>
</wsse:Security>""".strip()
    return header


def build_soap_envelope(wsse_header_xml: str, invoice_xml: str):
    return f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    {wsse_header_xml}
  </soapenv:Header>
  <soapenv:Body>
    {invoice_xml}
  </soapenv:Body>
</soapenv:Envelope>"""


def send_invoice(invoice_xml: str, cfg: dict):
    wsse = wsse_username_token(cfg.get("username",""), cfg.get("password",""), use_digest=True)
    soap_xml = build_soap_envelope(wsse, invoice_xml)

    headers = {"Content-Type": "text/xml; charset=utf-8"}
    if cfg.get("soap_action"):
        headers["SOAPAction"] = cfg["soap_action"]

    # requests session with TLS settings
    verify = cfg.get("verify_tls", True)
    if cfg.get("ca_bundle"):
        verify = cfg["ca_bundle"]

    cert = None
    if cfg.get("client_cert") and cfg.get("client_key"):
        cert = (cfg["client_cert"], cfg["client_key"])
    elif cfg.get("client_p12"):
        # Prefer native client pem/key pairs; for P12 you might pre-extract via openssl.
        # For MVP, document: convert P12 -> pem/key (see README). Keep field for future automation.
        pass

    t0 = time.time()
    resp = requests.post(
        cfg["endpoint"],
        headers=headers,
        data=soap_xml.encode("utf-8"),
        verify=verify,
        cert=cert,
        timeout=45
    )
    elapsed_ms = int((time.time() - t0) * 1000)

    debug = {
        "request": {
            "url": cfg["endpoint"],
            "headers": headers,
            "body": soap_xml
        },
        "response": {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text
        },
        "timing_ms": elapsed_ms
    }

    # success check (simple substring match)
    ok = (resp.status_code == 200) and (cfg.get("success_indicator","") in resp.text)
    return ok, debug
