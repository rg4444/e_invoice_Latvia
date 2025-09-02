import time
import base64
import os
import uuid
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


def _headers_for(cfg: dict) -> dict:
    v = (cfg.get("soap_version") or "1.2").strip()
    action = (cfg.get("soap_action") or "").strip()
    if v == "1.1":
        h = {"Content-Type": "text/xml; charset=utf-8"}
        if action:
            h["SOAPAction"] = action
        return h
    else:
        ct = 'application/soap+xml; charset=utf-8'
        if action:
            ct = f'{ct}; action="{action}"'
        return {"Content-Type": ct}


def wsa_header(cfg: dict) -> str:
    if not cfg.get("use_ws_addressing"):
        return ""
    to = cfg.get("endpoint", "")
    action = cfg.get("soap_action", "")
    mid = f"urn:uuid:{uuid.uuid4()}"
    return f"""
<wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">{action}</wsa:Action>
<wsa:To xmlns:wsa="http://www.w3.org/2005/08/addressing">{to}</wsa:To>
<wsa:MessageID xmlns:wsa="http://www.w3.org/2005/08/addressing">{mid}</wsa:MessageID>
""".strip()


def wsse_x509_header(cert_pem_path: str) -> str:
    if not cert_pem_path or not os.path.exists(cert_pem_path):
        return ""
    pem = open(cert_pem_path, "rb").read()
    b64 = base64.b64encode(b"".join([l for l in pem.splitlines() if b"-----" not in l])).decode()
    return f"""
<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <wsse:BinarySecurityToken
      EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
      ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
      wsse:Id="X509Token">
    {b64}
  </wsse:BinarySecurityToken>
</wsse:Security>
""".strip()


def build_soap_envelope(cfg: dict, body_xml: str) -> str:
    wsse = ""
    mode = cfg.get("wsse_mode", "username")
    if mode == "username":
        wsse = wsse_username_token(cfg.get("username", ""), cfg.get("password", ""), use_digest=True)
    elif mode == "x509":
        wsse = wsse_x509_header(cfg.get("client_cert", ""))

    wsa = wsa_header(cfg)

    v = (cfg.get("soap_version") or "1.2").strip()
    ns = "http://schemas.xmlsoap.org/soap/envelope/" if v == "1.1" else "http://www.w3.org/2003/05/soap-envelope"

    return f"""<soap:Envelope xmlns:soap="{ns}">
  <soap:Header>
    {wsa}
    {wsse}
  </soap:Header>
  <soap:Body>
    {body_xml}
  </soap:Body>
</soap:Envelope>"""


def send_invoice(invoice_xml: str, cfg: dict):
    soap_xml = build_soap_envelope(cfg, invoice_xml)

    headers = _headers_for(cfg)

    verify = cfg.get("verify_tls", True)
    if cfg.get("ca_bundle"):
        verify = cfg["ca_bundle"]

    cert = None
    if cfg.get("client_cert") and cfg.get("client_key"):
        cert = (cfg["client_cert"], cfg["client_key"])
    elif cfg.get("client_p12"):
        pass

    t0 = time.time()
    resp = requests.post(
        cfg["endpoint"],
        headers=headers,
        data=soap_xml.encode("utf-8"),
        verify=verify,
        cert=cert,
        timeout=45,
    )
    elapsed_ms = int((time.time() - t0) * 1000)

    debug = {
        "request": {
            "url": cfg["endpoint"],
            "headers": headers,
            "body": soap_xml,
        },
        "response": {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
        },
        "timing_ms": elapsed_ms,
    }

    ok = (resp.status_code == 200) and (cfg.get("success_indicator", "") in resp.text)
    return ok, debug

