import os
import time
import base64
import uuid
from datetime import datetime
from hashlib import sha1
import secrets
from typing import Any, Dict

from lxml import etree
import requests
from requests.exceptions import SSLError as RequestsSSLError
from wsdl_utils import build_session_with_sslcontext


def wsse_username_token(username: str, password: str, use_digest=True):
    username = (username or "").strip()
    password = (password or "").strip()
    if not username or not password:
        return ""

    created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    nonce = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce).decode()
    if use_digest:
        # PasswordDigest = Base64 ( SHA1 ( nonce + created + password ) )
        digest = sha1(nonce + created.encode("ascii") + password.encode("utf-8")).digest()
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
    mode = cfg.get("wsse_mode", "username")
    wsse = ""
    if mode == "username":
        wsse = wsse_username_token(cfg.get("username", ""), cfg.get("password", ""), use_digest=True)
    elif mode == "x509":
        wsse = wsse_x509_header(cfg.get("client_cert", ""))

    wsa = wsa_header(cfg)

    v = (cfg.get("soap_version") or "1.2").strip()
    ns = "http://schemas.xmlsoap.org/soap/envelope/" if v == "1.1" else "http://www.w3.org/2003/05/soap-envelope"

    header_parts = [part for part in (wsa, wsse) if part]
    header_xml = "\n    ".join(header_parts)
    if header_xml:
        header_xml = f"\n    {header_xml}\n  "

    return f"""<soap:Envelope xmlns:soap="{ns}">
  <soap:Header>{header_xml}</soap:Header>
  <soap:Body>
    {body_xml}
  </soap:Body>
</soap:Envelope>"""


def send_invoice(invoice_xml: str, cfg: dict):
    soap_xml = build_soap_envelope(cfg, invoice_xml)

    result = send_raw_envelope(cfg, soap_xml)

    debug = {
        "request": {
            "url": cfg.get("endpoint"),
            "headers": _headers_for(cfg),
            "body": soap_xml,
        },
        "response": {
            "status": result.get("http_status"),
            "headers": {},
            "body": result.get("response_xml"),
        },
        "timing_ms": result.get("took_ms"),
        "tls_debug": result.get("tls_debug"),
    }

    ok = result.get("ok", False) and (
        (cfg.get("success_indicator", "") in (result.get("response_xml") or ""))
        if cfg.get("success_indicator")
        else True
    )
    return ok, debug


def send_raw_envelope(cfg: dict, envelope_xml: str) -> dict:
    """
    Send a pre-built SOAP envelope using mutual TLS if configured.

    TLS strategy:
    - By default: use system CA store (verify=True).
    - If ca_bundle is set AND not obviously wrong: use as verify path.
    - If verification fails with 'self-signed certificate in certificate chain'
      and a custom CA file was used, retry once with system CAs.
    """

    headers = _headers_for(cfg)

    endpoint = (cfg.get("endpoint") or "").strip()
    if not endpoint:
        raise ValueError("Endpoint is not configured")

    client_cert = (cfg.get("client_cert") or "").strip()
    client_key = (cfg.get("client_key") or "").strip()
    ca_bundle = (cfg.get("ca_bundle") or "").strip()
    verify_tls = bool(cfg.get("verify_tls", True))

    # 1) Start with system CAs or no-verify
    verify: bool | str = True if verify_tls else False

    # 2) If a CA bundle is configured AND we are verifying, tentatively use it
    if verify_tls and ca_bundle:
        verify = ca_bundle

    def _looks_like_client_material(path: str) -> bool:
        if not path or not os.path.exists(path):
            return False
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
        # If file contains a PRIVATE KEY, it's not a CA bundle.
        return "PRIVATE KEY" in txt

    # 3) Guard against misconfigured ca_bundle pointing to client key/cert
    if isinstance(verify, str) and _looks_like_client_material(verify):
        # Fall back to system CAs instead of using an invalid CA bundle
        verify = True

    cert = None
    if client_cert and client_key:
        cert = (client_cert, client_key)

    t0 = time.time()
    try:
        resp = requests.post(
            endpoint,
            headers=headers,
            data=envelope_xml.encode("utf-8"),
            verify=verify,
            cert=cert,
            timeout=45,
        )
    except RequestsSSLError as e:
        msg = str(e)
        # 4) If we used a custom CA bundle and got a self-signed-chain error,
        #    retry once with system CA store (verify=True).
        if isinstance(verify, str) and "self-signed certificate in certificate chain" in msg:
            try:
                resp = requests.post(
                    endpoint,
                    headers=headers,
                    data=envelope_xml.encode("utf-8"),
                    verify=True,
                    cert=cert,
                    timeout=45,
                )
            except Exception:
                # If retry also fails, re-raise original
                raise
        else:
            # Other TLS errors propagate
            raise

    elapsed_ms = int((time.time() - t0) * 1000)

    return {
        "ok": resp.status_code == 200,
        "http_status": resp.status_code,
        "took_ms": elapsed_ms,
        "request_xml": envelope_xml,
        "response_xml": resp.text,
        "tls_debug": {
            "endpoint": endpoint,
            "verify_effective": verify if isinstance(verify, bool) else str(verify),
            "client_cert": client_cert,
            "client_key_set": bool(client_key),
            "ca_bundle": ca_bundle,
        },
    }


def send_get_initial_addressee_request(
    endpoint: str,
    envelope_xml: str,
    client_cert: str,
    client_key: str,
    key_pass: str = "",
) -> Dict[str, Any]:
    """
    Send a prepared SOAP 1.2 envelope to the VDAA UnifiedService.svc endpoint
    for GetInitialAddresseeRecordList.

    :param endpoint: Full HTTPS URL of UnifiedService.svc
    :param envelope_xml: Complete signed SOAP envelope (UTF-8 string)
    :param client_cert: Path to client certificate (PEM) file
    :param client_key: Path to client private key (PEM) file
    :param key_pass: Optional private key password
    :return: dict with keys: status (int), headers (dict), body (str), url (str)
    """
    try:
        etree.fromstring(envelope_xml.encode("utf-8"))
    except etree.XMLSyntaxError as exc:
        raise ValueError("Envelope XML is not well-formed") from exc

    cfg_endpoint = endpoint
    session = build_session_with_sslcontext(
        endpoint=cfg_endpoint,
        client_cert=client_cert,
        client_key=client_key,
        key_pass=key_pass,
    )

    headers = {
        "Content-Type": (
            'application/soap+xml; charset=utf-8; '
            'action="http://vraa.gov.lv/div/uui/2011/11/'
            'UnifiedServiceInterface/GetInitialAddresseeRecordList"'
        )
    }

    resp = session.post(
        cfg_endpoint,
        data=envelope_xml.encode("utf-8"),
        headers=headers,
    )

    return {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "body": resp.text,
        "url": resp.url,
    }

