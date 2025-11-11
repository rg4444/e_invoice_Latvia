from __future__ import annotations

import os
import re
import time
import traceback
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from lxml import etree
from requests import Session
from zeep import Client, Settings
from zeep.exceptions import Fault, TransportError
from zeep.helpers import serialize_object
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.wsse import utils as wsse_utils
from zeep.wsse import signature as zeep_signature
from zeep.wsse.signature import Signature

try:  # pragma: no cover - exercised in integration environments
    import xmlsec
except ImportError:  # pragma: no cover - xmlsec is optional during testing
    xmlsec = None  # type: ignore[assignment]

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from storage import load_config


SOAP_ENV_NAMESPACES = (
    "http://schemas.xmlsoap.org/soap/envelope/",
    "http://www.w3.org/2003/05/soap-envelope",
)

WSSE_NAMESPACE = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
)

DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"

WSA_NAMESPACE = "http://www.w3.org/2005/08/addressing"


def _find_security_header(
    envelope: etree._Element | etree._ElementTree,
) -> Optional[etree._Element]:
    """Return the wsse:Security header element if present."""

    if envelope is None:
        return None

    if isinstance(envelope, etree._ElementTree):  # pragma: no cover - defensive
        envelope = envelope.getroot()
        if envelope is None:
            return None

    for ns in SOAP_ENV_NAMESPACES:
        header = envelope.find(f"{{{ns}}}Header")
        if header is None:
            continue
        security = header.find(f"{{{WSSE_NAMESPACE}}}Security")
        if security is not None:
            return security

    return None


class LenientSignature(Signature):
    """Signature handler that skips verification when the response is unsigned."""

    def verify(self, envelope: etree._Element) -> None:  # type: ignore[override]
        security = _find_security_header(envelope)
        if security is None:
            return

        if security.find(f"{{{DS_NAMESPACE}}}Signature") is None:
            return

        super().verify(envelope)


class TimestampedSignature(LenientSignature):
    """Signature handler that injects a wsu:Timestamp before signing."""

    def __init__(
        self,
        key_file: str,
        certfile: str,
        *,
        timestamp_ttl_seconds: int = 300,
    ) -> None:
        signature_method = None
        digest_method = None

        if xmlsec is not None:
            signature_method = getattr(xmlsec.Transform, "RSA_SHA256", None)
            digest_method = getattr(xmlsec.Transform, "SHA256", None)

        super().__init__(
            key_file,
            certfile,
            signature_method=signature_method,
            digest_method=digest_method,
        )
        self.timestamp_ttl_seconds = max(int(timestamp_ttl_seconds), 1)
        self._last_timestamp_window: dict[str, str] | None = None
        self._cert_b64 = self._extract_certificate_b64(certfile, key_file)

    def _build_timestamp(self) -> etree._Element:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=self.timestamp_ttl_seconds)

        created_text = wsse_utils.get_timestamp(timestamp=now, zulu_timestamp=True)
        expires_text = wsse_utils.get_timestamp(timestamp=expires, zulu_timestamp=True)

        timestamp = wsse_utils.WSU.Timestamp()
        timestamp.set(wsse_utils.ID_ATTR, wsse_utils.get_unique_id())
        timestamp.append(wsse_utils.WSU.Created(created_text))
        timestamp.append(wsse_utils.WSU.Expires(expires_text))

        self._last_timestamp_window = {
            "created": created_text,
            "expires": expires_text,
        }

        return timestamp

    def apply(self, envelope, headers):  # type: ignore[override]
        security = wsse_utils.get_security_header(envelope)
        timestamp_tag = f"{{{wsse_utils.ns.WSU}}}Timestamp"

        for existing in list(security):
            if existing.tag == timestamp_tag:
                security.remove(existing)

        security.insert(0, self._build_timestamp())

        self._apply_signature(envelope)
        self._ensure_binary_security_token(security)
        return envelope, headers

    def _apply_signature(self, envelope: etree._Element) -> None:
        key = zeep_signature._make_sign_key(
            self.key_data, self.cert_data, self.password
        )
        security, sec_token_ref = self._signature_prepare_with_addressing(
            envelope, key, self.signature_method, self.digest_method
        )

    def _signature_prepare_with_addressing(
        self,
        envelope: etree._Element,
        key: Any,
        signature_method: Any,
        digest_method: Any,
    ) -> tuple[etree._Element, etree._Element]:
        soap_env = zeep_signature.detect_soap_env(envelope)

        signature_node = xmlsec.template.create(
            envelope,
            xmlsec.Transform.EXCL_C14N,
            signature_method or xmlsec.Transform.RSA_SHA1,
        )

        key_info = xmlsec.template.ensure_key_info(signature_node)

        security = wsse_utils.get_security_header(envelope)
        security.insert(0, signature_node)

        ctx = xmlsec.SignatureContext()
        ctx.key = key

        body = envelope.find(etree.QName(soap_env, "Body"))
        zeep_signature._sign_node(ctx, signature_node, body, digest_method)

        timestamp = security.find(etree.QName(wsse_utils.ns.WSU, "Timestamp"))
        if timestamp is not None:
            zeep_signature._sign_node(ctx, signature_node, timestamp, digest_method)

        for header in self._iter_addressing_headers(envelope, soap_env):
            zeep_signature.ensure_id(header)
            zeep_signature._sign_node(ctx, signature_node, header, digest_method)

        ctx.sign(signature_node)

        sec_token_ref = etree.SubElement(
            key_info, etree.QName(wsse_utils.ns.WSSE, "SecurityTokenReference")
        )
        return security, sec_token_ref

    @staticmethod
    def _iter_addressing_headers(
        envelope: etree._Element, soap_env: str
    ) -> list[etree._Element]:
        header = envelope.find(etree.QName(soap_env, "Header"))
        if header is None:
            return []

        nodes: list[etree._Element] = []
        for child in header:
            if etree.QName(child).namespace == WSA_NAMESPACE:
                nodes.append(child)
        return nodes

    def debug_summary(self) -> dict[str, object]:
        info: dict[str, object] = {
            "timestamp_added": True,
            "timestamp_ttl_seconds": self.timestamp_ttl_seconds,
        }
        if self._last_timestamp_window:
            info["last_timestamp_window"] = dict(self._last_timestamp_window)
        if self._cert_b64:
            info["binary_security_token"] = True
        if xmlsec is not None:
            if getattr(self, "signature_method", None) == getattr(
                xmlsec.Transform, "RSA_SHA256", None
            ):
                info["signature_method"] = "RSA_SHA256"
            if getattr(self, "digest_method", None) == getattr(
                xmlsec.Transform, "SHA256", None
            ):
                info["digest_method"] = "SHA256"
        return info

    @staticmethod
    def _extract_certificate_b64(certfile: str, key_file: str | None = None) -> str | None:
        try:
            raw_bytes = Path(certfile).read_bytes()
        except OSError:
            return None

        pem_text = raw_bytes.decode("utf-8", errors="ignore")
        matches = re.findall(
            r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
            pem_text,
            re.DOTALL,
        )
        if not matches:
            return None

        certificates: list[tuple[x509.Certificate | None, str]] = []
        for body in matches:
            payload = "".join(body.split())
            if not payload:
                continue
            pem = (
                "-----BEGIN CERTIFICATE-----\n"
                f"{body.strip()}\n"
                "-----END CERTIFICATE-----\n"
            )
            try:
                cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
            except Exception:
                cert = None
            certificates.append((cert, payload))

        if not certificates:
            return None

        key_public_numbers = None
        if key_file:
            try:
                key_bytes = Path(key_file).read_bytes()
                private_key = serialization.load_pem_private_key(key_bytes, password=None)
                key_public_numbers = private_key.public_key().public_numbers()
            except Exception:
                key_public_numbers = None

        if key_public_numbers is not None:
            for cert, payload in certificates:
                if cert is None:
                    continue
                try:
                    if cert.public_key().public_numbers() == key_public_numbers:
                        return payload
                except Exception:
                    continue

        fallback_payload: str | None = None
        leaf_candidates: list[str] = []

        for cert, payload in certificates:
            if cert is None:
                if fallback_payload is None:
                    fallback_payload = payload
                continue

            try:
                basic_constraints = cert.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                is_ca = bool(getattr(basic_constraints, "ca", False))
            except x509.ExtensionNotFound:
                # Treat self-signed certificates without explicit constraints as CA
                is_ca = cert.issuer == cert.subject
            except Exception:
                if fallback_payload is None:
                    fallback_payload = payload
                continue

            if not is_ca:
                leaf_candidates.append(payload)
            elif fallback_payload is None:
                fallback_payload = payload

        if leaf_candidates:
            return leaf_candidates[0]

        if fallback_payload is not None:
            return fallback_payload

        # Fallback to the first certificate if nothing else matched.
        return certificates[0][1]

    def _ensure_binary_security_token(self, security: etree._Element) -> None:
        if not self._cert_b64:
            return

        token_tag = f"{{{wsse_utils.ns.WSSE}}}BinarySecurityToken"
        wsu_id_attr = etree.QName(wsse_utils.ns.WSU, "Id")
        signature_tag = f"{{{DS_NAMESPACE}}}Signature"
        token_id = wsse_utils.get_unique_id()
        existing_token = None

        for child in security:
            if child.tag == token_tag:
                existing_token = child
                break

        if existing_token is None:
            bst = wsse_utils.WSSE.BinarySecurityToken()
            bst.set(
                "EncodingType",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
            )
            bst.set(
                "ValueType",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
            )
            bst.set(wsu_id_attr, token_id)
            bst.text = self._cert_b64

            signature = security.find(signature_tag)
            if signature is not None:
                siblings = list(security)
                try:
                    index = siblings.index(signature)
                except ValueError:
                    index = 0
                security.insert(index, bst)
            else:
                security.append(bst)
            binary_token = bst
        else:
            binary_token = existing_token
            if not binary_token.get(str(wsu_id_attr)):
                binary_token.set(wsu_id_attr, token_id)
            if not binary_token.text:
                binary_token.text = self._cert_b64

        signature = security.find(signature_tag)
        if signature is None:
            return

        key_info_path = f"{{{DS_NAMESPACE}}}KeyInfo"

        # The zeep signer injects one or more <ds:KeyInfo> elements containing
        # <ds:X509Data>.  A few Unified Interface endpoints insist on resolving the
        # signing certificate exclusively through a wsse:SecurityTokenReference that
        # points to the BinarySecurityToken.  When multiple KeyInfo nodes are present
        # (for example, because zeep duplicates them while processing policies), the
        # service can stumble over the first node and ignore the reference we add.
        #
        # To guarantee a single, clean <ds:KeyInfo>, remove all existing ones and
        # append a fresh element that only contains the SecurityTokenReference.
        for existing_key_info in signature.findall(key_info_path):
            signature.remove(existing_key_info)

        key_info = etree.SubElement(signature, etree.QName(DS_NAMESPACE, "KeyInfo"))

        sec_token_ref = etree.SubElement(
            key_info, etree.QName(wsse_utils.ns.WSSE, "SecurityTokenReference")
        )

        bst_id = binary_token.get(str(wsu_id_attr), token_id)
        reference = etree.SubElement(
            sec_token_ref, etree.QName(wsse_utils.ns.WSSE, "Reference")
        )
        reference.set("URI", f"#{bst_id}")
        reference.set(
            "ValueType",
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
        )


class UnifiedServiceError(Exception):
    """Raised when the UnifiedService call cannot be completed."""


@dataclass
class UnifiedServiceConfig:
    endpoint: str
    wsdl_url: str
    client_cert: str
    client_key: str
    ca_bundle: Optional[str]
    verify_tls: bool


DEFAULT_UNIFIED_ENDPOINT = (
    "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc"
)


def _derive_endpoint_and_wsdl(raw_endpoint: str) -> tuple[str, str]:
    """Return the SOAP execution endpoint and matching WSDL URL."""

    endpoint = (raw_endpoint or DEFAULT_UNIFIED_ENDPOINT).strip()
    if not endpoint:
        endpoint = DEFAULT_UNIFIED_ENDPOINT

    parsed = urlsplit(endpoint)

    # Always call the service without query/fragment to avoid hitting ?wsdl URLs.
    call_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

    query = (parsed.query or "").strip()
    if query:
        wsdl_url = endpoint
    else:
        wsdl_url = endpoint if endpoint.lower().endswith("?wsdl") else endpoint + "?wsdl"

    return call_endpoint, wsdl_url


class CapturingTransport(Transport):
    """Transport that keeps the last HTTP response around for diagnostics."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.last_response = None

    def post_xml(self, address, envelope, headers):  # type: ignore[override]
        try:
            response = super().post_xml(address, envelope, headers)
        except TransportError as exc:
            self.last_response = getattr(exc, "response", None)
            raise
        else:
            self.last_response = response
            return response


@dataclass
class AddressCallResult:
    ok: bool
    http_status: Optional[int]
    took_ms: int
    result: Any
    fault: Optional[str]
    fault_code: Optional[str]
    fault_detail_xml: Optional[str]
    request_xml: str
    response_xml: str
    endpoint: str
    soap_action: Optional[str]
    ws_security: Dict[str, Any]
    transport_debug: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "http_status": self.http_status,
            "took_ms": self.took_ms,
            "result": self.result,
            "fault": self.fault,
            "fault_code": self.fault_code,
            "fault_detail_xml": self.fault_detail_xml,
            "request_xml": self.request_xml,
            "response_xml": self.response_xml,
            "endpoint": self.endpoint,
            "soap_action": self.soap_action,
            "ws_security": self.ws_security,
            "transport_debug": self.transport_debug,
        }


def _normalize_path(value: str | None) -> Optional[str]:
    if not value:
        return None
    path = value.strip()
    return path or None


def _ensure_file(path: Optional[str], label: str) -> str:
    if not path:
        raise UnifiedServiceError(f"{label} is not configured")
    if not os.path.exists(path):
        raise UnifiedServiceError(f"{label} not found at {path}")
    return path


def get_unified_config() -> UnifiedServiceConfig:
    cfg = load_config()
    endpoint_raw = cfg.get("endpoint") or DEFAULT_UNIFIED_ENDPOINT
    endpoint, wsdl_url = _derive_endpoint_and_wsdl(endpoint_raw)

    client_cert = _ensure_file(_normalize_path(cfg.get("client_cert")), "Client certificate")
    client_key = _ensure_file(_normalize_path(cfg.get("client_key")), "Client private key")

    ca_bundle = _normalize_path(cfg.get("ca_bundle"))
    verify_tls = bool(cfg.get("verify_tls", True))

    return UnifiedServiceConfig(
        endpoint=endpoint,
        wsdl_url=wsdl_url,
        client_cert=client_cert,
        client_key=client_key,
        ca_bundle=ca_bundle,
        verify_tls=verify_tls,
    )


def _build_security_summary(
    config: UnifiedServiceConfig,
    wsse: Signature | None = None,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "ws_security_active": True,
        "mode": "wsse-x509-signature",
        "certificate_path": config.client_cert,
        "key_path": config.client_key,
        "ws_addressing": True,
        "mutual_tls": True,
        "verify_tls": config.verify_tls,
        "ca_bundle": config.ca_bundle,
    }

    if isinstance(wsse, TimestampedSignature):
        summary.update(wsse.debug_summary())

    return summary


def _pretty_xml(elem: Optional[etree._Element]) -> str:
    if elem is None:
        return ""
    return etree.tostring(elem, pretty_print=True, encoding="unicode")


def _extract_wsa_action(request_xml: str) -> Optional[str]:
    if not request_xml:
        return None
    try:
        root = etree.fromstring(request_xml.encode("utf-8"))
    except etree.XMLSyntaxError:
        return None
    action = root.find(".//{http://www.w3.org/2005/08/addressing}Action")
    if action is not None and action.text:
        return action.text.strip()
    return None


def _serialize_result(value: Any) -> Any:
    if value is None:
        return None
    return serialize_object(value)


def _serialize_fault_detail(detail: Any) -> Optional[str]:
    if detail is None:
        return None
    if isinstance(detail, etree._Element):
        return _pretty_xml(detail)
    return str(detail)


def _collect_transport_debug(transport: CapturingTransport) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    response = transport.last_response
    if response is None:
        return info

    status = getattr(response, "status_code", None)
    if status is not None:
        info["last_http_status"] = status

    headers = getattr(response, "headers", None)
    if headers:
        try:
            headers_dict = dict(headers)
        except Exception:  # pragma: no cover - extremely defensive
            headers_dict = {}
        if headers_dict:
            info["last_response_headers"] = headers_dict
            content_type = headers_dict.get("Content-Type") or headers_dict.get("content-type")
            if content_type:
                info["last_content_type"] = content_type

    request = getattr(response, "request", None)
    if request is not None:
        url = getattr(request, "url", None)
        if url:
            info["last_request_url"] = url

    elapsed = getattr(response, "elapsed", None)
    if elapsed is not None:
        try:
            info["last_request_elapsed_ms"] = int(elapsed.total_seconds() * 1000)
        except Exception:  # pragma: no cover - defensive
            pass

    preview = ""
    body_bytes = None
    try:
        body_bytes = response.content
    except Exception:  # pragma: no cover - defensive
        body_bytes = None

    if body_bytes:
        preview = body_bytes[:1024]
        if isinstance(preview, bytes):
            preview = preview.decode("utf-8", "replace")
        info["last_response_preview"] = preview

    return info


def create_unified_client() -> tuple[
    Client,
    Any,
    CapturingTransport,
    HistoryPlugin,
    UnifiedServiceConfig,
    Signature,
]:
    config = get_unified_config()

    session = Session()
    session.cert = (config.client_cert, config.client_key)
    if config.verify_tls:
        session.verify = config.ca_bundle or True
    else:
        session.verify = False

    transport = CapturingTransport(session=session, timeout=20)
    settings = Settings(strict=False, xml_huge_tree=True)
    history = HistoryPlugin()

    wsse = TimestampedSignature(config.client_key, config.client_cert)

    client = Client(
        wsdl=config.wsdl_url,
        wsse=wsse,
        transport=transport,
        settings=settings,
        plugins=[history],
    )

    client.set_default_soapheaders(None)

    service = client.bind("UnifiedService", "UnifiedServiceHttpBinding_UnifiedServiceInterface")
    if hasattr(service, "_binding_options"):
        service._binding_options["address"] = config.endpoint

    return client, service, transport, history, config, wsse


def call_unified_operation(operation: str, **params: Any) -> AddressCallResult:
    _client, service, transport, history, config, wsse = create_unified_client()

    if not hasattr(service, operation):
        raise UnifiedServiceError(f"UnifiedService does not expose operation {operation}")

    method = getattr(service, operation)

    started = time.perf_counter()
    result_obj: Any = None
    fault_message: Optional[str] = None
    fault_code: Optional[str] = None
    fault_detail: Optional[str] = None
    exception_info: Optional[dict[str, Any]] = None

    try:
        result_obj = method(**params)
        ok = True
    except Fault as exc:
        ok = False
        fault_message = exc.message
        fault_code = getattr(exc, "code", None)
        fault_detail = _serialize_fault_detail(getattr(exc, "detail", None))
        result_obj = getattr(exc, "detail", None)
    except TransportError as exc:
        status = getattr(exc, "status_code", None)
        raise UnifiedServiceError(f"Transport error{f' ({status})' if status else ''}: {exc.message}") from exc
    except Exception as exc:  # pragma: no cover - defensive logging path
        ok = False
        result_obj = None
        fault_message = f"Unexpected error invoking {operation}: {exc}"
        fault_code = getattr(exc, "code", None)
        fault_detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        if len(fault_detail) > 4000:
            fault_detail = fault_detail[:4000] + "... (truncated)"
        exception_info = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": fault_detail,
        }
    finally:
        took_ms = int((time.perf_counter() - started) * 1000)

    request_xml = ""
    if history.last_sent and history.last_sent.get("envelope") is not None:
        request_xml = _pretty_xml(history.last_sent["envelope"])

    response_xml = ""
    if history.last_received and history.last_received.get("envelope") is not None:
        response_xml = _pretty_xml(history.last_received["envelope"])

    status_code = None
    if transport.last_response is not None:
        status_code = getattr(transport.last_response, "status_code", None)

    soap_action = _extract_wsa_action(request_xml)

    serialized = _serialize_result(result_obj if ok else None)

    transport_debug = _collect_transport_debug(transport)
    if exception_info:
        transport_debug.setdefault("exception", exception_info)

    return AddressCallResult(
        ok=ok,
        http_status=status_code,
        took_ms=took_ms,
        result=serialized,
        fault=fault_message,
        fault_code=fault_code,
        fault_detail_xml=fault_detail,
        request_xml=request_xml,
        response_xml=response_xml,
        endpoint=config.endpoint,
        soap_action=soap_action,
        ws_security=_build_security_summary(config, wsse),
        transport_debug=transport_debug,
    )


def get_initial_addressee_record_list(token: str = "") -> AddressCallResult:
    return call_unified_operation("GetInitialAddresseeRecordList", Token=token)


def get_changed_addressee_record_list(last_version: str) -> AddressCallResult:
    return call_unified_operation("GetChangedAddresseeRecordList", LastVersion=last_version)
