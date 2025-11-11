from __future__ import annotations

import os
import time
import traceback
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from lxml import etree
from requests import Session
from zeep import Client, Settings
from zeep.exceptions import Fault, TransportError
from zeep.helpers import serialize_object
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.wsse.signature import Signature

from storage import load_config


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


def _build_security_summary(config: UnifiedServiceConfig) -> Dict[str, Any]:
    return {
        "ws_security_active": True,
        "mode": "wsse-x509-signature",
        "certificate_path": config.client_cert,
        "key_path": config.client_key,
        "ws_addressing": True,
        "mutual_tls": True,
        "verify_tls": config.verify_tls,
        "ca_bundle": config.ca_bundle,
    }


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


def create_unified_client() -> tuple[Client, Any, CapturingTransport, HistoryPlugin, UnifiedServiceConfig]:
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

    wsse = Signature(config.client_key, config.client_cert)

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

    return client, service, transport, history, config


def call_unified_operation(operation: str, **params: Any) -> AddressCallResult:
    _client, service, transport, history, config = create_unified_client()

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
        ws_security=_build_security_summary(config),
        transport_debug=transport_debug,
    )


def get_initial_addressee_record_list(token: str = "") -> AddressCallResult:
    return call_unified_operation("GetInitialAddresseeRecordList", Token=token)


def get_changed_addressee_record_list(last_version: str) -> AddressCallResult:
    return call_unified_operation("GetChangedAddresseeRecordList", LastVersion=last_version)
