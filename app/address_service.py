from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

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
    endpoint = (cfg.get("endpoint") or "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc").strip()
    wsdl_url = endpoint + ("?wsdl" if not endpoint.endswith("?wsdl") else "")

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
        raise UnifiedServiceError(str(exc)) from exc
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
    )


def get_initial_addressee_record_list(token: str = "") -> AddressCallResult:
    return call_unified_operation("GetInitialAddresseeRecordList", Token=token)


def get_changed_addressee_record_list(last_version: str) -> AddressCallResult:
    return call_unified_operation("GetChangedAddresseeRecordList", LastVersion=last_version)
