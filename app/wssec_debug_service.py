import os
import json
import time
import csv
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from lxml import etree

from address_service import (
    _assert_thumbprint_keyinfo,
    get_unified_config,
    build_signed_get_initial_addressee_request,
)
from soap_client import send_get_initial_addressee_request
from soap_engines.cert_utils import resolve_pfx_material
from soap_engines.dotnet_engine import call_dotnet
from soap_engines.java_vdaa_sdk import run_java_sdk_call
from storage import load_config, save_config

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DEBUG_DIR = os.path.join(BASE_DIR, "data", "addresses", "wssec_debug")


SCENARIOS = [
    {
        "name": "sha1_body_timestamp",
        "label": "SHA1, sign Body + Timestamp (classic)",
        "sign_alg": "rsa-sha1",
        "digest_alg": "sha1",
        "signed_parts": ("body", "timestamp"),
        "security_order": ("timestamp", "bst", "signature"),
    },
    {
        "name": "sha1_body_ts_action_to",
        "label": "SHA1, sign Body + Timestamp + Action + To",
        "sign_alg": "rsa-sha1",
        "digest_alg": "sha1",
        "signed_parts": ("body", "timestamp", "action", "to"),
        "security_order": ("timestamp", "bst", "signature"),
    },
    {
        "name": "sha256_body_timestamp",
        "label": "SHA256, sign Body + Timestamp",
        "sign_alg": "rsa-sha256",
        "digest_alg": "sha256",
        "signed_parts": ("body", "timestamp"),
        "security_order": ("timestamp", "bst", "signature"),
    },
    {
        "name": "sha256_body_ts_action_to",
        "label": "SHA256, sign Body + Timestamp + Action + To",
        "sign_alg": "rsa-sha256",
        "digest_alg": "sha256",
        "signed_parts": ("body", "timestamp", "action", "to"),
        "security_order": ("timestamp", "bst", "signature"),
    },
    {
        "name": "policy_compliant",
        "label": "Policy-compliant (SDK WSDL)",
        "sign_alg": "rsa-sha256",
        "digest_alg": "sha256",
        "signed_parts": ("body", "timestamp", "action", "to"),
        "security_order": ("timestamp", "bst", "signature"),
        "policy_mode": True,
    },
]


def _find_scenario(name: str) -> Dict[str, Any] | None:
    for scenario in SCENARIOS:
        if scenario["name"] == name:
            return scenario
    return None


def _extract_fault_reason(xml_text: str) -> str:
    if not xml_text:
        return ""
    try:
        root = etree.fromstring(
            xml_text.encode("utf-8"), parser=etree.XMLParser(recover=True)
        )
    except Exception:
        # Response is not valid XML at all
        return ""

    # When recover=True and parsing fails, fromstring may return None
    if root is None:
        return ""

    ns = {"s": "http://www.w3.org/2003/05/soap-envelope"}
    text_el = root.find(".//s:Fault/s:Reason/s:Text", namespaces=ns)
    if text_el is not None and text_el.text:
        return text_el.text.strip()
    return ""


def _extract_message_id(xml_text: str) -> Optional[str]:
    if not xml_text:
        return None
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return None
    msg = root.find(".//*[local-name()='MessageID']")
    if msg is not None and msg.text:
        return msg.text.strip()
    return None


def _extract_action(xml_text: str) -> Optional[str]:
    if not xml_text:
        return None
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return None
    action = root.find(".//*[local-name()='Action']")
    if action is not None and action.text:
        return action.text.strip()
    return None


def run_wssec_scenarios(
    token: str,
    scenario_name: str = "all",
    endpoint_mode: str = "debug",
    *,
    engine: str = "python",
) -> List[Dict[str, Any]]:
    if engine != "python":
        raise ValueError(
            "WS-Security scenarios are only available in the Python engine."
        )
    os.makedirs(DEBUG_DIR, exist_ok=True)

    config = get_unified_config()
    if endpoint_mode == "debug":
        endpoint = config.debug_endpoint or config.endpoint
    else:
        endpoint = config.endpoint

    if scenario_name != "all":
        selected = _find_scenario(scenario_name)
        if not selected:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        scenarios = [selected]
    else:
        scenarios = SCENARIOS

    results: List[Dict[str, Any]] = []

    for sc in scenarios:
        sent_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        started = time.perf_counter()
        envelope_xml = build_signed_get_initial_addressee_request(
            endpoint=endpoint,
            token=token or "",
            certfile=config.client_cert,
            key_file=config.client_key,
            sign_alg=sc.get("sign_alg", "rsa-sha1"),
            digest_alg=sc.get("digest_alg", "sha1"),
            signed_parts=sc.get(
                "signed_parts",
                ("body", "timestamp", "action", "to", "message", "replyto"),
            ),
            security_order=sc.get(
                "security_order", ("bst", "signature", "timestamp")
            ),
        )

        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        base = f"GetInitialAddresseeRecordList_{sc['name']}_{ts}"
        req_name = f"{base}_request.xml"
        resp_name = f"{base}_response.xml"

        req_path = os.path.join(DEBUG_DIR, req_name)
        resp_path = os.path.join(DEBUG_DIR, resp_name)

        with open(req_path, "w", encoding="utf-8") as fh:
            fh.write(envelope_xml)

        try:
            _assert_thumbprint_keyinfo(envelope_xml)
        except Exception as exc:
            with open(resp_path, "w", encoding="utf-8") as fh:
                fh.write(f"WS-Security guard failed: {exc}\n")
            raise

        http = send_get_initial_addressee_request(
            endpoint=endpoint,
            envelope_xml=envelope_xml,
            client_cert=config.client_cert,
            client_key=config.client_key,
            key_pass="",
        )

        took_ms = int((time.perf_counter() - started) * 1000)
        status = http.get("status")
        body = http.get("body") or ""
        fault_reason = _extract_fault_reason(body)
        message_id = _extract_message_id(envelope_xml)
        soap_action = _extract_action(envelope_xml)

        with open(resp_path, "w", encoding="utf-8") as fh:
            fh.write(body)

        results.append(
            {
                "ok": bool(status and 200 <= status < 300),
                "engine": "python",
                "operation": "GetInitialAddresseeRecordList",
                "endpoint": endpoint,
                "endpoint_mode": endpoint_mode,
                "sent_utc": sent_utc,
                "took_ms": took_ms,
                "http_status": status,
                "soap_action": soap_action,
                "message_id": message_id,
                "request_saved_path": req_path,
                "response_saved_path": resp_path,
                "parsed_saved_path": None,
                "scenario": sc["name"],
                "label": sc.get("label", sc["name"]),
                "policy_mode": bool(sc.get("policy_mode")),
                "fault_reason": fault_reason,
                "request_file": req_name,
                "response_file": resp_name,
                "stderr": "",
            }
        )

    summary_name = f"wssec_scenarios_{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    summary_path = os.path.join(DEBUG_DIR, summary_name)
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    return results


def _load_xml(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _element_to_data(element: etree._Element) -> Any:
    children = [child for child in element if isinstance(child.tag, str)]
    if not children:
        return (element.text or "").strip()
    data: dict[str, Any] = {}
    for child in children:
        key = _local_name(child.tag)
        value = _element_to_data(child)
        if key in data:
            if not isinstance(data[key], list):
                data[key] = [data[key]]
            data[key].append(value)
        else:
            data[key] = value
    return data


def _extract_repeating_records(xml_text: str) -> list[dict[str, Any]]:
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return []
    candidates: list[list[etree._Element]] = []
    for parent in root.iter():
        children = [child for child in parent if isinstance(child.tag, str)]
        if len(children) < 2:
            continue
        grouped: dict[str, list[etree._Element]] = {}
        for child in children:
            grouped.setdefault(child.tag, []).append(child)
        for items in grouped.values():
            if len(items) >= 2:
                candidates.append(items)
    if not candidates:
        return []
    best = max(candidates, key=len)
    records = []
    for item in best:
        data = _element_to_data(item)
        if isinstance(data, dict):
            records.append(data)
        else:
            records.append({"value": data})
    return records


def _save_response_artifacts(response_path: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not response_path or not os.path.isfile(response_path):
        return None, None
    xml_text = _load_xml(response_path)
    if not xml_text:
        return None, None
    records = _extract_repeating_records(xml_text)
    base_path = response_path
    if base_path.lower().endswith(".xml"):
        base_path = base_path[:-4]
    json_path = f"{base_path}.json"
    payload = {
        "record_count": len(records),
        "records": records,
        "extraction": "best_effort_repeating_nodes",
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    csv_path = None
    if records and all(isinstance(rec, dict) for rec in records):
        fieldnames = sorted({key for rec in records for key in rec.keys()})
        csv_path = f"{base_path}.csv"
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for rec in records:
                writer.writerow(rec)
    return json_path, csv_path


def run_wssec_single_call(
    *,
    engine: str,
    operation: str,
    token: str,
    endpoint_mode: str = "debug",
    use_app_config_certs: bool = True,
    pfx_path: str | None = None,
    pfx_password: str | None = None,
) -> Dict[str, Any]:
    os.makedirs(DEBUG_DIR, exist_ok=True)
    cfg = load_config()
    if endpoint_mode == "debug":
        endpoint = (cfg.get("debug_endpoint") or cfg.get("endpoint") or "").strip()
    else:
        endpoint = (cfg.get("endpoint") or "").strip()

    engine = engine.strip().lower()
    requested_pfx_path = pfx_path or ""
    requested_pfx_password = pfx_password or ""
    pfx_material = None
    if use_app_config_certs:
        pfx_material = resolve_pfx_material(cfg)
        pfx_path = pfx_material.path
        pfx_password = pfx_material.password

    if engine == "java":
        cfg["wssec_java_pfx_path"] = requested_pfx_path
        cfg["wssec_java_pfx_password"] = requested_pfx_password
        save_config(cfg)

    try:
        if engine == "dotnet":
            result = call_dotnet(
                operation=operation,
                token=token,
                endpoint=endpoint,
                out_dir=DEBUG_DIR,
                endpoint_mode=endpoint_mode,
                cert_pfx_path=pfx_path,
                cert_pfx_password=pfx_password,
            )
        elif engine == "java":
            result = run_java_sdk_call(
                operation=operation,
                token=token,
                endpoint=endpoint,
                out_dir=DEBUG_DIR,
                endpoint_mode=endpoint_mode,
                cert_pfx_path=pfx_path,
                cert_pfx_password=pfx_password,
            )
        else:
            raise ValueError(f"Unsupported engine for single call: {engine}")
    finally:
        if pfx_material is not None:
            pfx_material.cleanup()

    request_path = result.get("request_saved_path")
    response_path = result.get("response_saved_path")

    request_xml = _load_xml(request_path)
    response_xml = _load_xml(response_path)
    response_json_path, response_csv_path = _save_response_artifacts(response_path)

    response = {
        "ok": result.get("ok", False),
        "engine": result.get("engine", engine),
        "operation": operation,
        "endpoint": result.get("endpoint", endpoint),
        "endpoint_mode": result.get("endpoint_mode", endpoint_mode),
        "request_xml": request_xml,
        "response_xml": response_xml,
        "saved_request_path": request_path,
        "saved_response_path": response_path,
        "request_saved_path": request_path,
        "response_saved_path": response_path,
        "response_json_path": response_json_path,
        "response_csv_path": response_csv_path,
        "http_status": result.get("http_status"),
        "took_ms": result.get("took_ms"),
        "stderr": result.get("stderr", ""),
        "fault_reason": result.get("fault_reason"),
        "bridge_stdout": result.get("bridge_stdout"),
        "soap_request_path": result.get("soap_request_path"),
        "soap_response_path": result.get("soap_response_path"),
        "soap_request_saved_path": result.get("soap_request_path"),
        "soap_response_saved_path": result.get("soap_response_path"),
    }
    return response
