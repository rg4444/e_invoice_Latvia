from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from lxml import etree

from address_service import UnifiedServiceError, call_unified_operation
from soap_engines.bundle_utils import (
    extract_fault_info,
    extract_message_id,
    make_bundle_dir,
    parse_addressee_records,
    write_json,
    write_text,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_addressees(response_xml: str) -> list[dict[str, str]]:
    if not response_xml:
        return []
    try:
        root = etree.fromstring(response_xml.encode("utf-8"))
    except Exception:
        return []

    entries: list[dict[str, str]] = []
    nodes = root.xpath(".//*[contains(local-name(), 'Addressee')]")
    for node in nodes:
        if not isinstance(node, etree._Element):
            continue
        entry: dict[str, str] = {}
        for child in node:
            if not isinstance(child, etree._Element):
                continue
            key = etree.QName(child).localname
            value = (child.text or "").strip()
            if value:
                entry[key] = value
        if entry:
            entries.append(entry)
    return entries


def _parse_addressee_summary(response_xml: str) -> dict[str, Any]:
    if not response_xml:
        return {}
    try:
        root = etree.fromstring(response_xml.encode("utf-8"))
    except Exception:
        return {}

    def _xpath(expr: str):
        try:
            return root.xpath(expr)
        except etree.XPathError:
            return []

    entries = [
        node
        for node in _xpath(".//*[contains(local-name(), 'Addressee')]")
        if isinstance(node, etree._Element)
    ]
    count = len(entries)

    next_token = None
    for cand in _xpath(".//*[contains(local-name(), 'Token')]"):
        if isinstance(cand, etree._Element):
            txt = (cand.text or "").strip()
        else:
            txt = str(cand).strip()
        if txt:
            next_token = txt
            break

    max_version = None
    for cand in _xpath(".//*[contains(local-name(), 'Version')]"):
        if isinstance(cand, etree._Element):
            txt = (cand.text or "").strip()
        else:
            txt = str(cand).strip()
        if txt.isdigit():
            v = int(txt)
            if max_version is None or v > max_version:
                max_version = v

    out: dict[str, Any] = {}
    if count:
        out["addressee_count"] = count
    if next_token:
        out["next_token"] = next_token
    if max_version is not None:
        out["max_version"] = max_version
    return out


def _save_text(out_dir: str, filename: str, text: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _save_json(out_dir: str, filename: str, payload: Any) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def call_python(
    operation: str,
    token: str,
    endpoint: str,
    out_dir: str,
    *,
    endpoint_mode: str = "normal",
    save_raw: bool = True,
    parse: bool = True,
    **_: Any,
) -> dict[str, Any]:
    sent_utc = _utc_now_iso()
    started = time.perf_counter()
    stderr = ""
    result: dict[str, Any] = {}

    try:
        params: dict[str, str] = {}
        if token:
            if operation == "GetChangedAddresseeRecordList":
                params["LastVersion"] = token
            else:
                params["Token"] = token
        call_result = call_unified_operation(
            operation,
            endpoint_override=endpoint,
            **params,
        )
    except UnifiedServiceError as exc:
        took_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": False,
            "engine": "python",
            "operation": operation,
            "endpoint": endpoint,
            "endpoint_mode": endpoint_mode,
            "sent_utc": sent_utc,
            "took_ms": took_ms,
            "http_status": None,
            "soap_action": None,
            "message_id": None,
            "request_saved_path": None,
            "response_saved_path": None,
            "parsed_saved_path": None,
            "fault_code": None,
            "fault_reason": str(exc),
            "stderr": "",
        }
    except Exception as exc:
        took_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": False,
            "engine": "python",
            "operation": operation,
            "endpoint": endpoint,
            "endpoint_mode": endpoint_mode,
            "sent_utc": sent_utc,
            "took_ms": took_ms,
            "http_status": None,
            "soap_action": None,
            "message_id": None,
            "request_saved_path": None,
            "response_saved_path": None,
            "parsed_saved_path": None,
            "fault_code": None,
            "fault_reason": f"Unexpected internal error: {exc}",
            "stderr": "",
        }

    took_ms = int((time.perf_counter() - started) * 1000)
    request_path = None
    response_path = None
    parsed_path = None
    bundle_dir = None

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if save_raw and call_result.request_xml:
        request_filename = f"{operation}_{ts}_request.xml"
        request_path = _save_text(out_dir, request_filename, call_result.request_xml)

    if save_raw and call_result.response_xml:
        response_filename = f"{operation}_{ts}_response.xml"
        response_path = _save_text(out_dir, response_filename, call_result.response_xml)

    if parse and call_result.response_xml:
        parsed = _parse_addressees(call_result.response_xml)
        parsed_filename = f"{operation}_{ts}_parsed.json"
        parsed_path = _save_json(out_dir, parsed_filename, parsed)

    fault_code = call_result.fault_code
    fault_reason = call_result.fault

    if call_result.response_xml and not fault_reason:
        parsed_fault_code, parsed_fault_reason = _extract_fault_info(call_result.response_xml)
        fault_code = fault_code or parsed_fault_code
        fault_reason = fault_reason or parsed_fault_reason

    message_id = extract_message_id(call_result.request_xml)

    summary = _parse_addressee_summary(call_result.response_xml or "")

    result.update(
        {
            "ok": call_result.ok,
            "engine": "python",
            "operation": operation,
            "endpoint": endpoint,
            "endpoint_mode": endpoint_mode,
            "sent_utc": sent_utc,
            "took_ms": took_ms,
            "http_status": call_result.http_status,
            "soap_action": call_result.soap_action,
            "message_id": message_id,
            "request_saved_path": request_path,
            "response_saved_path": response_path,
            "parsed_saved_path": parsed_path,
            "fault_code": fault_code,
            "fault_reason": fault_reason,
            "stderr": stderr,
            "summary": summary,
        }
    )

    if operation == "GetInitialAddresseeRecordList":
        bundle_dir = make_bundle_dir(operation)
        request_payload_path = os.path.join(bundle_dir, "request_payload.xml")
        response_payload_path = os.path.join(bundle_dir, "response_payload.xml")
        soap_request_path = os.path.join(bundle_dir, "soap_request.xml")
        soap_response_path = os.path.join(bundle_dir, "soap_response.xml")
        parsed_records_path = os.path.join(bundle_dir, "parsed_records.json")
        engine_result_path = os.path.join(bundle_dir, "engine_result.json")
        stderr_path = os.path.join(bundle_dir, "stderr.log")

        write_text(request_payload_path, call_result.request_xml or "")
        write_text(response_payload_path, call_result.response_xml or "")
        write_text(soap_request_path, "")
        write_text(soap_response_path, "")
        write_text(stderr_path, stderr)

        parsed_records = parse_addressee_records(call_result.response_xml or "")
        write_json(parsed_records_path, parsed_records)

        result["trace_error"] = "Python engine cannot capture SOAP envelopes"

        result["request_saved_path"] = request_payload_path
        result["response_saved_path"] = response_payload_path
        result["parsed_saved_path"] = parsed_records_path
        result["soap_request_path"] = soap_request_path
        result["soap_response_path"] = soap_response_path

        write_json(engine_result_path, result)

    return result
