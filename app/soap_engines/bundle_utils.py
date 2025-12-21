from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Iterable

from lxml import etree

BUNDLE_ROOT = "/data/debug"


def make_bundle_dir(operation: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base_dir = os.path.join(BUNDLE_ROOT, operation, timestamp)
    candidate = base_dir
    counter = 1
    while os.path.exists(candidate):
        counter += 1
        candidate = f"{base_dir}-{counter}"
    os.makedirs(candidate, exist_ok=True)
    return candidate


def write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content or "")


def write_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def copy_file(src: str | None, dest: str) -> None:
    if not src or not os.path.isfile(src):
        write_text(dest, "")
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copyfile(src, dest)


def load_xml(path: str | None) -> str | None:
    if not path or not os.path.isfile(path):
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


def _extract_repeating_records(root: etree._Element | None) -> list[dict[str, Any]]:
    if root is None:
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


def _find_first_text(nodes: Iterable[etree._Element]) -> str | None:
    for node in nodes:
        text = (node.text or "").strip()
        if text:
            return text
    return None


def parse_addressee_records(xml_text: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "record_count": 0,
        "records": [],
        "next_token": None,
        "extraction_mode": "schema-targeted",
    }
    if not xml_text:
        return payload
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return payload

    output_nodes = root.xpath(".//*[local-name()='GetInitialAddresseeRecordListOutput']")
    output = output_nodes[0] if output_nodes else None
    target_root = output or root

    record_nodes = target_root.xpath(".//*[local-name()='AddresseeRecord']")
    records: list[dict[str, Any]] = []
    for node in record_nodes:
        if not isinstance(node, etree._Element):
            continue
        data = _element_to_data(node)
        if isinstance(data, dict):
            records.append(data)
        else:
            records.append({"value": data})

    token_nodes = target_root.xpath(".//*[local-name()='Token']")
    next_token = _find_first_text(
        [node for node in token_nodes if isinstance(node, etree._Element)]
    )

    if not records:
        fallback = _extract_repeating_records(target_root)
        if fallback:
            return {
                "record_count": len(fallback),
                "records": fallback,
                "next_token": next_token,
                "extraction_mode": "best_effort_repeating_nodes",
            }

    payload["record_count"] = len(records)
    payload["records"] = records
    payload["next_token"] = next_token
    return payload


def extract_message_id(xml_text: str | None) -> str | None:
    if not xml_text:
        return None
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return None
    message_id = root.find(".//*[local-name()='MessageID']")
    if message_id is not None and message_id.text:
        return message_id.text.strip()
    return None


def extract_fault_info(xml_text: str | None) -> tuple[str | None, str | None]:
    if not xml_text:
        return None, None
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return None, None

    for soap_ns in (
        "http://www.w3.org/2003/05/soap-envelope",
        "http://schemas.xmlsoap.org/soap/envelope/",
    ):
        fault = root.find(f".//{{{soap_ns}}}Fault")
        if fault is None:
            continue
        if soap_ns == "http://www.w3.org/2003/05/soap-envelope":
            reason = (
                fault.findtext(f".//{{{soap_ns}}}Reason/{{{soap_ns}}}Text", default="")
                or ""
            ).strip()
            code = (
                fault.findtext(f".//{{{soap_ns}}}Code/{{{soap_ns}}}Value", default="")
                or ""
            ).strip()
        else:
            reason = (fault.findtext("faultstring", default="") or "").strip()
            code = (fault.findtext("faultcode", default="") or "").strip()
        return code or None, reason or None

    return None, None


def assert_soap_success(xml_text: str | None) -> dict[str, Any]:
    result = {
        "ok": False,
        "fault_code": None,
        "fault_reason": None,
        "has_body": False,
        "has_output": False,
    }
    if not xml_text:
        return result
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return result

    envelope = root if _local_name(root.tag) == "Envelope" else None
    if envelope is None:
        envelope = root.find(".//*[local-name()='Envelope']")
    if envelope is None:
        return result

    body = envelope.find(".//*[local-name()='Body']")
    if body is None:
        return result

    result["has_body"] = True
    fault = body.find(".//*[local-name()='Fault']")
    if fault is not None:
        fault_code, fault_reason = extract_fault_info(xml_text)
        result["fault_code"] = fault_code
        result["fault_reason"] = fault_reason
        return result

    output = body.find(".//*[local-name()='GetInitialAddresseeRecordListOutput']")
    if output is not None:
        result["has_output"] = True

    result["ok"] = result["has_body"] and result["has_output"]
    return result
