import os
import json
from datetime import datetime
from typing import Dict, Any, List

from lxml import etree

from address_service import (
    _assert_thumbprint_keyinfo,
    get_unified_config,
    build_signed_get_initial_addressee_request,
)
from soap_client import send_get_initial_addressee_request

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


def run_wssec_scenarios(token: str, scenario_name: str = "all") -> List[Dict[str, Any]]:
    os.makedirs(DEBUG_DIR, exist_ok=True)

    config = get_unified_config()
    endpoint = config.debug_endpoint or config.endpoint

    if scenario_name != "all":
        selected = _find_scenario(scenario_name)
        if not selected:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        scenarios = [selected]
    else:
        scenarios = SCENARIOS

    results: List[Dict[str, Any]] = []

    for sc in scenarios:
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

        status = http.get("status")
        body = http.get("body") or ""
        fault_reason = _extract_fault_reason(body)

        with open(resp_path, "w", encoding="utf-8") as fh:
            fh.write(body)

        results.append(
            {
                "scenario": sc["name"],
                "label": sc.get("label", sc["name"]),
                "policy_mode": bool(sc.get("policy_mode")),
                "http_status": status,
                "fault_reason": fault_reason,
                "request_file": req_name,
                "response_file": resp_name,
            }
        )

    summary_name = f"wssec_scenarios_{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    summary_path = os.path.join(DEBUG_DIR, summary_name)
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    return results
