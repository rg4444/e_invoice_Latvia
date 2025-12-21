from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from soap_engines.bundle_utils import (
    assert_soap_success,
    copy_file,
    load_xml,
    make_bundle_dir,
    parse_addressee_records,
    write_json,
    write_text,
)
from soap_engines.cert_utils import resolve_pfx_material
from storage import load_config

JAVA_CLASS = "VdaaDivBridge"
JAVA_DIR = "/bridge/java/VdaaDivBridge"
JAVA_LIB = "/bridge/java/VdaaDivBridge/lib/*"
CLASSPATH = f"{JAVA_DIR}:{JAVA_LIB}"
JAVA_ARGS = [
    "-Dcom.sun.xml.bind.v2.bytecode.ClassTailor.noOptimize=true",
    "--add-opens",
    "java.base/java.lang=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.lang.reflect=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.util=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.io=ALL-UNNAMED",
    "--add-exports",
    "java.xml/com.sun.org.apache.xerces.internal.dom=ALL-UNNAMED",
    "--add-exports",
    "java.xml/com.sun.org.apache.xerces.internal.util=ALL-UNNAMED",
    "--add-exports",
    "java.xml.crypto/com.sun.org.apache.xml.internal.security=ALL-UNNAMED",
    "--add-exports",
    "java.xml.crypto/com.sun.org.apache.xml.internal.security.utils=ALL-UNNAMED",
]


def _extract_json_payload(stdout: str) -> dict[str, Any] | None:
    if not stdout:
        return None
    start = stdout.rfind('{"ok"')
    if start == -1:
        start = stdout.rfind("{")
    if start == -1:
        return None
    end = stdout.rfind("}")
    if end == -1 or end < start:
        return None
    candidate = stdout[start : end + 1]
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_base_result(
    *,
    ok: bool,
    operation: str,
    endpoint: str,
    endpoint_mode: str,
    sent_utc: str,
    took_ms: int,
    stderr: str,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "engine": "java",
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
        "fault_reason": None,
        "stderr": stderr,
    }


def run_java_sdk_call(
    *,
    operation: str,
    endpoint: str,
    token: str | None,
    cert_pfx_path: str | None,
    cert_pfx_password: str | None,
    out_dir: str,
    endpoint_mode: str = "normal",
    timeout_s: int = 60,
    config_path: str = "/data/config.json",
) -> dict[str, Any]:
    sent_utc = _utc_now_iso()
    started = time.perf_counter()
    cfg = load_config()
    pfx_material = None

    if not shutil.which("java"):
        took_ms = int((time.perf_counter() - started) * 1000)
        result = _build_base_result(
            ok=False,
            operation=operation,
            endpoint=endpoint,
            endpoint_mode=endpoint_mode,
            sent_utc=sent_utc,
            took_ms=took_ms,
            stderr="",
        )
        result["fault_reason"] = "Java runtime not available"
        return result

    if not os.path.isdir(JAVA_DIR):
        took_ms = int((time.perf_counter() - started) * 1000)
        result = _build_base_result(
            ok=False,
            operation=operation,
            endpoint=endpoint,
            endpoint_mode=endpoint_mode,
            sent_utc=sent_utc,
            took_ms=took_ms,
            stderr="",
        )
        result["fault_reason"] = f"Java bridge directory not found: {JAVA_DIR}"
        return result

    os.makedirs(out_dir, exist_ok=True)

    if not cert_pfx_path:
        pfx_material = resolve_pfx_material(cfg)
        cert_pfx_path = pfx_material.path
        if not cert_pfx_password:
            cert_pfx_password = pfx_material.password
    if not cert_pfx_password:
        cert_pfx_password = (cfg.get("p12_password") or "").strip() or None
    if not cert_pfx_path or not cert_pfx_password:
        took_ms = int((time.perf_counter() - started) * 1000)
        result = _build_base_result(
            ok=False,
            operation=operation,
            endpoint=endpoint,
            endpoint_mode=endpoint_mode,
            sent_utc=sent_utc,
            took_ms=took_ms,
            stderr="",
        )
        result["fault_reason"] = "PFX path and password are required for Java SDK calls"
        if pfx_material is not None:
            pfx_material.cleanup()
        return result
    if cert_pfx_path and not os.path.exists(cert_pfx_path):
        took_ms = int((time.perf_counter() - started) * 1000)
        result = _build_base_result(
            ok=False,
            operation=operation,
            endpoint=endpoint,
            endpoint_mode=endpoint_mode,
            sent_utc=sent_utc,
            took_ms=took_ms,
            stderr="",
        )
        result["fault_reason"] = f"PFX file not found: {cert_pfx_path}"
        if pfx_material is not None:
            pfx_material.cleanup()
        return result

    cmd = [
        "java",
        *JAVA_ARGS,
        "-cp",
        CLASSPATH,
        JAVA_CLASS,
        "--operation",
        operation,
        "--endpoint",
        endpoint,
        "--out-dir",
        out_dir,
        "--pfx",
        cert_pfx_path,
        "--pfx-pass",
        cert_pfx_password,
        "--token",
        token or "",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        took_ms = int((time.perf_counter() - started) * 1000)
        result = _build_base_result(
            ok=False,
            operation=operation,
            endpoint=endpoint,
            endpoint_mode=endpoint_mode,
            sent_utc=sent_utc,
            took_ms=took_ms,
            stderr=(exc.stderr or "").strip(),
        )
        result["fault_reason"] = "Java bridge timed out"
        return result
    except Exception as exc:
        took_ms = int((time.perf_counter() - started) * 1000)
        result = _build_base_result(
            ok=False,
            operation=operation,
            endpoint=endpoint,
            endpoint_mode=endpoint_mode,
            sent_utc=sent_utc,
            took_ms=took_ms,
            stderr=str(exc),
        )
        result["fault_reason"] = "Failed to start Java bridge"
        return result
    finally:
        if pfx_material is not None:
            pfx_material.cleanup()

    took_ms = int((time.perf_counter() - started) * 1000)
    stderr = (proc.stderr or "").strip()

    base = _build_base_result(
        ok=proc.returncode == 0,
        operation=operation,
        endpoint=endpoint,
        endpoint_mode=endpoint_mode,
        sent_utc=sent_utc,
        took_ms=took_ms,
        stderr=stderr,
    )

    stdout = (proc.stdout or "").strip()
    base["bridge_stdout"] = stdout
    if stdout:
        payload = _extract_json_payload(stdout)
        if payload is None:
            base["fault_reason"] = f"Bridge returned non-JSON output: {stdout}"
            base["raw_output"] = stdout
        else:
            base.update(payload)
            base["engine"] = "java"
            base["operation"] = operation
            base["endpoint"] = endpoint
            base["endpoint_mode"] = endpoint_mode
            base["sent_utc"] = sent_utc
            base["took_ms"] = took_ms
            base["stderr"] = stderr
    else:
        base["fault_reason"] = "Bridge returned no output"

    if proc.returncode != 0:
        base["ok"] = False
        base["fault_reason"] = f"Java process exited with code {proc.returncode}"

    if operation == "GetInitialAddresseeRecordList":
        bundle_dir = make_bundle_dir(operation)
        engine_stdout_path = os.path.join(bundle_dir, "engine_stdout.json")
        engine_stdout_text_path = os.path.join(bundle_dir, "engine_stdout.txt")
        stderr_path = os.path.join(bundle_dir, "stderr.log")
        engine_result_path = os.path.join(bundle_dir, "engine_result.json")
        request_payload_path = os.path.join(bundle_dir, "request_payload.xml")
        response_payload_path = os.path.join(bundle_dir, "response_payload.xml")
        soap_request_path = os.path.join(bundle_dir, "soap_request.xml")
        soap_response_path = os.path.join(bundle_dir, "soap_response.xml")
        parsed_records_path = os.path.join(bundle_dir, "parsed_records.json")

        if _extract_json_payload(stdout) is not None:
            write_text(engine_stdout_path, stdout)
        else:
            write_text(engine_stdout_text_path, stdout)
        write_text(stderr_path, stderr)

        copy_file(base.get("request_saved_path"), request_payload_path)
        copy_file(base.get("response_saved_path"), response_payload_path)
        copy_file(base.get("soap_request_path"), soap_request_path)
        copy_file(base.get("soap_response_path"), soap_response_path)

        response_xml = load_xml(base.get("response_saved_path")) or load_xml(
            base.get("soap_response_path")
        )
        parsed_records = parse_addressee_records(response_xml)
        write_json(parsed_records_path, parsed_records)

        soap_xml = load_xml(base.get("soap_response_path")) or ""
        soap_assert = assert_soap_success(soap_xml)
        if not soap_assert["ok"]:
            base["ok"] = False
            base["fault_code"] = base.get("fault_code") or soap_assert["fault_code"]
            base["fault_reason"] = base.get("fault_reason") or soap_assert["fault_reason"]

        if stderr and "Exception" in stderr:
            base["ok"] = False
            base["fault_reason"] = base.get("fault_reason") or "Engine stderr contains Exception"

        base["request_saved_path"] = request_payload_path
        base["response_saved_path"] = response_payload_path
        base["parsed_saved_path"] = parsed_records_path
        base["soap_request_path"] = soap_request_path
        base["soap_response_path"] = soap_response_path

        write_json(engine_result_path, base)

    return base
