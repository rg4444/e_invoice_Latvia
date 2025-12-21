from __future__ import annotations

import json
import os
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
from storage import load_config


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bridge_dir(cfg: dict[str, Any]) -> str:
    return (cfg.get("JAVA_BRIDGE_DIR") or os.getenv("JAVA_BRIDGE_DIR") or "").strip()


def _bridge_main(cfg: dict[str, Any]) -> str:
    return (cfg.get("JAVA_BRIDGE_MAIN") or os.getenv("JAVA_BRIDGE_MAIN") or "VdaaDivBridge").strip()


def _bridge_lib_dir(cfg: dict[str, Any]) -> str:
    return (cfg.get("JAVA_BRIDGE_LIB_DIR") or os.getenv("JAVA_BRIDGE_LIB_DIR") or "").strip()


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


def call_java(
    operation: str,
    token: str,
    endpoint: str,
    out_dir: str,
    *,
    endpoint_mode: str = "normal",
    **_: Any,
) -> dict[str, Any]:
    cfg = load_config()
    sent_utc = _utc_now_iso()
    started = time.perf_counter()

    bridge_dir = _bridge_dir(cfg)
    if not bridge_dir:
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
        result["fault_reason"] = "JAVA_BRIDGE_DIR is not configured"
        return result

    lib_dir = _bridge_lib_dir(cfg) or os.path.join(bridge_dir, "lib")
    if not os.path.isdir(lib_dir):
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
        result["fault_reason"] = "Java bridge lib directory not found"
        return result

    classpath = os.path.join(lib_dir, "*") + os.pathsep + bridge_dir
    main_class = _bridge_main(cfg)

    cmd = [
        "java",
        "-cp",
        classpath,
        main_class,
        "--operation",
        operation,
        "--endpoint",
        endpoint,
        "--out-dir",
        out_dir,
    ]
    if token:
        cmd.extend(["--token", token])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
    if stdout:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            base["fault_reason"] = "Bridge returned non-JSON output"
        else:
            if isinstance(payload, dict):
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
        if not base.get("fault_reason"):
            base["fault_reason"] = "Bridge process failed"

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

        if stdout:
            try:
                json.loads(stdout)
            except json.JSONDecodeError:
                write_text(engine_stdout_text_path, stdout)
            else:
                write_text(engine_stdout_path, stdout)
        else:
            write_text(engine_stdout_text_path, "")
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
