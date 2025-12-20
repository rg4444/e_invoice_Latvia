from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

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
    elif proc.returncode != 0:
        base["fault_reason"] = "Bridge returned no output"

    if proc.returncode != 0:
        base["ok"] = False
        if not base.get("fault_reason"):
            base["fault_reason"] = "Bridge process failed"

    return base
