from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

JAVA_CLASS = "VdaaDivBridge"
JAVA_DIR = "/bridge/java/VdaaDivBridge"
JAVA_LIB = "/bridge/java/VdaaDivBridge/lib/*"
CLASSPATH = f"{JAVA_DIR}:{JAVA_LIB}"


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

    cmd = [
        "java",
        "-cp",
        CLASSPATH,
        JAVA_CLASS,
        "--operation",
        operation,
        "--endpoint",
        endpoint,
        "--out-dir",
        out_dir,
        "--config",
        config_path,
    ]
    if token:
        cmd.extend(["--token", token])
    if cert_pfx_path:
        cmd.extend(["--pfx", cert_pfx_path])
    if cert_pfx_password:
        cmd.extend(["--pfx-pass", cert_pfx_password])

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
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            base["fault_reason"] = f"Bridge returned non-JSON output: {stdout}"
            base["raw_output"] = stdout
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
