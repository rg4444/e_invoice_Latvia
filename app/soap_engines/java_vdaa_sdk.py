from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from soap_engines.cert_utils import resolve_pfx_material
from storage import load_config

JAVA_CLASS = "VdaaDivBridge"
JAVA_DIR = "/bridge/java/VdaaDivBridge"
JAVA_LIB = "/bridge/java/VdaaDivBridge/lib/*"
CLASSPATH = f"{JAVA_DIR}:{JAVA_LIB}"
JAVA_ARGS = [
    "--add-opens",
    "java.base/java.lang=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.util=ALL-UNNAMED",
    "-Dcom.sun.xml.bind.v2.bytecode.ClassTailor.noOptimize=true",
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
        "--timeout-seconds",
        str(timeout_s),
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
    if proc.returncode != 0:
        base["ok"] = False
        base["fault_reason"] = f"Java process exited with code {proc.returncode}"

    return base
