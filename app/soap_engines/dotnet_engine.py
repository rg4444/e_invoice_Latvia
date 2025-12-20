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


def _bridge_path(cfg: dict[str, Any]) -> str:
    return (cfg.get("DOTNET_BRIDGE_PATH") or os.getenv("DOTNET_BRIDGE_PATH") or "").strip()


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
        "engine": "dotnet",
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


def call_dotnet(
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

    bridge = _bridge_path(cfg)
    if not bridge or not os.path.exists(bridge):
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
        result["fault_reason"] = "DOTNET_BRIDGE_PATH is not configured or does not exist"
        return result

    cmd = [
        bridge,
        "--operation",
        operation,
        "--endpoint",
        endpoint,
        "--out-dir",
        out_dir,
    ]
    if token:
        cmd.extend(["--token", token])

    cert_pfx = (cfg.get("DOTNET_CERT_PFX_PATH") or os.getenv("DOTNET_CERT_PFX_PATH") or "").strip()
    cert_pass = (
        cfg.get("DOTNET_CERT_PFX_PASSWORD")
        or os.getenv("DOTNET_CERT_PFX_PASSWORD")
        or ""
    )
    if cert_pfx:
        cmd.extend(["--cert-pfx", cert_pfx])
    if cert_pass:
        cmd.extend(["--cert-pass", cert_pass])

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
        result["fault_reason"] = "Failed to start .NET bridge"
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
                base["engine"] = "dotnet"
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
