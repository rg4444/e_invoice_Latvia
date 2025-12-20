from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any


@dataclass
class PfxMaterial:
    path: str | None
    password: str | None
    cleanup_path: str | None = None

    def cleanup(self) -> None:
        if not self.cleanup_path:
            return
        try:
            os.remove(self.cleanup_path)
        except OSError:
            pass


def resolve_pfx_material(
    cfg: dict[str, Any],
    *,
    preserve_tmp: bool = False,
) -> PfxMaterial:
    pfx_path = (cfg.get("client_p12") or "").strip() or None
    pfx_password = (cfg.get("p12_password") or "").strip() or None
    if pfx_path:
        return PfxMaterial(path=pfx_path, password=pfx_password)

    cert_path = (cfg.get("client_cert") or "").strip()
    key_path = (cfg.get("client_key") or "").strip()
    if not cert_path or not key_path:
        return PfxMaterial(path=None, password=None)

    key_pass = (cfg.get("client_key_pass") or "").strip()
    password = secrets.token_urlsafe(18)
    fd, temp_path = tempfile.mkstemp(prefix="client_", suffix=".pfx")
    os.close(fd)

    cmd = [
        "openssl",
        "pkcs12",
        "-export",
        "-inkey",
        key_path,
        "-in",
        cert_path,
        "-out",
        temp_path,
        "-passout",
        f"pass:{password}",
    ]
    if key_pass:
        cmd.extend(["-passin", f"pass:{key_pass}"])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "Failed to generate PFX").strip())

    cleanup_path = None if preserve_tmp else temp_path
    return PfxMaterial(path=temp_path, password=password, cleanup_path=cleanup_path)
