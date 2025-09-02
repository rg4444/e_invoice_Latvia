import os, re, subprocess, shlex, glob, shutil
from typing import Dict, List, Tuple

OPENSSL = "openssl"


def _run(cmd: str) -> Tuple[int, str, str]:
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out.strip(), err.strip()


def scan_for_materials(search_dir: str) -> Dict[str, List[str]]:
    patterns = {
        "keys": ["*.key", "*.pem"],
        "certs": ["*.cer", "*.crt", "*.pem"],
        "p7b": ["*.p7b", "*.p7c"],
    }
    found = {k: [] for k in patterns}
    for k, pats in patterns.items():
        for pat in pats:
            found[k].extend(glob.glob(os.path.join(search_dir, pat)))
    for k in found:
        found[k] = sorted(list(dict.fromkeys(found[k])))
    return found


def convert_cer_to_pem(cer_path: str, out_pem: str) -> Dict:
    try:
        with open(cer_path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
            if "BEGIN CERTIFICATE" in txt:
                open(out_pem, "w", encoding="utf-8").write(txt)
                return {"ok": True, "note": "input already PEM", "out": out_pem}
    except Exception:
        pass
    code, out, err = _run(f"{OPENSSL} x509 -inform DER -in {shlex.quote(cer_path)} -out {shlex.quote(out_pem)}")
    return {"ok": code == 0, "out": out_pem, "err": err}


def extract_chain_from_p7b(p7b_path: str, out_pem: str) -> Dict:
    code, out, err = _run(f"{OPENSSL} pkcs7 -print_certs -in {shlex.quote(p7b_path)} -out {shlex.quote(out_pem)}")
    return {"ok": code == 0, "out": out_pem, "err": err}


def concat_cert_chain(cert_pem: str, chain_pem: str, out_full: str) -> Dict:
    try:
        with open(out_full, "w", encoding="utf-8") as f_out:
            f_out.write(open(cert_pem, "r", encoding="utf-8").read())
            if os.path.exists(chain_pem):
                f_out.write("\n")
                f_out.write(open(chain_pem, "r", encoding="utf-8").read())
        return {"ok": True, "out": out_full}
    except Exception as e:
        return {"ok": False, "err": str(e)}


def make_p12(key_path: str, cert_pem: str, chain_pem: str, out_p12: str, password: str = "") -> Dict:
    cmd = f"{OPENSSL} pkcs12 -export -inkey {shlex.quote(key_path)} -in {shlex.quote(cert_pem)} -out {shlex.quote(out_p12)}"
    if chain_pem and os.path.exists(chain_pem):
        cmd += f" -certfile {shlex.quote(chain_pem)}"
    if password:
        cmd += f" -passout pass:{shlex.quote(password)}"
    else:
        cmd += " -passout pass:"
    code, out, err = _run(cmd)
    return {"ok": code == 0, "out": out_p12, "err": err}


def verify_chain(cert_full_pem: str, ca_bundle: str = "") -> Dict:
    if ca_bundle and os.path.exists(ca_bundle):
        cmd = f"{OPENSSL} verify -CAfile {shlex.quote(ca_bundle)} {shlex.quote(cert_full_pem)}"
    else:
        cmd = f"{OPENSSL} verify {shlex.quote(cert_full_pem)}"
    code, out, err = _run(cmd)
    return {"ok": code == 0, "out": out, "err": err}


def tls_probe(url: str, cert_full_pem: str, key_path: str, ca_bundle: str = "") -> Dict:
    curl = "curl"
    if not shutil.which(curl):
        return {"ok": False, "err": "curl not present in container"}
    cmd = f'{curl} -v --cert {shlex.quote(cert_full_pem)} --key {shlex.quote(key_path)} '
    if ca_bundle and os.path.exists(ca_bundle):
        cmd += f'--cacert {shlex.quote(ca_bundle)} '
    cmd += shlex.quote(url)
    code, out, err = _run(cmd)
    return {"ok": code == 0, "http": out, "tls_log": err}
