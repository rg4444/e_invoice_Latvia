import os, re, subprocess, shlex, glob, shutil
from typing import Dict, List, Tuple
from storage import load_config, save_config

OPENSSL = "openssl"
CURL = "curl"


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


def _is_pem(path: str) -> bool:
    try:
        txt = open(path, 'r', encoding='utf-8', errors='ignore').read()
        return "BEGIN" in txt
    except Exception:
        return False


def _key_is_encrypted(path: str) -> bool:
    try:
        txt = open(path, 'r', encoding='utf-8', errors='ignore').read()
        return "ENCRYPTED PRIVATE KEY" in txt or "BEGIN RSA PRIVATE KEY" in txt and "Proc-Type: 4,ENCRYPTED" in txt
    except Exception:
        return False


def diagnose(allow_decrypt: bool = False) -> Dict:
    cfg = load_config()
    issues = []
    suggestions = []
    facts = {
        "endpoint": cfg.get("endpoint",""),
        "client_cert": cfg.get("client_cert",""),
        "client_key": cfg.get("client_key",""),
        "ca_bundle": cfg.get("ca_bundle",""),
    }
    # 1) Paths exist?
    for k in ["client_cert","client_key","ca_bundle"]:
        v = facts.get(k,"")
        if v and not os.path.exists(v):
            issues.append(f"{k} path does not exist: {v}")
            suggestions.append(f"Place the file at {v} or update the Config paths.")
    # 2) Cert format?
    if facts["client_cert"] and os.path.exists(facts["client_cert"]) and not _is_pem(facts["client_cert"]):
        issues.append("Client certificate is not PEM.")
        suggestions.append("Convert .cer to PEM: openssl x509 -inform DER -in client.cer -out client.pem; then concatenate with chain to client_full.pem")

    # 3) Key format & encryption?
    dec_test_key = ""
    if facts["client_key"] and os.path.exists(facts["client_key"]):
        if not _is_pem(facts["client_key"]):
            issues.append("Private key is not PEM (likely DER/PKCS8).")
            suggestions.append("Convert to PEM: openssl pkcs8 -inform DER -in client.key -out client.key.pem")
        if _key_is_encrypted(facts["client_key"]):
            issues.append("Private key appears ENCRYPTED.")
            suggestions.append("Either provide key passphrase in Config or create a decrypted test key (client.key.decrypted.pem) for local testing only.")
            if allow_decrypt:
                dec_test_key = os.path.join(os.path.dirname(facts["client_key"]), "client.key.decrypted.pem")
                code, out, err = _run(f'{OPENSSL} pkey -in {shlex.quote(facts["client_key"])} -out {shlex.quote(dec_test_key)}')
                if code == 0:
                    facts["client_key"] = dec_test_key
                    suggestions.append(f"Decrypted test key created: {dec_test_key}")

    # 4) If cert_full missing, try assemble if cert + chain exist
    if facts["client_cert"] and "client_full.pem" in facts["client_cert"] and not os.path.exists(facts["client_cert"]):
        base_dir = os.path.dirname(facts["client_cert"])
        cert_pem = os.path.join(base_dir, "client.pem")
        chain_pem = facts["ca_bundle"] if facts["ca_bundle"] else os.path.join(base_dir, "chain.pem")
        if os.path.exists(cert_pem) and os.path.exists(chain_pem):
            try:
                open(facts["client_cert"], "w", encoding="utf-8").write(open(cert_pem).read()+"\n"+open(chain_pem).read())
                suggestions.append(f"Assembled client_full.pem from client.pem + chain.pem at {facts['client_cert']}")
            except Exception as e:
                issues.append(f"Failed to assemble client_full.pem: {e}")
                suggestions.append("Use Find & Convert to build client_full.pem")

    # 5) Verify chain
    verify_cmd = f"{OPENSSL} verify "
    if facts["ca_bundle"] and os.path.exists(facts["ca_bundle"]):
        verify_cmd += f"-CAfile {shlex.quote(facts['ca_bundle'])} "
    verify_cmd += shlex.quote(facts["client_cert"])
    code, out, err = _run(verify_cmd)
    chain_ok = (code == 0)
    if not chain_ok:
        issues.append("openssl verify failed")
        suggestions.append("Ensure correct CA chain in /data/certs/chain.pem (extract from .p7b using: openssl pkcs7 -print_certs -in chain.p7b -out chain.pem)")

    # 6) TLS probe with curl (include pass if provided)
    tls = {"ok": False, "http": "", "tls_log": ""}
    if facts["endpoint"] and facts["client_cert"] and facts["client_key"]:
        curl_cmd = f'{CURL} -v --cert {shlex.quote(facts["client_cert"])} --key {shlex.quote(facts["client_key"])} '
        if cfg.get("client_key_pass"):
            curl_cmd += f'--pass "pass:{cfg.get("client_key_pass")}" '
        if facts["ca_bundle"] and os.path.exists(facts["ca_bundle"]):
            curl_cmd += f'--cacert {shlex.quote(facts["ca_bundle"])} '
        curl_cmd += shlex.quote(facts["endpoint"])
        code, http, log = _run(curl_cmd)
        tls["ok"] = (code == 0)
        tls["http"] = http
        tls["tls_log"] = log
        if not tls["ok"]:
            # Parse common error
            if "unable to set private key file" in log:
                issues.append("TLS probe: private key not accepted (format or passphrase).")
                suggestions.append("If key is encrypted, set the passphrase in Config or create client.key.decrypted.pem via Diagnostics.")
            if "certificate verify failed" in log:
                issues.append("TLS probe: certificate verify failed (CA chain).")
                suggestions.append("Set CA bundle path to your chain.pem in Config.")
            if "handshake failure" in log or "alert handshake failure" in log:
                suggestions.append("Check that your client certificate is registered for this test endpoint and the chain is complete.")
    else:
        issues.append("Endpoint or cert/key not set. Fill Config fields and Save.")

    return {
        "facts": facts,
        "chain_verify": {"ok": chain_ok, "out": out, "err": err},
        "tls_probe": tls,
        "issues": issues,
        "suggestions": suggestions,
        "apply_suggestion": True if suggestions else False,
    }


def auto_fix() -> Dict:
    """
    - Convert .cer → client.pem if needed
    - Extract .p7b → chain.pem if found
    - Concatenate client.pem + chain.pem → client_full.pem
    - Does NOT guess passphrases; user can decrypt via Diagnostics with prompt.
    """
    cfg = load_config()
    cert_dir = os.path.dirname(cfg.get("client_cert","/data/certs/client_full.pem")) or "/data/certs"
    key_dir = os.path.dirname(cfg.get("client_key","/data/certs/client.key")) or "/data/certs"

    # locate materials
    cer = next((p for p in glob.glob(os.path.join(cert_dir, "*.cer"))), "")
    p7b = next((p for p in glob.glob(os.path.join(cert_dir, "*.p7b"))), "")
    client_pem = os.path.join(cert_dir, "client.pem")
    chain_pem = os.path.join(cert_dir, "chain.pem")
    client_full = os.path.join(cert_dir, "client_full.pem")

    outputs = {}

    # .cer → client.pem if not PEM
    if cer and not os.path.exists(client_pem):
        code, out, err = _run(f"{OPENSSL} x509 -inform DER -in {shlex.quote(cer)} -out {shlex.quote(client_pem)}")
        outputs["cer_to_pem"] = {"ok": code == 0, "err": err, "out": client_pem}
    elif os.path.exists(client_pem):
        outputs["cer_to_pem"] = {"ok": True, "note": "client.pem already exists"}

    # .p7b → chain.pem
    if p7b and not os.path.exists(chain_pem):
        code, out, err = _run(f"{OPENSSL} pkcs7 -print_certs -in {shlex.quote(p7b)} -out {shlex.quote(chain_pem)}")
        outputs["p7b_to_chain"] = {"ok": code == 0, "err": err, "out": chain_pem}
    elif os.path.exists(chain_pem):
        outputs["p7b_to_chain"] = {"ok": True, "note": "chain.pem already exists"}

    # concat → client_full.pem
    if os.path.exists(client_pem):
        try:
            with open(client_full, "w", encoding="utf-8") as f:
                f.write(open(client_pem, "r", encoding="utf-8").read())
                if os.path.exists(chain_pem):
                    f.write("\n")
                    f.write(open(chain_pem, "r", encoding="utf-8").read())
            outputs["concat"] = {"ok": True, "out": client_full}
        except Exception as e:
            outputs["concat"] = {"ok": False, "err": str(e)}
    else:
        outputs["concat"] = {"ok": False, "err": "client.pem not present"}

    # apply to config
    cfg["client_cert"] = client_full
    save_config(cfg)
    return {"ok": True, "outputs": outputs, "applied_paths": {"client_cert": cfg["client_cert"]}}
