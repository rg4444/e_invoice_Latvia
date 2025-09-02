import os, ssl, requests, shlex, subprocess, tempfile
from typing import Tuple
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from lxml import etree

CURL = "curl"

class SSLContextAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, ssl_context=self.ssl_context)

def build_session_with_sslcontext(endpoint: str, client_cert: str, client_key: str, key_pass: str):
    """
    Build requests.Session using system CAs (public trust) + mTLS (client cert/key).
    IMPORTANT: We *do not* load custom CA bundle here to avoid replacing system roots.
    """
    ctx = ssl.create_default_context()  # system CAs
    pwd = key_pass or None
    if client_cert and client_key:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key, password=pwd)

    s = requests.Session()
    s.mount("https://", SSLContextAdapter(ctx))
    s.mount("http://", HTTPAdapter())
    s.headers.update({"User-Agent": "e-rekini-tester/1.0"})
    return s

def http_get(session: requests.Session, url: str) -> Tuple[int, dict, bytes, str]:
    try:
        r = session.get(url, timeout=30)
        return r.status_code, dict(r.headers), r.content, ""
    except Exception as e:
        return -1, {}, b"", str(e)

def try_parse_wsdl(content: bytes) -> Tuple[bool, str]:
    try:
        doc = etree.fromstring(content)
        if b"definitions" in content or doc.tag.endswith("definitions"):
            return True, "WSDL/definitions element found"
        return False, "XML parsed but no <definitions> found"
    except Exception as e:
        return False, f"XML parse error: {e}"

def curl_fetch_wsdl(url: str, client_cert: str, client_key: str, key_pass: str = "") -> Tuple[int, str, str, bytes]:
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        out_file = tf.name
    cmd = f'{CURL} -sS -D - '
    if client_cert:
        cmd += f' --cert {shlex.quote(client_cert)}'
    if client_key:
        cmd += f' --key {shlex.quote(client_key)}'
    if key_pass:
        cmd += f' --pass "pass:{shlex.quote(key_pass)}"'
    cmd += f' -o {shlex.quote(out_file)} {shlex.quote(url)}'

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    raw_headers, err = p.communicate()
    code = p.returncode
    body = b""
    try:
        with open(out_file, "rb") as f:
            body = f.read()
    finally:
        try: os.remove(out_file)
        except Exception: pass

    status = 0
    if raw_headers:
        for line in raw_headers.splitlines():
            if line.startswith("HTTP/"):
                try: status = int(line.split()[1])
                except Exception: status = 0
    return status, raw_headers, err, body
