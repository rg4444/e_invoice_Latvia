import os, logging, base64, uuid, time, json, subprocess
from datetime import datetime
from fastapi import FastAPI, Request, Form, Query, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from dotenv import load_dotenv
from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
import requests
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse
from urllib.parse import quote

from storage import load_config, save_config
from ubl import read_reference_invoice, build_invoice_xml, parse_invoice_to_form
from wsdl_utils import http_get, try_parse_wsdl, curl_fetch_wsdl
from wsdl_body import build_body_template
from tools import (
    scan_for_materials,
    convert_cer_to_pem,
    extract_chain_from_p7b,
    concat_cert_chain,
    make_p12,
    verify_chain,
    tls_probe,
    diagnose,
    auto_fix,
    gen_rsa_key_and_csr,
    file_download_response,
)
from validation import validate_xsd
from utils_attachments import read_file_b64, new_content_id
from soap_client import send_invoice, send_raw_envelope
from lxml import etree
from schematron import run_schematron
from kosit_runner import run_kosit

INVOICE_DIR = "/data/invoices"
SAMPLES_DIR = "/data/samples"
XSD_DIR = "/data/xsd"
SCHEMATRON_DIR = "/data/schematron"

os.makedirs(INVOICE_DIR, exist_ok=True)

load_dotenv()
LOG_DIR = "/data/logs"
KOSIT_OUT_BASE = "/data/logs/kosit"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(KOSIT_OUT_BASE, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "app.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-me"),
    same_site="lax",
)
app.mount("/static", StaticFiles(directory="static"), name="static")
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"])
)

# In-memory invoice editor state
INVOICE_XML = ""
DEFAULT_INVOICE = os.getenv("DEFAULT_INVOICE", os.path.join(SAMPLES_DIR, "einvoice_reference.xml"))
CHUNK_STATE = {}

@app.on_event("startup")
def load_defaults():
    global INVOICE_XML
    if DEFAULT_INVOICE and os.path.isfile(DEFAULT_INVOICE):
        INVOICE_XML = open(DEFAULT_INVOICE, "r", encoding="utf-8").read()

def render(tpl, request: Request, **ctx):
    return HTMLResponse(env.get_template(tpl).render(request=request, **ctx))


def _safe_next(target: str | None) -> str:
    if not target:
        return "/"
    if target.startswith("/"):
        return target
    return "/"


LOGIN_EXEMPT_PATHS = {"/login"}


class LoginRequiredMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        session = request.scope.get("session")
        if session is None:
            session = {}
            request.scope["session"] = session

        if path.startswith("/static") or path in LOGIN_EXEMPT_PATHS:
            return await call_next(request)

        if session.get("user"):
            return await call_next(request)

        if request.method.upper() == "GET":
            next_path = path
            if request.url.query:
                next_path = f"{next_path}?{request.url.query}"
            redirect_url = f"/login?next={quote(next_path)}"
            return RedirectResponse(url=redirect_url, status_code=303)

        return JSONResponse({"detail": "Not authenticated"}, status_code=401)


app.add_middleware(LoginRequiredMiddleware)


def _list_xsd_entrypoints():
    entries = []
    for root, _, files in os.walk(XSD_DIR):
        for f in files:
            if f.lower().endswith(".xsd"):
                if "Invoice-2.1" in f or "CreditNote-2.1" in f or "maindoc" in root:
                    entries.append(os.path.join(root, f))
    entries = sorted(set(entries))
    if not entries:
        for root, _, files in os.walk(XSD_DIR):
            for f in files:
                if f.lower().endswith(".xsd"):
                    entries.append(os.path.join(root, f))
        entries = sorted(set(entries))
    return entries


def _is_svrl_stylesheet(path: str) -> bool:
    """Return True when the XSLT produces SVRL rather than an HTML preview."""

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            snippet = fh.read(4096)
    except OSError:
        return False

    # Compiled Schematron stylesheets always declare the SVRL namespace.
    if "http://purl.oclc.org/dsdl/svrl" in snippet:
        return True

    # Some viewers declare HTML output, so explicitly exclude those when we
    # have a better option available.
    if "<xsl:output" in snippet and "method=\"html\"" in snippet:
        return False

    return False


def _list_rulesets():
    # pick schematron files under data/schematron**
    xslt = []
    fallback = []
    schematron_sources = []
    for root, _, files in os.walk(SCHEMATRON_DIR):
        for f in files:
            lower = f.lower()
            path = os.path.join(root, f)
            if lower.endswith((".xsl", ".xslt")):
                if _is_svrl_stylesheet(path):
                    xslt.append(path)
                else:
                    fallback.append(path)
            elif lower.endswith(".sch"):
                schematron_sources.append(path)
    if xslt:
        return sorted(xslt) + sorted(schematron_sources)
    if schematron_sources:
        return sorted(schematron_sources) + sorted(fallback)
    return sorted(fallback)


def _list_invoices():
    if not os.path.isdir(INVOICE_DIR):
        return []
    return sorted([os.path.join(INVOICE_DIR, f) for f in os.listdir(INVOICE_DIR) if f.lower().endswith(".xml")])

@app.get("/schematron/list")
def schematron_list():
    return JSONResponse({"ok": True, "rulesets": _list_rulesets()})


@app.get("/schematron/invoices")
def schematron_invoices():
    return JSONResponse({"ok": True, "invoices": _list_invoices()})


@app.post("/schematron/validate")
async def schematron_validate(
    ruleset_path: str = Form(...),
    invoice_xml: str | None = Form(None),
    invoice_path: str | None = Form(None),
    invoice_file: UploadFile | None = File(None),
):
    xml_text = None
    invoice_label = "Editor XML"

    if invoice_xml:
        xml_text = invoice_xml
    elif invoice_path:
        abs_dir = os.path.abspath(INVOICE_DIR)
        abs_path = os.path.abspath(invoice_path)
        if not abs_path.startswith(abs_dir + os.sep) and abs_path != abs_dir:
            raise HTTPException(status_code=400, detail="Invoice path outside invoices directory")
        if not os.path.isfile(abs_path):
            raise HTTPException(status_code=404, detail="Invoice file not found")
        with open(abs_path, "r", encoding="utf-8") as f:
            xml_text = f.read()
        invoice_label = os.path.basename(abs_path) or "Selected invoice"
    elif invoice_file is not None:
        try:
            xml_bytes = await invoice_file.read()
            xml_text = xml_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid XML encoding: {exc}")
        invoice_label = invoice_file.filename or "Uploaded invoice"

    if not xml_text:
        raise HTTPException(status_code=400, detail="No invoice XML provided")

    ok, svrl, issues = run_schematron(xml_text, ruleset_path)
    ruleset_label = os.path.basename(ruleset_path) or "Selected ruleset"

    payload: dict[str, object] = {"ok": ok, "issues": issues, "svrl": svrl, "invoice_name": invoice_label, "ruleset_name": ruleset_label}

    if not ok:
        readable_issues = issues or ["No additional details were provided."]
        header = (
            f"Schematron rules validation failed while checking {invoice_label} "
            f"against schema {ruleset_label}."
        )
        lines = [header, "", "Following error(s) appear:"] + [f"- {item}" for item in readable_issues]
        lines.extend(["", "----- Invoice Content -----", xml_text])
        report_text = "\n".join(lines)
        payload["report"] = {
            "header": header,
            "errors": readable_issues,
            "invoice_content": xml_text,
            "text": report_text,
            "filename": f"schematron-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt",
        }

    return JSONResponse(payload)

@app.get("/kosit", response_class=HTMLResponse)
def kosit_page(request: Request):
    invoices = _list_invoices()
    conf = {
        # Default jar path points to the shared /data volume so the validator
        # can be updated without rebuilding the container image.
        "jar": os.environ.get("KOSIT_JAR", "/data/kosit/bin/validator-1.5.2-standalone.jar"),
        "conf_dir": os.environ.get("KOSIT_CONF_DIR", "/data/kosit/bis")
    }
    return render("kosit.html", request, invoices=invoices, conf=conf)

@app.post("/kosit/validate")
def kosit_validate(invoice_path: str = Form(...), html_report: str = Form("true")):
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(KOSIT_OUT_BASE, ts)
    res = run_kosit(invoice_path, out_dir, html_report.lower() == "true")
    return JSONResponse(res)



def _log_div_call(operation: str, req_xml: str, resp_xml: str, took_ms: int, cfg: dict):
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, "div.log")
    tls = {
        "client_cert": cfg.get("client_cert", ""),
        "client_key": cfg.get("client_key", ""),
        "ca_bundle": cfg.get("ca_bundle", ""),
    }
    with open(path, "a", encoding="utf-8") as f:
        ts = datetime.utcnow().isoformat()
        f.write(f"{ts} {operation} {took_ms}ms\n")
        f.write(f"TLS: {tls}\n")
        f.write("Request:\n")
        f.write(req_xml + "\n")
        f.write("Response:\n")
        f.write(resp_xml + "\n\n")


def _wsdl_session(cfg):
    s = Session()
    cert = (cfg.get("client_cert"), cfg.get("client_key"))
    if all(cert):
        s.cert = cert
    s.verify = True  # use system CA store
    return s


def _op_namespace(op, client):
    """
    Prefer the operation input body type QName namespace.
    Fallback to the WSDL target namespace (client.wsdl.tns).
    """
    try:
        body = getattr(op.input, "body", None)
        if body is not None:
            tp = getattr(body, "type", None)
            qn = getattr(tp, "qname", None)
            if qn is not None and getattr(qn, "namespace", None):
                return qn.namespace
    except Exception:
        pass
    # Fallback
    try:
        return client.wsdl.tns
    except Exception:
        return None


@app.get("/cert", response_class=HTMLResponse)
def certgen_page(request: Request):
    defaults = {
        "out_dir": "/data/certs",
        "base_name": "client",
        "country": "LV",
        "state": "Riga",
        "locality": "Riga",
        "org": "Organization Name",
        "org_unit": "IT",
        "common_name": "your.company.lv",
        "email": "it@example.com",
        "bits": 2048,
        "key_passphrase": "",
    }
    return render("certgen.html", request, defaults=defaults)


@app.post("/cert/generate")
def certgen_generate(
    out_dir: str = Form("/data/certs"),
    base_name: str = Form("client"),
    country: str = Form("LV"),
    state: str = Form("Riga"),
    locality: str = Form("Riga"),
    org: str = Form("Organization Name"),
    org_unit: str = Form("IT"),
    common_name: str = Form("your.company.lv"),
    email: str = Form("it@example.com"),
    bits: int = Form(2048),
    key_passphrase: str = Form(""),
):
    res = gen_rsa_key_and_csr(
        out_dir=out_dir,
        base_name=base_name,
        country=country,
        state=state,
        locality=locality,
        org=org,
        org_unit=org_unit,
        common_name=common_name,
        email=email,
        bits=bits,
        key_passphrase=key_passphrase,
    )
    return JSONResponse(res)


@app.get("/cert/download")
def cert_download(path: str = Query(...)):
    try:
        return file_download_response(path)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    cfg = load_config()
    return render("config.html", request, cfg=cfg)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str | None = Query(None)):
    if request.session.get("user"):
        return RedirectResponse(url=_safe_next(next), status_code=303)
    return render("login.html", request, next=_safe_next(next))


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/"),
):
    cfg = load_config()
    credentials = cfg.get("auth_credentials") or []
    valid = any(
        cred.get("username") == username and cred.get("password") == password
        for cred in credentials
    )
    if valid:
        request.session["user"] = username
        return RedirectResponse(url=_safe_next(next), status_code=303)
    error = "Invalid username or password"
    return render(
        "login.html",
        request,
        error=error,
        next=_safe_next(next),
        username=username,
    )


@app.get("/logout")
def logout(request: Request, next: str | None = Query(None)):
    request.session.clear()
    target = _safe_next(next)
    if target == "/":
        target = "/login"
    return RedirectResponse(url=target, status_code=303)

@app.post("/save-config")
def save_config_route(
    endpoint: str = Form(""), soap_action: str = Form(""),
    soap_version: str = Form("1.2"), use_ws_addressing: bool = Form(False),
    wsse_mode: str = Form("username"),
    username: str = Form(""), password: str = Form(""),
    client_cert: str = Form(""), client_key: str = Form(""),
    client_key_pass: str = Form(""),
    client_p12: str = Form(""), p12_password: str = Form(""),
    verify_tls: bool = Form(False), ca_bundle: str = Form(""),
    schema_path: str = Form(""), success_indicator: str = Form("Success"),
    auth_credentials: str = Form("[]"),
):
    cfg = load_config()
    parsed_credentials: list[dict[str, str]] = []
    try:
        payload = json.loads(auth_credentials)
        if isinstance(payload, list):
            for cred in payload:
                if not isinstance(cred, dict):
                    continue
                user = str(cred.get("username", "")).strip()
                password_value = str(cred.get("password", ""))
                if user:
                    parsed_credentials.append({"username": user, "password": password_value})
    except json.JSONDecodeError:
        parsed_credentials = cfg.get("auth_credentials", [])
    cfg.update({
        "endpoint": endpoint.strip(),
        "soap_action": soap_action.strip(),
        "soap_version": soap_version.strip(),
        "use_ws_addressing": use_ws_addressing,
        "wsse_mode": wsse_mode,
        "username": username,
        "password": password,
        "client_cert": client_cert.strip(),
        "client_key": client_key.strip(),
        "client_key_pass": client_key_pass,
        "client_p12": client_p12.strip(),
        "p12_password": p12_password,
        "verify_tls": verify_tls,
        "ca_bundle": ca_bundle.strip(),
        "schema_path": schema_path.strip(),
        "success_indicator": success_indicator.strip(),
        "auth_credentials": parsed_credentials,
    })
    save_config(cfg)
    return JSONResponse({"status": "ok"})


@app.post("/tools/diagnose")
async def tools_diagnose(allow_decrypt: bool = Form(False)):
    report = diagnose(allow_decrypt=allow_decrypt)
    return JSONResponse(report)


@app.post("/tools/auto-fix")
async def tools_auto_fix():
    res = auto_fix()
    return JSONResponse(res)

@app.post("/tools/find-convert")
async def find_convert(
    dir: str = Form("/data/certs"),
    out: str = Form("/data/certs"),
    mkp12: bool = Form(False),
    p12pass: str = Form(""),
):
    os.makedirs(out, exist_ok=True)
    found = scan_for_materials(dir)

    key = next((p for p in found["keys"] if p.lower().endswith(".key")), "")
    cer = next((p for p in found["certs"] if p.lower().endswith((".cer", ".crt"))), "")
    pem = next((p for p in found["certs"] if p.lower().endswith(".pem")), "")
    p7b = next((p for p in found["p7b"]), "")

    outputs = {}
    client_pem = os.path.join(out, "client.pem")
    chain_pem = os.path.join(out, "chain.pem")
    client_full = os.path.join(out, "client_full.pem")
    client_p12 = os.path.join(out, "client.p12")

    steps = []

    if cer:
        steps.append({"step": "cer->pem", "in": cer})
        r = convert_cer_to_pem(cer, client_pem)
        outputs["cer_to_pem"] = r
    elif pem:
        open(client_pem, "w", encoding="utf-8").write(
            open(pem, "r", encoding="utf-8").read()
        )
        outputs["pem_copy"] = {"ok": True, "out": client_pem}
    else:
        return JSONResponse({
            "ok": False,
            "error": "No client certificate (.cer/.crt/.pem) found",
            "found": found,
        })

    if p7b:
        steps.append({"step": "p7b->chain.pem", "in": p7b})
        r = extract_chain_from_p7b(p7b, chain_pem)
        outputs["p7b_to_chain"] = r

    steps.append({"step": "concat", "in": [client_pem, chain_pem]})
    r = concat_cert_chain(
        client_pem, chain_pem if os.path.exists(chain_pem) else "", client_full
    )
    outputs["concat"] = r

    if mkp12 and key and os.path.exists(client_pem):
        steps.append({"step": "p12_export", "in": [key, client_pem, chain_pem]})
        r = make_p12(
            key,
            client_pem,
            chain_pem if os.path.exists(chain_pem) else "",
            client_p12,
            p12pass,
        )
        outputs["p12"] = r

    cfg = load_config()
    config_applied = False
    if key and os.path.exists(client_full):
        cfg["client_cert"] = client_full
        cfg["client_key"] = key
        if os.path.exists(chain_pem):
            cfg["ca_bundle"] = chain_pem
        save_config(cfg)
        config_applied = True

    return JSONResponse(
        {
            "ok": True,
            "found": found,
            "outputs": outputs,
            "steps": steps,
            "applied_paths": {
                "client_cert": cfg.get("client_cert", ""),
                "client_key": cfg.get("client_key", ""),
                "ca_bundle": cfg.get("ca_bundle", ""),
            },
            "config_applied": config_applied,
        }
    )


@app.post("/tools/verify")
async def tools_verify():
    cfg = load_config()
    client_full = cfg.get("client_cert", "")
    key = cfg.get("client_key", "")
    ca = cfg.get("ca_bundle", "")
    endpoint = cfg.get("endpoint", "")

    res = {"chain_verify": None, "tls_probe": None}

    if client_full and os.path.exists(client_full):
        res["chain_verify"] = verify_chain(client_full, ca)
    else:
        res["chain_verify"] = {"ok": False, "err": "client_full.pem not set or missing"}

    if endpoint and client_full and key:
        try:
            res["tls_probe"] = tls_probe(endpoint, client_full, key, ca)
        except Exception as e:
            res["tls_probe"] = {"ok": False, "err": str(e)}
    else:
        res["tls_probe"] = {"ok": False, "err": "endpoint or cert/key missing in config"}

    return JSONResponse(res)

@app.get("/invoice", response_class=HTMLResponse)
def invoice_unified_page(request: Request):
    cfg = load_config()
    ref_path = os.getenv("DEFAULT_INVOICE", os.path.join(SAMPLES_DIR, "einvoice_reference.xml"))
    ref = read_reference_invoice(ref_path)
    xsds = _list_xsd_entrypoints()
    return render("invoice_unified.html", request, prefill=ref, xsds=xsds, cfg=cfg, ref_path=ref_path)

@app.post("/invoice/generate")
def invoice_generate(payload: str = Form(...), save: str = Form("true"), filename: str = Form("")):
    data = json.loads(payload)
    xml_bytes = build_invoice_xml(data)
    out = None
    if save.lower() == "true":
        ts = time.strftime("%Y%m%d-%H%M%S")
        name = filename.strip() or f"invoice-{ts}.xml"
        out = os.path.join(INVOICE_DIR, name)
        with open(out, "wb") as f:
            f.write(xml_bytes)
    return JSONResponse({"ok": True, "saved_to": out, "xml": xml_bytes.decode("utf-8")})

@app.post("/invoice/validate")
def invoice_validate(xml_text: str = Form(...), xsd_path: str = Form(...)):
    try:
        xml_doc = etree.fromstring(xml_text.encode("utf-8"))
    except Exception as e:
        return JSONResponse({"ok": False, "stage": "parse", "error": str(e)}, status_code=400)
    try:
        parser = etree.XMLParser(resolve_entities=False)
        with open(xsd_path, "rb") as f:
            schema_doc = etree.parse(f, parser)
        schema = etree.XMLSchema(schema_doc)
        schema.assertValid(xml_doc)
        return JSONResponse({"ok": True, "message": "XSD validation passed"})
    except etree.DocumentInvalid as e:
        errs = [str(err) for err in schema.error_log] if 'schema' in locals() else [str(e)]
        return JSONResponse({"ok": False, "stage": "xsd", "errors": errs}, status_code=422)
    except Exception as e:
        return JSONResponse({"ok": False, "stage": "xsd-load", "error": str(e)}, status_code=400)

@app.get("/invoices", response_class=HTMLResponse)
def invoices_page(request: Request):
    files = []
    if os.path.isdir(INVOICE_DIR):
        for fn in sorted(os.listdir(INVOICE_DIR)):
            if fn.lower().endswith(".xml"):
                p = os.path.join(INVOICE_DIR, fn)
                stat = os.stat(p)
                files.append({
                    "name": fn,
                    "path": p,
                    "size": stat.st_size,
                    "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                })
    return render("invoices.html", request, files=files)


@app.post("/fetch-schemas")
def fetch_schemas():
    try:
        script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools", "fetch_schemas.py"))
        subprocess.run(["python", script], check=True)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.post("/invoice/upload")
async def invoice_upload(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".xml"):
        return JSONResponse({"ok": False, "error": "Only XML files allowed"}, status_code=400)
    content = await file.read()
    data = parse_invoice_to_form(content)
    return JSONResponse({"ok": True, "form": data, "filename": file.filename})

@app.get("/invoice/download")
def invoice_download(path: str):
    base = os.path.abspath(INVOICE_DIR)
    p = os.path.abspath(path)
    if not p.startswith(base) or not os.path.exists(p):
        return JSONResponse({"ok": False, "error": "Invalid path"}, status_code=400)
    return FileResponse(p, filename=os.path.basename(p), media_type="application/xml")

@app.post("/invoice/set")
async def invoice_set(request: Request):
    global INVOICE_XML
    data = await request.json()
    INVOICE_XML = data.get("xml", "")
    return JSONResponse({"status": "ok", "len": len(INVOICE_XML)})


@app.get("/wsdlui", response_class=HTMLResponse)
def wsdl_ui(request: Request):
    return render("wsdlui.html", request, cfg=load_config())


@app.post("/wsdl/load")
def wsdl_load(url: str = Form(""), prefer_multi: bool = Form(True)):
    """
    Prefer ?wsdl (multi-doc WSDL) over ?singleWsdl (WCF single-file often breaks Zeep:
    'NotImplementedError: schemaLocation is required').
    Use system CA trust (verify=True). Keep mTLS via client cert/key.
    """
    cfg = load_config()
    base = (url or cfg.get("endpoint") or "").strip()
    if not base:
        return JSONResponse({"ok": False, "error": "Endpoint not set"}, status_code=400)

    variants = ["?wsdl", "?singleWsdl"] if prefer_multi else ["?singleWsdl", "?wsdl"]

    s = _wsdl_session(cfg)
    transport = Transport(session=s, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)

    errors = []
    for suffix in variants:
        wsdl_url = base + suffix
        try:
            Client(wsdl=wsdl_url, transport=transport, settings=settings)
            return JSONResponse({"ok": True, "url": wsdl_url, "note": f"Loaded via {suffix}"})
        except requests.exceptions.SSLError as e:
            errors.append({"url": wsdl_url, "stage": "tls-verify", "error": str(e),
                           "hint": "Use system CA for public hosts. Do not set CA bundle to your client chain for WSDL fetch."})
        except NotImplementedError as e:
            errors.append({"url": wsdl_url, "stage": "wsdl-parse", "error": str(e),
                           "hint": "WCF ?singleWsdl can omit schemaLocation. Prefer ?wsdl."})
        except Exception as e:
            errors.append({"url": wsdl_url, "stage": "zeep-init", "error": str(e)})

    return JSONResponse({"ok": False, "tried": variants, "errors": errors}, status_code=502)


@app.post("/wsdl/debug")
def wsdl_debug(url: str = Form(""), try_both: bool = Form(True), use_curl_fallback: bool = Form(True)):
    cfg = load_config()
    base = (url or cfg.get("endpoint") or "").strip()
    if not base:
        return JSONResponse({"ok": False, "error": "Endpoint not set"}, status_code=400)

    results = []
    variants = ["?wsdl", "?singleWsdl"] if try_both else ["?wsdl"]

    # requests + system CA + mTLS
    s = _wsdl_session(cfg)
    transport = Transport(session=s, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)

    for suffix in variants:
        wsdl_url = base + suffix
        entry = {"variant": f"requests{suffix}", "url": wsdl_url}
        try:
            # raw GET to inspect headers/body quickly
            status, headers, content, err = http_get(s, wsdl_url)
            parsed, note = (False, "")
            if content:
                parsed, note = try_parse_wsdl(content)
            entry.update({
                "ok": parsed and status == 200,
                "status": status, "headers": headers,
                "parse_note": note, "error": err,
                "content_type": headers.get("Content-Type","") if headers else "",
                "preview": content[:256].decode("utf-8","ignore") if content else ""
            })
        except Exception as e:
            entry.update({"ok": False, "error": str(e)})
        results.append(entry)

    # curl fallback (can show raw headers/body with mTLS + encrypted key pass)
    if use_curl_fallback:
        for suffix in variants:
            wsdl_url = base + suffix
            status, raw_headers, err, body = curl_fetch_wsdl(
                wsdl_url,
                cfg.get("client_cert",""), cfg.get("client_key",""),
                cfg.get("client_key_pass","")
            )
            parsed, note = try_parse_wsdl(body) if body else (False, "no body")
            results.append({
                "variant": f"curl{suffix}",
                "url": wsdl_url,
                "ok": parsed and status == 200,
                "status": status,
                "headers_raw": raw_headers,
                "error": err,
                "parse_note": note,
                "preview": body[:256].decode("utf-8","ignore") if body else ""
            })

    # Suggestions
    suggestions = []
    any_200_html = any(("text/html" in r.get("content_type","") and r.get("status")==200) for r in results if r["variant"].startswith("requests"))
    any_parse_err = any(("XML parse error" in (r.get("parse_note") or "")) for r in results)
    any_401_403 = any(r.get("status") in (401,403) for r in results if "status" in r)
    any_404 = any(r.get("status")==404 for r in results if "status" in r)

    if any_200_html:
        suggestions.append("Server returned HTML help page. Use ?wsdl or ?singleWsdl explicitly; avoid the bare service URL.")
    if any_parse_err:
        suggestions.append("Content is not valid WSDL. Confirm the exact ?wsdl URL and that mTLS client certificate is accepted.")
    if any_401_403:
        suggestions.append("Unauthorized/Forbidden. Verify your client certificate is registered for the DIV test environment.")
    if any_404:
        suggestions.append("Not Found. Verify the exact service path and casing.")
    if not results:
        suggestions.append("No results collected. Check network/DNS and container egress.")

    return JSONResponse({"ok": any(r.get("ok") for r in results), "results": results, "suggestions": suggestions})


@app.post("/wsdl/inspect")
def wsdl_inspect(url: str = Form(""), prefer_multi: bool = Form(True)):
    cfg = load_config()
    base = (url or cfg.get("endpoint") or "").strip()
    if not base:
        return JSONResponse({"ok": False, "error": "Endpoint not set"}, status_code=400)

    variants = ["?wsdl", "?singleWsdl"] if prefer_multi else ["?singleWsdl", "?wsdl"]

    s = _wsdl_session(cfg)
    transport = Transport(session=s, timeout=45)
    settings = Settings(strict=False, xml_huge_tree=True)

    errors = []
    for suffix in variants:
        wsdl_url = base + suffix
        try:
            cl = Client(wsdl=wsdl_url, transport=transport, settings=settings)
            ops = []
            for svc in cl.wsdl.services.values():
                for port in svc.ports.values():
                    for op in port.binding._operations.values():
                        ns = _op_namespace(op, cl)
                        sig = ""
                        try:
                            sig = op.input.signature(cl.wsdl.types)
                        except Exception:
                            sig = "(signature unavailable)"
                        ops.append({
                            "service": str(svc.name),
                            "port": str(port.name),
                            "operation": str(op.name),
                            "soap_action": op.soapaction,
                            "ns": ns,
                            "input_signature": sig,
                        })
            return JSONResponse({"ok": True, "url": wsdl_url, "count": len(ops), "operations": ops})
        except NotImplementedError as e:
            errors.append({"url": wsdl_url, "stage": "wsdl-parse", "error": str(e),
                           "hint": "WCF ?singleWsdl can omit schemaLocation. Prefer ?wsdl."})
        except requests.exceptions.SSLError as e:
            errors.append({"url": wsdl_url, "stage": "tls-verify", "error": str(e),
                           "hint": "Use system CA for public hosts; do not set CA bundle to the client chain for WSDL fetch."})
        except Exception as e:
            errors.append({"url": wsdl_url, "stage": "zeep-init", "error": str(e)})

    return JSONResponse({"ok": False, "tried": variants, "errors": errors}, status_code=502)


@app.post("/wsdl/op-template")
def wsdl_op_template(
    service: str = Form(...),
    port: str = Form(...),
    operation: str = Form(...),
    url: str = Form(""),
    prefer_multi: bool = Form(True),
    apply_to_config: bool = Form(True),
):
    cfg = load_config()
    base = (url or cfg.get("endpoint") or "").strip()
    if not base:
        return JSONResponse({"ok": False, "error": "Endpoint not set"}, status_code=400)

    variants = ["?wsdl", "?singleWsdl"] if prefer_multi else ["?singleWsdl", "?wsdl"]

    s = _wsdl_session(cfg)
    transport = Transport(session=s, timeout=45)
    settings = Settings(strict=False, xml_huge_tree=True)

    errors = []
    for suffix in variants:
        wsdl_url = base + suffix
        try:
            cl = Client(wsdl=wsdl_url, transport=transport, settings=settings)
            op = cl.wsdl.services[service].ports[port].binding._operations[operation]
            action = op.soapaction or ""

            body_xml = build_body_template(cl, service, port, operation)

            if apply_to_config:
                cfg["soap_action"] = action
                cfg["soap_version"] = cfg.get("soap_version") or "1.2"
                save_config(cfg)

            v = (cfg.get("soap_version") or "1.2").strip()
            if v == "1.1":
                env_ns = "http://schemas.xmlsoap.org/soap/envelope/"
            else:
                env_ns = "http://www.w3.org/2003/05/soap-envelope"

            envelope = f'''<soap:Envelope xmlns:soap="{env_ns}">
  <soap:Header>
    <!-- Optional: WS-Addressing/WS-Security if required -->
  </soap:Header>
  <soap:Body>
{body_xml}
  </soap:Body>
</soap:Envelope>'''

            return JSONResponse({"ok": True, "soap_action": action, "soap_version": v, "body_template": envelope})
        except Exception as e:
            errors.append({"url": wsdl_url, "error": str(e)})

    return JSONResponse({"ok": False, "errors": errors}, status_code=502)

@app.post("/validate")
def validate_route():
    cfg = load_config()
    ok, issues = validate_xsd(INVOICE_XML, cfg["schema_path"])
    return JSONResponse({"ok": ok, "issues": issues})

@app.get("/send", response_class=HTMLResponse)
def send_page(request: Request):
    cfg = load_config()
    samples = []
    if os.path.isdir("/data/samples"):
        samples = [os.path.join("/data/samples", f) for f in os.listdir("/data/samples")]
    return render("send.html", request, cfg=cfg, xml=INVOICE_XML, samples=samples)

@app.post("/send")
def send_route():
    cfg = load_config()
    ok, debug = send_invoice(INVOICE_XML, cfg)
    # Persist traffic logs
    os.makedirs("/data/logs", exist_ok=True)
    with open("/data/logs/last-request.xml", "w", encoding="utf-8") as f:
        f.write(debug["request"]["body"])
    with open("/data/logs/last-response.xml", "w", encoding="utf-8") as f:
        f.write(debug["response"]["body"])
    logging.info("POST %s -> %s in %dms", debug["request"]["url"], debug["response"]["status"], debug["timing_ms"])
    return JSONResponse({"ok": ok, "debug": debug})


@app.post("/div/attachment")
def div_attachment(path: str = Form("")):
    try:
        b64, length = read_file_b64(path)
        mime = "application/xml" if path.lower().endswith(".xml") else "application/octet-stream"
        return JSONResponse({
            "ok": True,
            "contents": b64,
            "length": length,
            "filename": os.path.basename(path),
            "mime": mime,
        })
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/div/sendmessage")
def div_sendmessage(
    attachment_path: str = Form(""),
    mime_type: str = Form("application/xml"),
    sender_eaddr: str = Form(""),
    recipient_eaddr: str = Form(""),
    client_msg_id: str = Form(""),
):
    cfg = load_config()
    if not cfg.get("soap_action"):
        return JSONResponse({"ok": False, "error": "SOAPAction not set. Pick operation from WSDL Browser → Use in Send."}, status_code=400)

    att_b64, att_len = ("", "0")
    content_id = new_content_id()
    if attachment_path:
        att_b64, att_len = read_file_b64(attachment_path)

    ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
    body = f"""
    <tns:SendMessage xmlns:tns="{ns}">
      <tns:Envelope>
        <MessageClientId>{client_msg_id or uuid.uuid4()}</MessageClientId>
        <SenderEAddress>{sender_eaddr}</SenderEAddress>
        <Recipients>
          <Recipient>
            <EAddress>{recipient_eaddr}</EAddress>
          </Recipient>
        </Recipients>
        <Subject>Test e-invoice</Subject>
        <BodyText>Test transmission from e-Rēķini Tester</BodyText>
      </tns:Envelope>
      <tns:AttachmentsInput>
        <AttachmentInput>
          <ContentId>{content_id}</ContentId>
          <FileName>invoice.xml</FileName>
          <MimeType>{mime_type}</MimeType>
          <Contents>{att_b64}</Contents>
        </AttachmentInput>
      </tns:AttachmentsInput>
    </tns:SendMessage>
    """.strip()

    env = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                             xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <wsa:Action>{cfg.get("soap_action","")}</wsa:Action>
    <wsa:To>{cfg.get("endpoint","")}</wsa:To>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
{body}
  </soap:Body>
</soap:Envelope>"""

    res = send_raw_envelope(cfg, env)
    msg_id = None
    if res.get("response_xml"):
        import re
        m = re.search(r"<MessageId>([^<]+)</MessageId>", res["response_xml"])
        if m:
            msg_id = m.group(1)
    if msg_id:
        cfg["last_message_id"] = msg_id
        save_config(cfg)

    _log_div_call("SendMessage", res.get("request_xml", env), res.get("response_xml", ""), res.get("took_ms", 0), cfg)
    return JSONResponse({**res, "inferred_message_id": msg_id})


@app.post("/div/init")
def div_init(
    attachment_path: str = Form(""),
    mime_type: str = Form("application/xml"),
    sender_eaddr: str = Form(""),
    recipient_eaddr: str = Form(""),
    client_msg_id: str = Form(""),
    chunk_size: int = Form(524288),
):
    cfg = load_config()
    if not cfg.get("soap_action"):
        return JSONResponse({"ok": False, "error": "SOAPAction not set."}, status_code=400)

    raw = b""
    att_len = "0"
    file_name = ""
    if attachment_path:
        with open(attachment_path, "rb") as f:
            raw = f.read()
        att_len = str(len(raw))
        file_name = os.path.basename(attachment_path)
    content_id = new_content_id()
    chunks = []
    if raw:
        for i in range(0, len(raw), chunk_size):
            chunk = base64.b64encode(raw[i:i+chunk_size]).decode("ascii")
            chunks.append(chunk)

    ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
    body = f"""
    <tns:InitSendMessage xmlns:tns="{ns}">
      <tns:Envelope>
        <MessageClientId>{client_msg_id or uuid.uuid4()}</MessageClientId>
        <SenderEAddress>{sender_eaddr}</SenderEAddress>
        <Recipients>
          <Recipient>
            <EAddress>{recipient_eaddr}</EAddress>
          </Recipient>
        </Recipients>
        <Subject>Test e-invoice</Subject>
        <BodyText>Test transmission from e-Rēķini Tester</BodyText>
      </tns:Envelope>
      <tns:AttachmentsInput>
        <AttachmentInput>
          <ContentId>{content_id}</ContentId>
          <FileName>{file_name or 'attachment.bin'}</FileName>
          <MimeType>{mime_type}</MimeType>
          <Length>{att_len}</Length>
        </AttachmentInput>
      </tns:AttachmentsInput>
    </tns:InitSendMessage>
    """.strip()

    env = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                             xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <wsa:Action>{cfg.get("soap_action","")}</wsa:Action>
    <wsa:To>{cfg.get("endpoint","")}</wsa:To>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
{body}
  </soap:Body>
</soap:Envelope>"""

    res = send_raw_envelope(cfg, env)
    msg_id = None
    if res.get("response_xml"):
        import re
        m = re.search(r"<MessageId>([^<]+)</MessageId>", res["response_xml"])
        if m:
            msg_id = m.group(1)
    if msg_id:
        cfg["last_message_id"] = msg_id
        cfg["last_content_id"] = content_id
        save_config(cfg)

    CHUNK_STATE.clear()
    CHUNK_STATE.update({
        "chunks": chunks,
        "message_id": msg_id,
        "content_id": content_id,
        "mime_type": mime_type,
        "file_name": file_name,
        "sender": sender_eaddr,
        "recipient": recipient_eaddr,
        "client_msg_id": client_msg_id or str(uuid.uuid4()),
    })

    _log_div_call("InitSendMessage", env, res.get("response_xml", ""), res.get("took_ms", 0), cfg)
    return JSONResponse({**res, "message_id": msg_id, "content_id": content_id, "chunk_count": len(chunks)})


@app.post("/div/sendsection")
def div_sendsection(index: int = Form(0)):
    cfg = load_config()
    chunk = CHUNK_STATE.get("chunks", [])
    if index >= len(chunk):
        return JSONResponse({"ok": False, "error": "Invalid section index"}, status_code=400)

    ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
    body = f"""
    <tns:SendAttachmentSection xmlns:tns="{ns}">
      <tns:MessageId>{CHUNK_STATE.get('message_id')}</tns:MessageId>
      <tns:ContentId>{CHUNK_STATE.get('content_id')}</tns:ContentId>
      <tns:SectionIndex>{index}</tns:SectionIndex>
      <tns:SectionContents>{chunk[index]}</tns:SectionContents>
    </tns:SendAttachmentSection>
    """.strip()

    env = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                             xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <wsa:Action>{cfg.get("soap_action","")}</wsa:Action>
    <wsa:To>{cfg.get("endpoint","")}</wsa:To>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
{body}
  </soap:Body>
</soap:Envelope>"""

    res = send_raw_envelope(cfg, env)
    _log_div_call("SendAttachmentSection", env, res.get("response_xml", ""), res.get("took_ms", 0), cfg)
    return JSONResponse(res)


@app.post("/div/complete")
def div_complete():
    cfg = load_config()
    ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
    body = f"""
    <tns:CompleteSendMessage xmlns:tns="{ns}">
      <tns:MessageId>{CHUNK_STATE.get('message_id')}</tns:MessageId>
      <tns:Envelope>
        <MessageClientId>{CHUNK_STATE.get('client_msg_id')}</MessageClientId>
        <SenderEAddress>{CHUNK_STATE.get('sender')}</SenderEAddress>
        <Recipients>
          <Recipient><EAddress>{CHUNK_STATE.get('recipient')}</EAddress></Recipient>
        </Recipients>
        <Subject>Test e-invoice</Subject>
        <BodyText>Test transmission from e-Rēķini Tester</BodyText>
      </tns:Envelope>
      <tns:AttachmentsInput>
        <AttachmentInput>
          <ContentId>{CHUNK_STATE.get('content_id')}</ContentId>
          <FileName>{CHUNK_STATE.get('file_name')}</FileName>
          <MimeType>{CHUNK_STATE.get('mime_type')}</MimeType>
        </AttachmentInput>
      </tns:AttachmentsInput>
    </tns:CompleteSendMessage>
    """.strip()

    env = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                             xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <wsa:Action>{cfg.get("soap_action","")}</wsa:Action>
    <wsa:To>{cfg.get("endpoint","")}</wsa:To>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
{body}
  </soap:Body>
</soap:Envelope>"""

    res = send_raw_envelope(cfg, env)
    _log_div_call("CompleteSendMessage", env, res.get("response_xml", ""), res.get("took_ms", 0), cfg)
    return JSONResponse(res)


@app.post("/div/confirm")
def div_confirm(message_id: str = Form("")):
    cfg = load_config()
    mid = message_id or cfg.get("last_message_id")
    if not mid:
        return JSONResponse({"ok": False, "error": "MessageId not provided"}, status_code=400)

    ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
    body = f"""
    <tns:GetMessageServerConfirmation xmlns:tns="{ns}">
      <tns:MessageId>{mid}</tns:MessageId>
    </tns:GetMessageServerConfirmation>
    """.strip()

    env = f"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                             xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <wsa:Action>{cfg.get("soap_action","")}</wsa:Action>
    <wsa:To>{cfg.get("endpoint","")}</wsa:To>
    <wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
{body}
  </soap:Body>
</soap:Envelope>"""

    res = send_raw_envelope(cfg, env)
    statuses = []
    if res.get("response_xml"):
        import re
        statuses = re.findall(r"<Status[^>]*>([^<]+)</Status[^>]*>", res["response_xml"])
    _log_div_call("GetMessageServerConfirmation", env, res.get("response_xml", ""), res.get("took_ms", 0), cfg)
    return JSONResponse({**res, "statuses": statuses})
