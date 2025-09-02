import os, logging
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from dotenv import load_dotenv

from storage import load_config, save_config
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
)
from validation import validate_xsd
from soap_client import send_invoice

load_dotenv()
LOG_DIR = "/data/logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "app.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"])
)

# In-memory invoice editor state
INVOICE_XML = ""
DEFAULT_INVOICE = os.getenv("DEFAULT_INVOICE", "/data/samples/einvoice_nePVN2.xml")

@app.on_event("startup")
def load_defaults():
    global INVOICE_XML
    if DEFAULT_INVOICE and os.path.isfile(DEFAULT_INVOICE):
        INVOICE_XML = open(DEFAULT_INVOICE, "r", encoding="utf-8").read()

def render(tpl, **ctx):
    return HTMLResponse(env.get_template(tpl).render(**ctx))

@app.get("/", response_class=HTMLResponse)
def home():
    cfg = load_config()
    return render("config.html", cfg=cfg)

@app.post("/save-config")
def save_config_route(
    endpoint: str = Form(""), soap_action: str = Form(""),
    username: str = Form(""), password: str = Form(""),
    client_cert: str = Form(""), client_key: str = Form(""),
    client_key_pass: str = Form(""),
    client_p12: str = Form(""), p12_password: str = Form(""),
    verify_tls: bool = Form(False), ca_bundle: str = Form(""),
    schema_path: str = Form(""), success_indicator: str = Form("Success")
):
    cfg = load_config()
    cfg.update({
        "endpoint": endpoint.strip(),
        "soap_action": soap_action.strip(),
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
def invoice_page():
    return render("invoice.html", xml=INVOICE_XML)

@app.post("/invoice/load")
async def invoice_load(file: UploadFile = File(...)):
    global INVOICE_XML
    INVOICE_XML = (await file.read()).decode("utf-8")
    return JSONResponse({"status":"ok", "len": len(INVOICE_XML)})

@app.post("/invoice/save")
def invoice_save():
    os.makedirs("/data/samples", exist_ok=True)
    path = "/data/samples/invoice-edited.xml"
    with open(path, "w", encoding="utf-8") as f:
        f.write(INVOICE_XML)
    return JSONResponse({"status":"ok", "path": path})

@app.post("/invoice/set")
async def invoice_set(request: Request):
    global INVOICE_XML
    data = await request.json()
    INVOICE_XML = data.get("xml","")
    return JSONResponse({"status":"ok", "len": len(INVOICE_XML)})

@app.get("/schema", response_class=HTMLResponse)
def schema_page():
    cfg = load_config()
    return render("schema.html", cfg=cfg)

@app.post("/validate")
def validate_route():
    cfg = load_config()
    ok, issues = validate_xsd(INVOICE_XML, cfg["schema_path"])
    return JSONResponse({"ok": ok, "issues": issues})

@app.get("/send", response_class=HTMLResponse)
def send_page():
    cfg = load_config()
    return render("send.html", cfg=cfg)

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
