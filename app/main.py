import os, logging
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from dotenv import load_dotenv

from storage import load_config, save_config
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
DEFAULT_INVOICE = os.getenv("DEFAULT_INVOICE", "")

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
    client_p12: str = Form(""), p12_password: str = Form(""),
    verify_tls: bool = Form(False), ca_bundle: str = Form(""),
    schema_path: str = Form(""), success_indicator: str = Form("Valid")
):
    cfg = load_config()
    cfg.update({
        "endpoint": endpoint.strip(),
        "soap_action": soap_action.strip(),
        "username": username,
        "password": password,
        "client_cert": client_cert.strip(),
        "client_key": client_key.strip(),
        "client_p12": client_p12.strip(),
        "p12_password": p12_password,
        "verify_tls": verify_tls,
        "ca_bundle": ca_bundle.strip(),
        "schema_path": schema_path.strip(),
        "success_indicator": success_indicator.strip(),
    })
    save_config(cfg)
    return JSONResponse({"status": "ok"})

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
