import json, os

CONFIG_PATH = "/data/config.json"

DEFAULTS = {
    "endpoint": "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc",
    "soap_action": "",
    "soap_version": "1.2",
    "use_ws_addressing": True,
    "wsse_mode": "username",
    "username": "",
    "password": "",
    "client_cert": "/data/certs/client_full.pem",
    "client_key": "/data/certs/client.key",
    "client_key_pass": "",
    "client_p12": "",
    "p12_password": "",
    "verify_tls": True,
    "ca_bundle": "/data/certs/chain.pem",
    "schema_path": os.getenv("DEFAULT_SCHEMA", "/data/xsd/UBL-Invoice-2.1.xsd"),
    "success_indicator": "Success",
    "last_message_id": "",
    "last_content_id": "",
}

def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            for k, v in DEFAULTS.items():
                data.setdefault(k, v)
            return data
    except Exception:
        return DEFAULTS.copy()

def save_config(cfg: dict):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
