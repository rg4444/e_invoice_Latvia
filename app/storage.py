import json, os

CONFIG_PATH = "/data/config.json"

DEFAULTS = {
    "endpoint": "",
    "soap_action": "",
    "username": "",
    "password": "",
    "client_cert": "",        # /data/certs/client.pem
    "client_key": "",         # /data/certs/client.key
    "client_p12": "",         # /data/certs/client.p12 (optional)
    "p12_password": "",
    "verify_tls": True,
    "ca_bundle": "",          # /data/trust/ca.pem (optional)
    "schema_path": os.getenv("DEFAULT_SCHEMA", ""),
    "success_indicator": "Valid",
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
