import json, os, copy

CONFIG_PATH = "/data/config.json"

DEFAULTS = {
    "endpoint": "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc",
    "debug_endpoint": "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterfaceDebug/UnifiedService.svc",
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
    "auth_credentials": [
        {"username": "Administrator", "password": "invoicetool"},
    ],
    "DOTNET_BRIDGE_PATH": "/bridge/dotnet/VdaaDivBridge/VdaaDivBridge.exe",
    "DOTNET_CERT_PFX_PATH": "",
    "DOTNET_CERT_PFX_PASSWORD": "",
    "JAVA_BRIDGE_DIR": "/bridge/java/VdaaDivBridge",
    "JAVA_BRIDGE_LIB_DIR": "/examples/VDAA_docs/Client/JAVA",
    "JAVA_BRIDGE_MAIN": "VdaaDivBridge",
    "wssec_java_pfx_path": "",
    "wssec_java_pfx_password": "",
}

def load_config():
    config = copy.deepcopy(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                config.update(data)
    except Exception:
        pass
    return config

def save_config(cfg: dict):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
