#!/usr/bin/env python3
"""Download the KoSIT validator jar.

By default it fetches version 1.5.2 and stores it under
``data/kosit/bin/validator-<version>-standalone.jar`` relative to the
repository root. The destination and version can be overridden via the
``KOSIT_HOME`` and ``KOSIT_VER`` environment variables respectively.
"""
import os, urllib.request, zipfile, io

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KOSIT_VER = os.environ.get("KOSIT_VER", "1.5.2")
KOSIT_HOME = os.environ.get("KOSIT_HOME", os.path.join(BASE_DIR, "data", "kosit"))
DEST_DIR = os.path.join(KOSIT_HOME, "bin")

os.makedirs(DEST_DIR, exist_ok=True)
jar_name = f"validator-{KOSIT_VER}-standalone.jar"
jar_path = os.path.join(DEST_DIR, jar_name)
zip_name = f"validator-{KOSIT_VER}.zip"
url = f"https://github.com/itplr-kosit/validator/releases/download/v{KOSIT_VER}/{zip_name}"

print(f"Downloading KoSIT validator {KOSIT_VER} from {url}")
with urllib.request.urlopen(url) as resp:
    data = resp.read()
with zipfile.ZipFile(io.BytesIO(data)) as z:
    with z.open(jar_name) as src, open(jar_path, "wb") as dst:
        dst.write(src.read())
print("Saved to", jar_path)
