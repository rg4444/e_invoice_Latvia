#!/usr/bin/env python3
"""Download the KoSIT validator jar.

By default it fetches version 1.5.2 and stores it under
``/opt/kosit/bin/validator-<version>-standalone.jar``.  The destination
and version can be overridden via the ``KOSIT_HOME`` and
``KOSIT_VER`` environment variables respectively.
"""
import os, urllib.request

KOSIT_VER = os.environ.get("KOSIT_VER", "1.5.2")
KOSIT_HOME = os.environ.get("KOSIT_HOME", "/opt/kosit")
DEST_DIR = os.path.join(KOSIT_HOME, "bin")

os.makedirs(DEST_DIR, exist_ok=True)
jar_name = f"validator-{KOSIT_VER}-standalone.jar"
jar_path = os.path.join(DEST_DIR, jar_name)
url = f"https://github.com/itplr-kosit/validator/releases/download/v{KOSIT_VER}/{jar_name}"

print(f"Downloading KoSIT validator {KOSIT_VER} from {url}")
urllib.request.urlretrieve(url, jar_path)
print("Saved to", jar_path)
