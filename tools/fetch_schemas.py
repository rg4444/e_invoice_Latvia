#!/usr/bin/env python3
import os, zipfile, io, urllib.request

UBL_URL = "https://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip"
DEST = "data/xsd"

os.makedirs(DEST, exist_ok=True)
print("Downloading UBL 2.1…")
data = urllib.request.urlopen(UBL_URL).read()
with zipfile.ZipFile(io.BytesIO(data)) as z:
    for n in z.namelist():
        if n.startswith("maindoc/") or n.startswith("common/") or n.endswith(".xsd"):
            z.extract(n, DEST)
print("Done. XSDs under", DEST)
