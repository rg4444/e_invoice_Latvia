# VDAA DIV .NET Bridge

Place the compiled `VdaaDivBridge.exe` here along with any required DLLs.

The bridge should accept arguments like:

```
VdaaDivBridge.exe --operation GetInitialAddresseeRecordList --endpoint <url> --token <token> \
  --out-dir /data/addresses --cert-pfx <path> --cert-pass <password>
```

It must print the unified JSON contract described in `app/contracts/soap_engine_result.json` to stdout.
