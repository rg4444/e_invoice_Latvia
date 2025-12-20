# VDAA DIV Java Bridge

Compile `VdaaDivBridge.java` here and place the SDK jars under `lib/`.

Expected invocation:

```
java -cp "lib/*:." VdaaDivBridge --operation GetInitialAddresseeRecordList --endpoint <url> --token <token> \
  --out-dir /data/addresses
```

The bridge must emit the unified JSON contract described in `app/contracts/soap_engine_result.json` to stdout.
