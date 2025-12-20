from soap_engines.python_engine import call_python
from soap_engines.dotnet_engine import call_dotnet
from soap_engines.java_engine import call_java


def call_engine(
    engine: str,
    operation: str,
    token: str,
    endpoint: str,
    out_dir: str,
    **opts,
):
    if engine == "python":
        return call_python(operation, token, endpoint, out_dir, **opts)
    if engine == "dotnet":
        return call_dotnet(operation, token, endpoint, out_dir, **opts)
    if engine == "java":
        return call_java(operation, token, endpoint, out_dir, **opts)
    raise ValueError(f"Unknown engine: {engine}")
