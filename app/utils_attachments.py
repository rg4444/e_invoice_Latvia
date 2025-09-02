import os, base64, uuid

def read_file_b64(path: str) -> tuple[str, str]:
    with open(path, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode('ascii'), str(len(data))

def new_content_id() -> str:
    return str(uuid.uuid4())
