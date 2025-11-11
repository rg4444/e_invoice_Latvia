from copy import deepcopy
from pathlib import Path
import sys

import pytest

try:
    from types import SimpleNamespace
except ImportError:  # pragma: no cover - Python < 3.3
    SimpleNamespace = None

etree = pytest.importorskip("lxml.etree")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.address_service as address_service

from app.address_service import DS_NAMESPACE, TimestampedSignature, WSA_NAMESPACE
from zeep.wsse import utils as wsse_utils


WSSE = wsse_utils.ns.WSSE
WSU = wsse_utils.ns.WSU


def _make_security_tree():
    nsmap = {"wsse": WSSE, "wsu": WSU, "ds": DS_NAMESPACE}
    security = etree.Element(etree.QName(WSSE, "Security"), nsmap=nsmap)

    binary_token = etree.SubElement(security, etree.QName(WSSE, "BinarySecurityToken"))
    binary_token.set(etree.QName(WSU, "Id"), "token-123")

    signature = etree.SubElement(security, etree.QName(DS_NAMESPACE, "Signature"))
    key_info = etree.SubElement(signature, etree.QName(DS_NAMESPACE, "KeyInfo"))
    etree.SubElement(key_info, etree.QName(DS_NAMESPACE, "X509Data"))

    return security


def test_binary_security_token_reference_replaced_with_wsse_reference():
    security = _make_security_tree()

    signer = TimestampedSignature.__new__(TimestampedSignature)
    signer._cert_b64 = "CERTDATA=="

    signer._ensure_binary_security_token(security)

    binary_token = security.find(f"{{{WSSE}}}BinarySecurityToken")
    assert binary_token is not None
    assert binary_token.text == "CERTDATA=="

    key_info = security.find(f"{{{DS_NAMESPACE}}}Signature/{{{DS_NAMESPACE}}}KeyInfo")
    assert key_info is not None

    children = list(key_info)
    assert len(children) == 1
    sec_token_ref = children[0]
    assert sec_token_ref.tag == f"{{{WSSE}}}SecurityTokenReference"

    reference = sec_token_ref.find(f"{{{WSSE}}}Reference")
    assert reference is not None
    assert reference.get("URI") == f"#token-123"
    assert (
        reference.get("ValueType")
        == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
    )


def test_duplicate_key_info_nodes_removed_before_replacement():
    security = _make_security_tree()

    signature = security.find(f"{{{DS_NAMESPACE}}}Signature")
    assert signature is not None

    # Simulate zeep emitting multiple KeyInfo nodes by cloning the existing one.
    key_info = signature.find(f"{{{DS_NAMESPACE}}}KeyInfo")
    assert key_info is not None
    signature.append(deepcopy(key_info))

    signer = TimestampedSignature.__new__(TimestampedSignature)
    signer._cert_b64 = "CERTDATA=="

    signer._ensure_binary_security_token(security)

    key_infos = signature.findall(f"{{{DS_NAMESPACE}}}KeyInfo")
    assert len(key_infos) == 1

    sec_token_ref = key_infos[0].find(f"{{{WSSE}}}SecurityTokenReference")
    assert sec_token_ref is not None


class _DummyKey:
    def __init__(self, marker: str) -> None:
        self.marker = marker

    def public_numbers(self):
        return ("dummy", self.marker)


class _DummyBasicConstraints:
    def __init__(self, ca: bool) -> None:
        self.ca = ca


class _DummyExtension:
    def __init__(self, ca: bool) -> None:
        self.value = _DummyBasicConstraints(ca)


class _DummyExtensions:
    def __init__(self, ca: bool | None, exc_type):
        self._ca = ca
        self._exc_type = exc_type

    def get_extension_for_class(self, _cls):
        if self._ca is None:
            raise self._exc_type()
        return _DummyExtension(self._ca)


class _DummyCert:
    def __init__(self, marker: str, *, ca: bool | None, self_signed: bool) -> None:
        self._marker = marker
        self.subject = marker
        self.issuer = marker if self_signed else f"issuer-{marker}"
        self._ca = ca

    def public_key(self):
        return _DummyKey(self._marker)

    @property
    def extensions(self):
        return _DummyExtensions(self._ca, _DummyX509.ExtensionNotFound)


class _DummyX509:
    class ExtensionNotFound(Exception):
        pass

    BasicConstraints = object

    mapping: dict[str, _DummyCert] = {}

    @staticmethod
    def load_pem_x509_certificate(data: bytes):
        text = data.decode()
        for marker, cert in _DummyX509.mapping.items():
            if marker in text:
                return cert
        raise AssertionError(f"Unexpected certificate content: {text!r}")


def _write_chain(tmp_path, *bodies: str):
    chain = "".join(
        f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n" for body in bodies
    )
    path = tmp_path / "chain.pem"
    path.write_text(chain)
    return path


def _patch_crypto(monkeypatch, mapping):
    _DummyX509.mapping = mapping
    monkeypatch.setattr(address_service, "x509", _DummyX509, raising=False)

    def fake_load_private_key(*_args, **_kwargs):
        raise ValueError("encrypted key")

    monkeypatch.setattr(
        address_service.serialization,
        "load_pem_private_key",
        fake_load_private_key,
        raising=False,
    )


def test_certificate_selection_skips_self_signed_ca(monkeypatch, tmp_path):
    pem_path = _write_chain(tmp_path, "ROOTCERT", "LEAFCERT")

    mapping = {
        "ROOTCERT": _DummyCert("ROOTCERT", ca=None, self_signed=True),
        "LEAFCERT": _DummyCert("LEAFCERT", ca=False, self_signed=False),
    }

    _patch_crypto(monkeypatch, mapping)

    chosen = TimestampedSignature._extract_certificate_b64(str(pem_path), None)
    assert chosen == "LEAFCERT"


def _make_envelope_with_wsa(*, include_wsu: bool = True):
    soap_env = "http://www.w3.org/2003/05/soap-envelope"
    nsmap = {
        "s": soap_env,
        "wsse": WSSE,
        "wsa": WSA_NAMESPACE,
        "ds": DS_NAMESPACE,
    }
    if include_wsu:
        nsmap["wsu"] = WSU

    envelope = etree.Element(etree.QName(soap_env, "Envelope"), nsmap=nsmap)
    header = etree.SubElement(envelope, etree.QName(soap_env, "Header"))
    etree.SubElement(header, etree.QName(WSA_NAMESPACE, "Action"))
    etree.SubElement(header, etree.QName(WSA_NAMESPACE, "MessageID"))
    etree.SubElement(header, etree.QName("http://example.com", "Ignored"))
    etree.SubElement(header, etree.QName(WSA_NAMESPACE, "To"))
    etree.SubElement(header, etree.QName(WSSE, "Security"))

    etree.SubElement(envelope, etree.QName(soap_env, "Body"))
    return envelope, soap_env


def test_iter_addressing_headers_returns_wsa_nodes():
    envelope, soap_env = _make_envelope_with_wsa()

    nodes = TimestampedSignature._iter_addressing_headers(envelope, soap_env)
    assert [etree.QName(node).localname for node in nodes] == [
        "Action",
        "MessageID",
        "To",
    ]


def test_apply_signs_ws_addressing_headers(monkeypatch):
    envelope, soap_env = _make_envelope_with_wsa()
    header = envelope.find(etree.QName(soap_env, "Header"))
    assert header is not None
    security = header.find(f"{{{WSSE}}}Security")
    assert security is not None

    signer = TimestampedSignature.__new__(TimestampedSignature)
    signer.key_data = b"key"
    signer.cert_data = b"cert"
    signer.password = None
    signer.digest_method = None
    signer.signature_method = None
    signer.timestamp_ttl_seconds = 300
    signer._cert_b64 = "CERT=="
    signer._last_timestamp_window = None

    signed_nodes = []
    ensured_nodes = []

    class _DummyTemplate:
        @staticmethod
        def create(envelope, _c14n, _method):
            return etree.Element(etree.QName(DS_NAMESPACE, "Signature"))

        @staticmethod
        def ensure_key_info(signature):
            return etree.SubElement(signature, etree.QName(DS_NAMESPACE, "KeyInfo"))

        @staticmethod
        def add_x509_data(key_info):
            return etree.SubElement(key_info, etree.QName(DS_NAMESPACE, "X509Data"))

        @staticmethod
        def x509_data_add_issuer_serial(_x509_data):
            return None

        @staticmethod
        def x509_data_add_certificate(_x509_data):
            return None

    class _DummySignatureContext:
        def __init__(self):
            self.key = None

        def sign(self, _signature):
            return None

    dummy_xmlsec = SimpleNamespace(  # type: ignore[arg-type]
        Transform=SimpleNamespace(EXCL_C14N="exc", RSA_SHA1="rsa"),
        template=_DummyTemplate,
        SignatureContext=_DummySignatureContext,
    )

    monkeypatch.setattr(address_service, "xmlsec", dummy_xmlsec, raising=False)
    monkeypatch.setattr(
        address_service.zeep_signature,
        "_make_sign_key",
        lambda *_args: object(),
        raising=False,
    )

    def _capture_sign_node(ctx, signature, node, _digest):
        assert ctx.key is not None
        signed_nodes.append(node)

    monkeypatch.setattr(
        address_service.zeep_signature,
        "_sign_node",
        _capture_sign_node,
        raising=False,
    )

    def _capture_ensure_id(node):
        ensured_nodes.append(node)
        node.set(etree.QName(WSU, "Id"), f"id-{len(ensured_nodes)}")

    monkeypatch.setattr(
        address_service.zeep_signature,
        "ensure_id",
        _capture_ensure_id,
        raising=False,
    )

    signer.apply(envelope, headers={})

    assert ensured_nodes
    assert all(etree.QName(node).namespace == WSA_NAMESPACE for node in ensured_nodes)
    assert len(ensured_nodes) == 3

    signed_local_names = [etree.QName(node).localname for node in signed_nodes]
    assert "Body" in signed_local_names
    assert "Timestamp" in signed_local_names
    assert sorted(name for name in signed_local_names if name in {"Action", "MessageID", "To"}) == [
        "Action",
        "MessageID",
        "To",
    ]


def test_apply_adds_wsu_namespace_when_missing(monkeypatch):
    envelope, soap_env = _make_envelope_with_wsa(include_wsu=False)
    header = envelope.find(etree.QName(soap_env, "Header"))
    assert header is not None
    security = header.find(f"{{{WSSE}}}Security")
    assert security is not None

    signer = TimestampedSignature.__new__(TimestampedSignature)
    signer.key_data = b"key"
    signer.cert_data = b"cert"
    signer.password = None
    signer.digest_method = None
    signer.signature_method = None
    signer.timestamp_ttl_seconds = 300
    signer._cert_b64 = "CERT=="
    signer._last_timestamp_window = None

    monkeypatch.setattr(
        TimestampedSignature,
        "_apply_signature",
        lambda self, env: None,
        raising=False,
    )
    monkeypatch.setattr(
        TimestampedSignature,
        "_ensure_binary_security_token",
        lambda self, sec: None,
        raising=False,
    )

    signer.apply(envelope, headers={})

    assert envelope.nsmap.get("wsu") == WSU


def test_timestamped_signature_prefers_sha256(monkeypatch):
    if SimpleNamespace is None:  # pragma: no cover - defensive
        pytest.skip("SimpleNamespace unavailable")

    captured: dict[str, object] = {}

    def _fake_init(
        self,
        key_file,
        certfile,
        password=None,
        signature_method=None,
        digest_method=None,
    ) -> None:
        captured["signature_method"] = signature_method
        captured["digest_method"] = digest_method
        self.signature_method = signature_method
        self.digest_method = digest_method

    monkeypatch.setattr(
        address_service.Signature,
        "__init__",
        _fake_init,
        raising=False,
    )

    stub_transform = SimpleNamespace(RSA_SHA256="rsa256", SHA256="sha256")
    monkeypatch.setattr(
        address_service,
        "xmlsec",
        SimpleNamespace(Transform=stub_transform),
        raising=False,
    )

    monkeypatch.setattr(
        TimestampedSignature,
        "_extract_certificate_b64",
        staticmethod(lambda certfile, key_file=None: "CERTDATA"),
    )

    TimestampedSignature("key.pem", "cert.pem")

    assert captured["signature_method"] == "rsa256"
    assert captured["digest_method"] == "sha256"


def test_certificate_selection_handles_leaf_without_constraints(monkeypatch, tmp_path):
    pem_path = _write_chain(tmp_path, "ROOTCERT", "LEAFCERT")

    mapping = {
        "ROOTCERT": _DummyCert("ROOTCERT", ca=True, self_signed=True),
        "LEAFCERT": _DummyCert("LEAFCERT", ca=None, self_signed=False),
    }

    _patch_crypto(monkeypatch, mapping)

    chosen = TimestampedSignature._extract_certificate_b64(str(pem_path), None)
    assert chosen == "LEAFCERT"
