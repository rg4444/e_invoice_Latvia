from copy import deepcopy

import pytest

etree = pytest.importorskip("lxml.etree")

import app.address_service as address_service

from app.address_service import DS_NAMESPACE, TimestampedSignature
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


def test_certificate_selection_handles_leaf_without_constraints(monkeypatch, tmp_path):
    pem_path = _write_chain(tmp_path, "ROOTCERT", "LEAFCERT")

    mapping = {
        "ROOTCERT": _DummyCert("ROOTCERT", ca=True, self_signed=True),
        "LEAFCERT": _DummyCert("LEAFCERT", ca=None, self_signed=False),
    }

    _patch_crypto(monkeypatch, mapping)

    chosen = TimestampedSignature._extract_certificate_b64(str(pem_path), None)
    assert chosen == "LEAFCERT"
