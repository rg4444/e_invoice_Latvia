import pytest

etree = pytest.importorskip("lxml.etree")

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
