import pytest

etree = pytest.importorskip("lxml.etree")

from div_envelope import (
    DIV_ENVELOPE_NS,
    DS_NS,
    EnvelopeMetadata,
    build_div_envelope,
    parse_recipient_list,
)


def test_parse_recipient_list_strips_and_deduplicates():
    raw = "alpha@example.com; beta@example.com, alpha@example.com\n gamma@example.com"
    assert parse_recipient_list(raw) == [
        "alpha@example.com",
        "beta@example.com",
        "gamma@example.com",
    ]


def test_build_div_envelope_contains_required_nodes():
    envelope = build_div_envelope(
        sender_eaddress="sender@example.com",
        recipients=["recipient@example.com"],
        sender_reference="ref-123",
        subject="Sample Subject",
        body_text="Sample body",
        metadata=EnvelopeMetadata(
            author="Test Suite",
            document_kind_code="DOC",
            document_kind_version="v1",
            priority="high",
            notify_sender_on_delivery=True,
        ),
        trace_entries={"ClientId": "TraceValue"},
    )

    assert etree.QName(envelope).namespace == DIV_ENVELOPE_NS
    assert etree.QName(envelope).localname == "Envelope"

    sender_document = envelope.find(f"{{{DIV_ENVELOPE_NS}}}SenderDocument")
    assert sender_document is not None
    assert sender_document.get("Id") == "SenderSection"

    sender_transport = envelope.find(f".//{{{DIV_ENVELOPE_NS}}}SenderTransportMetadata")
    assert sender_transport is not None
    sender_eaddr = sender_transport.find(f"{{{DIV_ENVELOPE_NS}}}SenderE-Address")
    assert sender_eaddr is not None and sender_eaddr.text == "sender@example.com"

    recipient_eaddr = envelope.find(f".//{{{DIV_ENVELOPE_NS}}}RecipientE-Address")
    assert recipient_eaddr is not None and recipient_eaddr.text == "recipient@example.com"

    trace_id = envelope.find(f".//{{{DIV_ENVELOPE_NS}}}TraceInfoID")
    trace_text = envelope.find(f".//{{{DIV_ENVELOPE_NS}}}TraceText")
    assert trace_id is not None and trace_id.text.startswith("ClientId")
    assert trace_text is not None and trace_text.text == "TraceValue"

    signature = envelope.find(f".//{{{DS_NS}}}Signature")
    digest_value = envelope.find(f".//{{{DS_NS}}}DigestValue")
    assert signature is not None
    assert digest_value is not None


def test_build_div_envelope_requires_sender_and_recipient():
    with pytest.raises(ValueError):
        build_div_envelope(
            sender_eaddress="",
            recipients=["recipient@example.com"],
            sender_reference="ref",
            subject="Subject",
            body_text="Body",
        )

    with pytest.raises(ValueError):
        build_div_envelope(
            sender_eaddress="sender@example.com",
            recipients=[],
            sender_reference="ref",
            subject="Subject",
            body_text="Body",
        )
