import os
import re
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, Any, List

from lxml import etree

PDF_NS = "urn:lv:einvoice:pdf-transform:1.0"


class PdfOcrError(Exception):
    pass


def ocr_pdf_to_text(pdf_path: str, lang: str = "eng+lav") -> str:
    """
    Run ocrmypdf on pdf_path and return plain OCR text (sidecar file).
    """
    if not os.path.exists(pdf_path):
        raise PdfOcrError(f"PDF not found: {pdf_path}")

    workdir = tempfile.mkdtemp(prefix="pdfocr_")
    sidecar = os.path.join(workdir, "ocr.txt")
    out_pdf = os.path.join(workdir, "ocr-ocr.pdf")

    cmd = [
        "ocrmypdf",
        "--sidecar",
        sidecar,
        "-l",
        lang,
        "--force-ocr",
        pdf_path,
        out_pdf,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.exists(sidecar):
        raise PdfOcrError(f"OCR failed ({proc.returncode}): {proc.stderr}")

    with open(sidecar, "r", encoding="utf-8") as f:
        text = f.read()

    return text


# ---------- Parsing logic for PwC-style invoice ----------

def _clean_lines(text: str) -> List[str]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            lines.append(line)
    return lines


def _find(regex: str, text: str, default: str = "") -> str:
    m = re.search(regex, text, flags=re.MULTILINE)
    return m.group(1).strip() if m else default


def parse_pwc_invoice(text: str) -> Dict[str, Any]:
    """
    Very targeted parser for PwC -> Sadales tīkls invoice layout.
    Later you can extend this or plug in multiple layout parsers.
    """
    lines = _clean_lines(text)
    joined = "\n".join(lines)

    # Header
    invoice_number = _find(r"Rēķina numurs/Invoice No\s+([0-9A-Za-z]+)", joined)
    invoice_date = _find(r"Rēķina datums/Invoice date\s+([0-9\.]+)", joined)
    due_date = _find(r"Apmaksas datums/Due date\s+([0-9\.]+)", joined)
    tax_date = _find(r"Pakalpojuma sniegšanas datums/Tax date\s+([0-9\.]+)", joined)
    engagement = _find(r"Projekta Nr./Engagement\s+([0-9A-Za-z]+)", joined)

    # Amounts & VAT
    def _to_decimal(num: str) -> str:
        # "1 105,00" -> "1105.00"
        if not num:
            return ""
        num = num.replace(" ", "").replace(",", ".")
        return num

    net_amount = _to_decimal(_find(r"SUMMA/ Amount\s+([\d\s,]+)", joined))
    vat_amount = _to_decimal(_find(r"PVN 21% / VAT 21%\s+([\d\s,]+)", joined))

    # SUMMA APMAKSAI line can have two numbers: prepaid + payable
    m = re.search(r"SUMMA APMAKSAI/AMOUNT PAYABLE\s+([\d\s,]+)\s+([\d\s,]+)", joined)
    prepaid = _to_decimal(m.group(1)) if m else ""
    payable = _to_decimal(m.group(2)) if m else ""

    # Supplier / Customer blocks by anchor labels
    def extract_block(anchor: str) -> List[str]:
        block: List[str] = []
        active = False
        for ln in lines:
            if anchor in ln:
                active = True
                continue
            if active:
                # stop when we hit another known anchor
                if "PVN/VAT no" in ln or "Klients/To" in ln or "Pakalpojuma sniedzējs/From" in ln:
                    break
                block.append(ln)
        return block

    supplier_block = extract_block("Pakalpojuma sniedzējs/From")
    customer_block = extract_block("Klients/To")

    # Supplier
    supplier = {
        "name": supplier_block[0] if len(supplier_block) > 0 else "",
        "address_line": supplier_block[1] if len(supplier_block) > 1 else "",
        "city_postcode": supplier_block[2] if len(supplier_block) > 2 else "",
        "country_name": supplier_block[3] if len(supplier_block) > 3 else "",
        "phone": _find(r"Tel/Telephone\s+(.+)", joined),
        "email": _find(r"E-mail:\s*([^, ]+)", joined),
        "website": _find(r"Internet:\s*([A-Za-z0-9\.:/]+)", joined),
        "reg_no": _find(r"Uzņēmumu reģistra numurs/Registration number\s+([0-9]+)", joined),
        "vat_no": _find(r"PVN/VAT no\s+([A-Z0-9]+)", joined),
    }

    # Customer
    customer = {
        "name": customer_block[0] if len(customer_block) > 0 else "",
        "address_line": customer_block[1] if len(customer_block) > 1 else "",
        "city_postcode": customer_block[2] if len(customer_block) > 2 else "",
        "country_name": customer_block[3] if len(customer_block) > 3 else "",
        "vat_no": _find(r"Klients/To.*?PVN/VAT no\s+([A-Z0-9]+)", joined, default=""),
    }

    # Payment details – crude but robust for PwC layout
    payment_accounts: List[Dict[str, str]] = []
    pay_idx = next((i for i, ln in enumerate(lines) if "Norēķinu rekvizīti/Payment details" in ln), -1)
    if pay_idx != -1:
        i = pay_idx + 1
        current: Dict[str, str] = {}
        while i < len(lines):
            ln = lines[i]
            if "Kontaktpersona/Contact name" in ln:
                break
            if "Banka/Bank name" in ln:
                # Start / reset bank account
                if current:
                    payment_accounts.append(current)
                    current = {}
                current["bank_name"] = ln.split("Banka/Bank name", 1)[1].strip()
            elif ln.startswith("Luminor") or ln.startswith("SEB "):
                current["bank_name"] = ln.strip()
            elif ln.startswith("IBAN"):
                current["iban"] = ln.replace("IBAN", "").split(",", 1)[0].strip()
            elif ln.startswith("LV") and "iban" not in current:
                current["iban"] = ln.split(",", 1)[0].strip()
            elif re.match(r"^[A-Z]{6}[A-Z0-9]{2,5}$", ln):
                current["swift"] = ln.strip()
            i += 1
        if current:
            payment_accounts.append(current)

    # Contact
    contact_name = _find(r"Kontaktpersona/Contact name\s+(.+)", joined)

    # Line description block
    desc_block: List[str] = []
    in_desc = False
    for ln in lines:
        if "Pakalpojuma apraksts/Description" in ln:
            in_desc = True
            continue
        if in_desc:
            if "SUMMA/" in ln or "SUMMA/ Amount" in ln:
                break
            desc_block.append(ln)
    description = " ".join(desc_block).strip()

    # Build dictionary model matching XSD
    model: Dict[str, Any] = {
        "header": {
            "invoice_number": invoice_number,
            "invoice_date": invoice_date,
            "due_date": due_date,
            "tax_date": tax_date,
            "engagement": engagement,
            "currency": "EUR",
        },
        "supplier": supplier,
        "customer": customer,
        "payment_accounts": payment_accounts,
        "contact": {"name": contact_name},
        "lines": [
            {
                "line_no": 1,
                "description": description,
                "quantity": "1",
                "unit": "service",
                "unit_price": net_amount,
                "net_amount": net_amount,
                "tax_rate": "21.00",
                "tax_amount": vat_amount,
                "gross_amount": payable,
            }
        ],
        "totals": {
            "line_ext": net_amount,
            "tax_excl": net_amount,
            "tax_incl": payable,
            "prepaid": prepaid,
            "payable": payable,
            "vat_total": vat_amount,
            "vat_rate": "21.00",
        },
        "raw_text": joined,
    }

    return model


# ---------- XML builder ----------

def build_pdf_invoice_xml(model: Dict[str, Any], source_file: str = "") -> bytes:
    """
    Build PdfInvoice XML according to pdf_invoice_transform.xsd.
    """
    nsmap = {None: PDF_NS}
    root = etree.Element("PdfInvoice", nsmap=nsmap)
    root.set("schemaVersion", "1.0")
    root.set("createdAt", datetime.utcnow().isoformat() + "Z")
    root.set("sourceSystem", "e-invoice-latvia-pdf-ocr")

    header = etree.SubElement(root, "Header")
    h = model.get("header", {})

    def add(parent, name, value):
        if value:
            el = etree.SubElement(parent, name)
            el.text = value

    add(header, "InvoiceNumber", h.get("invoice_number"))
    add(header, "TaxInvoiceNumber", h.get("invoice_number"))

    def norm_date(d: str) -> str:
        if not d:
            return ""
        if "." in d:
            dd, mm, yyyy = d.split(".")
            return f"{yyyy}-{mm}-{dd}"
        return d

    add(header, "InvoiceDate", norm_date(h.get("invoice_date")))
    add(header, "DueDate", norm_date(h.get("due_date")))
    add(header, "TaxDate", norm_date(h.get("tax_date")))
    add(header, "Currency", h.get("currency") or "EUR")
    add(header, "EngagementNumber", h.get("engagement"))
    add(header, "OriginalFileName", os.path.basename(source_file))

    # Supplier
    s_data = model.get("supplier", {})
    supplier = etree.SubElement(root, "Supplier")
    add(supplier, "Name", s_data.get("name"))
    add(supplier, "LegalRegistrationNumber", s_data.get("reg_no"))
    add(supplier, "VATNumber", s_data.get("vat_no"))
    add(supplier, "AddressLine", s_data.get("address_line"))
    if s_data.get("city_postcode"):
        add(supplier, "City", s_data.get("city_postcode"))
    add(supplier, "CountryName", s_data.get("country_name"))
    add(supplier, "Phone", s_data.get("phone"))
    add(supplier, "Email", s_data.get("email"))
    add(supplier, "Website", s_data.get("website"))

    # Customer
    c_data = model.get("customer", {})
    customer = etree.SubElement(root, "Customer")
    add(customer, "Name", c_data.get("name"))
    add(customer, "VATNumber", c_data.get("vat_no"))
    add(customer, "AddressLine", c_data.get("address_line"))
    add(customer, "City", c_data.get("city_postcode"))
    add(customer, "CountryName", c_data.get("country_name"))

    # Payment details
    if model.get("payment_accounts"):
        pd = etree.SubElement(root, "PaymentDetails")
        for acc in model["payment_accounts"]:
            ba = etree.SubElement(pd, "BankAccount")
            add(ba, "BankName", acc.get("bank_name"))
            add(ba, "IBAN", acc.get("iban"))
            add(ba, "SWIFT", acc.get("swift"))
            add(ba, "Currency", "EUR")

    # Contact
    contact_data = model.get("contact", {})
    if contact_data.get("name"):
        ct = etree.SubElement(root, "Contact")
        add(ct, "Name", contact_data.get("name"))

    # Lines
    lines_el = etree.SubElement(root, "Lines")
    for ln in model.get("lines", []):
        le = etree.SubElement(lines_el, "Line")
        add(le, "LineNumber", str(ln.get("line_no", "")))
        add(le, "Description", ln.get("description"))
        add(le, "Quantity", ln.get("quantity"))
        add(le, "UnitOfMeasure", ln.get("unit"))
        add(le, "UnitPrice", ln.get("unit_price"))
        add(le, "NetAmount", ln.get("net_amount"))
        add(le, "TaxRate", ln.get("tax_rate"))
        add(le, "TaxAmount", ln.get("tax_amount"))
        add(le, "GrossAmount", ln.get("gross_amount"))

    # Totals
    t = model.get("totals", {})
    if t:
        totals_el = etree.SubElement(root, "Totals")
        add(totals_el, "LineExtensionAmount", t.get("line_ext"))
        add(totals_el, "TaxExclusiveAmount", t.get("tax_excl"))
        add(totals_el, "TaxInclusiveAmount", t.get("tax_incl"))
        add(totals_el, "PrepaidAmount", t.get("prepaid"))
        add(totals_el, "PayableAmount", t.get("payable"))
        add(totals_el, "VATTotal", t.get("vat_total"))
        add(totals_el, "VATRate", t.get("vat_rate"))

    # Raw OCR text (optional)
    if model.get("raw_text"):
        raw_el = etree.SubElement(root, "RawOcrText")
        raw_el.text = model["raw_text"]

    return etree.tostring(root, pretty_print=True, encoding="UTF-8", xml_declaration=True)


def process_pdf_to_xml(pdf_path: str) -> bytes:
    text = ocr_pdf_to_text(pdf_path)
    model = parse_pwc_invoice(text)
    return build_pdf_invoice_xml(model, source_file=pdf_path)
