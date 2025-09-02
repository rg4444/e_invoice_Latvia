from lxml import etree
from typing import Dict, Any, List
import os

NSMAP = {
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "inv": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
}

def read_reference_invoice(path: str) -> Dict[str, Any]:
    """Extract minimal fields from a reference UBL Invoice to prefill the form."""
    if not os.path.exists(path):
        return {}

    xml = etree.parse(path)
    x = xml.xpath

    def _txt(nodes):
        return nodes[0].text if nodes else ""

    data = {
        "id": _txt(x("//cbc:ID", namespaces=NSMAP)),
        "issue_date": _txt(x("//cbc:IssueDate", namespaces=NSMAP)),
        "due_date": _txt(x("//cbc:DueDate", namespaces=NSMAP)),
        "type_code": _txt(x("//cbc:InvoiceTypeCode", namespaces=NSMAP)),
        "currency": _txt(x("//cbc:DocumentCurrencyCode", namespaces=NSMAP)) or "EUR",
        "supplier_name": _txt(x("//cac:AccountingSupplierParty//cac:PartyName/cbc:Name", namespaces=NSMAP)),
        "supplier_company_id": _txt(x("//cac:AccountingSupplierParty//cac:Party/cac:PartyLegalEntity/cbc:CompanyID", namespaces=NSMAP)),
        "supplier_vat": _txt(x("//cac:AccountingSupplierParty//cac:Party/cac:PartyTaxScheme/cbc:CompanyID", namespaces=NSMAP)),
        "customer_name": _txt(x("//cac:AccountingCustomerParty//cac:PartyName/cbc:Name", namespaces=NSMAP)),
        "customer_company_id": _txt(x("//cac:AccountingCustomerParty//cac:Party/cac:PartyLegalEntity/cbc:CompanyID", namespaces=NSMAP)),
        "customer_vat": _txt(x("//cac:AccountingCustomerParty//cac:Party/cac:PartyTaxScheme/cbc:CompanyID", namespaces=NSMAP)),
        "lines": [],
    }

    lines = x("//cac:InvoiceLine", namespaces=NSMAP)
    for ln in lines[:5]:
        q = lambda p: _txt(ln.xpath(p, namespaces=NSMAP))
        data["lines"].append({
            "id": q("./cbc:ID"),
            "name": q(".//cac:Item/cbc:Name"),
            "qty": q("./cbc:InvoicedQuantity"),
            "price": q(".//cac:Price/cbc:PriceAmount"),
            "line_ext": q("./cbc:LineExtensionAmount"),
        })

    data["tax_amount"] = _txt(x("//cac:TaxTotal/cbc:TaxAmount", namespaces=NSMAP))
    data["payable_amount"] = _txt(x("//cac:LegalMonetaryTotal/cbc:PayableAmount", namespaces=NSMAP))

    return data

def build_invoice_xml(form: Dict[str, Any]) -> bytes:
    """Build a minimal UBL 2.1 Invoice XML from form fields."""
    E = etree.Element
    inv = E("{%s}Invoice" % NSMAP["inv"], nsmap={
        None: NSMAP["inv"],
        "cbc": NSMAP["cbc"],
        "cac": NSMAP["cac"],
    })

    def add(parent, qname, text):
        el = E(qname)
        el.text = text
        parent.append(el)
        return el

    add(inv, "{%s}CustomizationID" % NSMAP["cbc"], "urn:cen.eu:en16931:2017#compliant")
    if form.get("profile_id"):
        add(inv, "{%s}ProfileID" % NSMAP["cbc"], form["profile_id"])
    add(inv, "{%s}ID" % NSMAP["cbc"], form.get("id", "INV-1"))
    add(inv, "{%s}IssueDate" % NSMAP["cbc"], form.get("issue_date", "2025-01-01"))
    if form.get("due_date"):
        add(inv, "{%s}DueDate" % NSMAP["cbc"], form["due_date"])
    add(inv, "{%s}InvoiceTypeCode" % NSMAP["cbc"], form.get("type_code", "380"))
    add(inv, "{%s}DocumentCurrencyCode" % NSMAP["cbc"], form.get("currency", "EUR"))

    sup = E("{%s}AccountingSupplierParty" % NSMAP["cac"])
    sparty = E("{%s}Party" % NSMAP["cac"])
    if form.get("supplier_name"):
        pn = E("{%s}PartyName" % NSMAP["cac"])
        add(pn, "{%s}Name" % NSMAP["cbc"], form["supplier_name"])
        sparty.append(pn)
    ple = E("{%s}PartyLegalEntity" % NSMAP["cac"])
    if form.get("supplier_company_id"):
        add(ple, "{%s}CompanyID" % NSMAP["cbc"], form["supplier_company_id"])
    sparty.append(ple)
    if form.get("supplier_vat"):
        pts = E("{%s}PartyTaxScheme" % NSMAP["cac"])
        add(pts, "{%s}CompanyID" % NSMAP["cbc"], form["supplier_vat"])
        sparty.append(pts)
    sup.append(sparty)
    inv.append(sup)

    cus = E("{%s}AccountingCustomerParty" % NSMAP["cac"])
    cparty = E("{%s}Party" % NSMAP["cac"])
    if form.get("customer_name"):
        pn2 = E("{%s}PartyName" % NSMAP["cac"])
        add(pn2, "{%s}Name" % NSMAP["cbc"], form["customer_name"])
        cparty.append(pn2)
    ple2 = E("{%s}PartyLegalEntity" % NSMAP["cac"])
    if form.get("customer_company_id"):
        add(ple2, "{%s}CompanyID" % NSMAP["cbc"], form["customer_company_id"])
    cparty.append(ple2)
    if form.get("customer_vat"):
        pts2 = E("{%s}PartyTaxScheme" % NSMAP["cac"])
        add(pts2, "{%s}CompanyID" % NSMAP["cbc"], form["customer_vat"])
        cparty.append(pts2)
    cus.append(cparty)
    inv.append(cus)

    lines: List[Dict[str, Any]] = form.get("lines") or []
    for i, ln in enumerate(lines, start=1):
        il = E("{%s}InvoiceLine" % NSMAP["cac"])
        add(il, "{%s}ID" % NSMAP["cbc"], ln.get("id") or str(i))
        if ln.get("line_ext"):
            add(il, "{%s}LineExtensionAmount" % NSMAP["cbc"], ln["line_ext"])
        if ln.get("qty"):
            add(il, "{%s}InvoicedQuantity" % NSMAP["cbc"], ln["qty"])
        item = E("{%s}Item" % NSMAP["cac"])
        if ln.get("name"):
            add(item, "{%s}Name" % NSMAP["cbc"], ln["name"])
        il.append(item)
        if ln.get("price"):
            price = E("{%s}Price" % NSMAP["cac"])
            add(price, "{%s}PriceAmount" % NSMAP["cbc"], ln["price"])
            il.append(price)
        inv.append(il)

    if form.get("tax_amount"):
        taxtotal = E("{%s}TaxTotal" % NSMAP["cac"])
        add(taxtotal, "{%s}TaxAmount" % NSMAP["cbc"], form["tax_amount"])
        inv.append(taxtotal)

    lmt = E("{%s}LegalMonetaryTotal" % NSMAP["cac"])
    add(lmt, "{%s}PayableAmount" % NSMAP["cbc"], form.get("payable_amount", "0.00"))
    inv.append(lmt)

    return etree.tostring(inv, pretty_print=True, xml_declaration=True, encoding="UTF-8")
