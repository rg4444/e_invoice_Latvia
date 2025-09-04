from lxml import etree
from typing import Dict, Any, List
import os

NSMAP = {
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "inv": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
}

def _txt(nodes):
    return nodes[0].text if nodes else ""

def _attr(nodes, attr):
    return nodes[0].get(attr, "") if nodes else ""


def parse_invoice_to_form(xml_bytes: bytes) -> Dict[str, Any]:
    doc = etree.fromstring(xml_bytes)
    x = doc.xpath

    def party(base: str) -> Dict[str, str]:
        return {
            "endpoint_id": _txt(x(f"{base}/cbc:EndpointID", namespaces=NSMAP)),
            "endpoint_scheme": _attr(x(f"{base}/cbc:EndpointID", namespaces=NSMAP), "schemeID"),
            "party_id": _txt(x(f"{base}/cac:PartyIdentification/cbc:ID", namespaces=NSMAP)),
            "name": _txt(x(f"{base}/cac:PartyName/cbc:Name", namespaces=NSMAP)),
            "address_line": _txt(x(f"{base}/cac:PostalAddress/cac:AddressLine/cbc:Line", namespaces=NSMAP)),
            "country_code": _txt(x(f"{base}/cac:PostalAddress/cac:Country/cbc:IdentificationCode", namespaces=NSMAP)),
            "tax_reg_name": _txt(x(f"{base}/cac:PartyTaxScheme/cbc:RegistrationName", namespaces=NSMAP)),
            "tax_company_id": _txt(x(f"{base}/cac:PartyTaxScheme/cbc:CompanyID", namespaces=NSMAP)),
            "tax_scheme_id": _txt(x(f"{base}/cac:PartyTaxScheme/cac:TaxScheme/cbc:ID", namespaces=NSMAP)),
            "legal_name": _txt(x(f"{base}/cac:PartyLegalEntity/cbc:RegistrationName", namespaces=NSMAP)),
            "legal_company_id": _txt(x(f"{base}/cac:PartyLegalEntity/cbc:CompanyID", namespaces=NSMAP)),
        }

    lines: List[Dict[str, str]] = []
    for ln in x("//cac:InvoiceLine", namespaces=NSMAP):
        q = lambda p: _txt(ln.xpath(p, namespaces=NSMAP))
        a = lambda p, attr: _attr(ln.xpath(p, namespaces=NSMAP), attr)
        lines.append({
            "id": q("./cbc:ID"),
            "qty": q("./cbc:InvoicedQuantity"),
            "unit_code": a("./cbc:InvoicedQuantity", "unitCode"),
            "line_ext": q("./cbc:LineExtensionAmount"),
            "allow_charge_indicator": q("./cac:AllowanceCharge/cbc:ChargeIndicator"),
            "allow_reason": q("./cac:AllowanceCharge/cbc:AllowanceChargeReason"),
            "allow_amount": q("./cac:AllowanceCharge/cbc:Amount"),
            "item_name": q("./cac:Item/cbc:Name"),
            "tax_id": q("./cac:Item/cac:ClassifiedTaxCategory/cbc:ID"),
            "tax_percent": q("./cac:Item/cac:ClassifiedTaxCategory/cbc:Percent"),
            "tax_scheme": q("./cac:Item/cac:ClassifiedTaxCategory/cac:TaxScheme/cbc:ID"),
            "price_amount": q("./cac:Price/cbc:PriceAmount"),
            "price_currency": a("./cac:Price/cbc:PriceAmount", "currencyID"),
            "base_qty": q("./cac:Price/cbc:BaseQuantity"),
        })

    return {
        "header": {
            "customization_id": _txt(x("//cbc:CustomizationID", namespaces=NSMAP)),
            "profile_id": _txt(x("//cbc:ProfileID", namespaces=NSMAP)),
            "id": _txt(x("//cbc:ID", namespaces=NSMAP)),
            "issue_date": _txt(x("//cbc:IssueDate", namespaces=NSMAP)),
            "due_date": _txt(x("//cbc:DueDate", namespaces=NSMAP)),
            "type_code": _txt(x("//cbc:InvoiceTypeCode", namespaces=NSMAP)),
            "note": _txt(x("//cbc:Note", namespaces=NSMAP)),
            "currency": _txt(x("//cbc:DocumentCurrencyCode", namespaces=NSMAP)),
            "buyer_reference": _txt(x("//cbc:BuyerReference", namespaces=NSMAP)),
            "contract_id": _txt(x("//cac:ContractDocumentReference/cbc:ID", namespaces=NSMAP)),
        },
        "supplier": party("//cac:AccountingSupplierParty/cac:Party"),
        "customer": party("//cac:AccountingCustomerParty/cac:Party"),
        "payment": {
            "means_code": _txt(x("//cac:PaymentMeans/cbc:PaymentMeansCode", namespaces=NSMAP)),
            "iban": _txt(x("//cac:PayeeFinancialAccount/cbc:ID", namespaces=NSMAP)),
            "bic": _txt(x("//cac:PayeeFinancialAccount/cac:FinancialInstitutionBranch/cbc:ID", namespaces=NSMAP)),
        },
        "tax": {
            "total_amount": _txt(x("//cac:TaxTotal/cbc:TaxAmount", namespaces=NSMAP)),
            "subtotal_taxable": _txt(x("//cac:TaxTotal/cac:TaxSubtotal/cbc:TaxableAmount", namespaces=NSMAP)),
            "subtotal_tax": _txt(x("//cac:TaxTotal/cac:TaxSubtotal/cbc:TaxAmount", namespaces=NSMAP)),
            "category_id": _txt(x("//cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:ID", namespaces=NSMAP)),
            "category_name": _txt(x("//cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:Name", namespaces=NSMAP)),
            "category_percent": _txt(x("//cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:Percent", namespaces=NSMAP)),
            "category_scheme": _txt(x("//cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cac:TaxScheme/cbc:ID", namespaces=NSMAP)),
        },
        "totals": {
            "line_ext": _txt(x("//cac:LegalMonetaryTotal/cbc:LineExtensionAmount", namespaces=NSMAP)),
            "tax_excl": _txt(x("//cac:LegalMonetaryTotal/cbc:TaxExclusiveAmount", namespaces=NSMAP)),
            "tax_incl": _txt(x("//cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount", namespaces=NSMAP)),
            "prepaid": _txt(x("//cac:LegalMonetaryTotal/cbc:PrepaidAmount", namespaces=NSMAP)),
            "payable": _txt(x("//cac:LegalMonetaryTotal/cbc:PayableAmount", namespaces=NSMAP)),
        },
        "lines": lines,
    }


def read_reference_invoice(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        minimal_invoice = (
            b"<Invoice xmlns='urn:oasis:names:specification:ubl:schema:xsd:Invoice-2' "
            b"xmlns:cac='urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2' "
            b"xmlns:cbc='urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'></Invoice>"
        )
        return parse_invoice_to_form(minimal_invoice)
    with open(path, "rb") as f:
        return parse_invoice_to_form(f.read())


def build_invoice_xml(form: Dict[str, Any]) -> bytes:
    E = etree.Element
    inv = E("{%s}Invoice" % NSMAP["inv"], nsmap={None: NSMAP["inv"], "cbc": NSMAP["cbc"], "cac": NSMAP["cac"]})

    def add_cbc(parent, tag, text, attrs=None):
        if text == "" and not attrs:
            return None
        el = E("{%s}%s" % (NSMAP["cbc"], tag))
        if text != "":
            el.text = text
        if attrs:
            for k, v in attrs.items():
                if v:
                    el.set(k, v)
        parent.append(el)
        return el

    def add_cac(parent, tag):
        el = E("{%s}%s" % (NSMAP["cac"], tag))
        parent.append(el)
        return el

    h = form.get("header", {})
    currency = h.get("currency") or "EUR"
    add_cbc(inv, "CustomizationID", h.get("customization_id"))
    add_cbc(inv, "ProfileID", h.get("profile_id"))
    add_cbc(inv, "ID", h.get("id"))
    add_cbc(inv, "IssueDate", h.get("issue_date"))
    add_cbc(inv, "DueDate", h.get("due_date"))
    add_cbc(inv, "InvoiceTypeCode", h.get("type_code"))
    add_cbc(inv, "Note", h.get("note"))
    add_cbc(inv, "DocumentCurrencyCode", currency)
    add_cbc(inv, "BuyerReference", h.get("buyer_reference"))
    if h.get("contract_id"):
        cdr = add_cac(inv, "ContractDocumentReference")
        add_cbc(cdr, "ID", h.get("contract_id"))

    def build_party(tag: str, data: Dict[str, Any]):
        cnt = add_cac(inv, tag)
        party = add_cac(cnt, "Party")
        if data.get("endpoint_id") or data.get("endpoint_scheme"):
            add_cbc(party, "EndpointID", data.get("endpoint_id"), {"schemeID": data.get("endpoint_scheme")})
        if data.get("party_id"):
            pid = add_cac(party, "PartyIdentification")
            add_cbc(pid, "ID", data.get("party_id"))
        if data.get("name"):
            pn = add_cac(party, "PartyName")
            add_cbc(pn, "Name", data.get("name"))
        if data.get("address_line") or data.get("country_code"):
            addr = add_cac(party, "PostalAddress")
            if data.get("address_line"):
                line = add_cac(addr, "AddressLine")
                add_cbc(line, "Line", data.get("address_line"))
            if data.get("country_code"):
                country = add_cac(addr, "Country")
                add_cbc(country, "IdentificationCode", data.get("country_code"))
        if data.get("tax_reg_name") or data.get("tax_company_id") or data.get("tax_scheme_id"):
            pts = add_cac(party, "PartyTaxScheme")
            add_cbc(pts, "RegistrationName", data.get("tax_reg_name"))
            add_cbc(pts, "CompanyID", data.get("tax_company_id"))
            if data.get("tax_scheme_id"):
                ts = add_cac(pts, "TaxScheme")
                add_cbc(ts, "ID", data.get("tax_scheme_id"))
        if data.get("legal_name") or data.get("legal_company_id"):
            ple = add_cac(party, "PartyLegalEntity")
            add_cbc(ple, "RegistrationName", data.get("legal_name"))
            add_cbc(ple, "CompanyID", data.get("legal_company_id"))

    build_party("AccountingSupplierParty", form.get("supplier", {}))
    build_party("AccountingCustomerParty", form.get("customer", {}))

    pay = form.get("payment", {})
    if any(pay.values()):
        pm = add_cac(inv, "PaymentMeans")
        add_cbc(pm, "PaymentMeansCode", pay.get("means_code"))
        if pay.get("iban") or pay.get("bic"):
            acc = add_cac(pm, "PayeeFinancialAccount")
            add_cbc(acc, "ID", pay.get("iban"))
            if pay.get("bic"):
                br = add_cac(acc, "FinancialInstitutionBranch")
                add_cbc(br, "ID", pay.get("bic"))

    tx = form.get("tax", {})
    if any(tx.values()):
        tt = add_cac(inv, "TaxTotal")
        add_cbc(tt, "TaxAmount", tx.get("total_amount"), {"currencyID": currency})
        if tx.get("subtotal_taxable") or tx.get("subtotal_tax") or tx.get("category_id") or tx.get("category_name") or tx.get("category_percent") or tx.get("category_scheme"):
            ts = add_cac(tt, "TaxSubtotal")
            add_cbc(ts, "TaxableAmount", tx.get("subtotal_taxable"), {"currencyID": currency})
            add_cbc(ts, "TaxAmount", tx.get("subtotal_tax"), {"currencyID": currency})
            if tx.get("category_id") or tx.get("category_name") or tx.get("category_percent") or tx.get("category_scheme"):
                cat = add_cac(ts, "TaxCategory")
                add_cbc(cat, "ID", tx.get("category_id"))
                add_cbc(cat, "Name", tx.get("category_name"))
                add_cbc(cat, "Percent", tx.get("category_percent"))
                if tx.get("category_scheme"):
                    sch = add_cac(cat, "TaxScheme")
                    add_cbc(sch, "ID", tx.get("category_scheme"))

    totals = form.get("totals", {})
    if any(totals.values()):
        lmt = add_cac(inv, "LegalMonetaryTotal")
        add_cbc(lmt, "LineExtensionAmount", totals.get("line_ext"), {"currencyID": currency})
        add_cbc(lmt, "TaxExclusiveAmount", totals.get("tax_excl"), {"currencyID": currency})
        add_cbc(lmt, "TaxInclusiveAmount", totals.get("tax_incl"), {"currencyID": currency})
        add_cbc(lmt, "PrepaidAmount", totals.get("prepaid"), {"currencyID": currency})
        add_cbc(lmt, "PayableAmount", totals.get("payable"), {"currencyID": currency})
    else:
        lmt = add_cac(inv, "LegalMonetaryTotal")
        add_cbc(lmt, "PayableAmount", "0.00", {"currencyID": currency})

    for i, ln in enumerate(form.get("lines", []), start=1):
        il = add_cac(inv, "InvoiceLine")
        add_cbc(il, "ID", ln.get("id") or str(i))
        add_cbc(il, "InvoicedQuantity", ln.get("qty"), {"unitCode": ln.get("unit_code")})
        add_cbc(il, "LineExtensionAmount", ln.get("line_ext"), {"currencyID": currency})
        if ln.get("allow_charge_indicator") or ln.get("allow_reason") or ln.get("allow_amount"):
            ac = add_cac(il, "AllowanceCharge")
            add_cbc(ac, "ChargeIndicator", ln.get("allow_charge_indicator"))
            add_cbc(ac, "AllowanceChargeReason", ln.get("allow_reason"))
            add_cbc(ac, "Amount", ln.get("allow_amount"), {"currencyID": currency})
        item = add_cac(il, "Item")
        add_cbc(item, "Name", ln.get("item_name"))
        if ln.get("tax_id") or ln.get("tax_percent") or ln.get("tax_scheme"):
            cat = add_cac(item, "ClassifiedTaxCategory")
            add_cbc(cat, "ID", ln.get("tax_id"))
            add_cbc(cat, "Percent", ln.get("tax_percent"))
            if ln.get("tax_scheme"):
                ts = add_cac(cat, "TaxScheme")
                add_cbc(ts, "ID", ln.get("tax_scheme"))
        if ln.get("price_amount") or ln.get("base_qty"):
            price = add_cac(il, "Price")
            add_cbc(price, "PriceAmount", ln.get("price_amount"), {"currencyID": ln.get("price_currency") or currency})
            add_cbc(price, "BaseQuantity", ln.get("base_qty"))

    return etree.tostring(inv, pretty_print=True, xml_declaration=True, encoding="UTF-8")
