from lxml import etree


def _el(tag, nsmap=None, text=None):
    el = etree.Element(tag, nsmap=nsmap) if nsmap else etree.Element(tag)
    if text is not None:
        el.text = text
    return el


def _walk_part(el, xsd_type, depth=0, max_depth=4):
    """Minimal recursive skeleton: complex types -> child elements; simple types -> <value>."""
    if depth > max_depth or xsd_type is None:
        return
    # complexType
    if hasattr(xsd_type, "elements"):
        try:
            for name, sub in xsd_type.elements:
                # name may be a QName or string
                tag = getattr(name, "text", None) or str(name)
                child = etree.SubElement(el, tag)
                sub_type = getattr(sub, "type", None)
                if sub_type is not None and getattr(sub_type, "elements", None):
                    _walk_part(child, sub_type, depth+1, max_depth)
                else:
                    child.text = "<value>"
        except Exception:
            el.text = "<value>"
    else:
        el.text = "<value>"


def _resolve_namespace_from_op(client, service_name, port_name, operation_name):
    svc = client.wsdl.services[service_name]
    port = svc.ports[port_name]
    op = port.binding._operations[operation_name]
    # Prefer the input body type QName namespace
    body = getattr(op.input, "body", None)
    if body is not None:
        tp = getattr(body, "type", None)
        qn = getattr(tp, "qname", None)
        if qn is not None and getattr(qn, "namespace", None):
            return qn.namespace
    # Fallback to WSDL tns
    return getattr(client.wsdl, "tns", None)


def build_body_template(client, service_name, port_name, operation_name):
    svc = client.wsdl.services[service_name]
    port = svc.ports[port_name]
    op = port.binding._operations[operation_name]

    target_ns = _resolve_namespace_from_op(client, service_name, port_name, operation_name)
    nsmap = {"tns": target_ns} if target_ns else None

    # Root element name: use the operation name in the target namespace if possible
    # For document/literal wrapped, this is usually correct.
    root_tag = f"{{{target_ns}}}{operation_name}" if target_ns else operation_name
    root = _el(root_tag, nsmap=nsmap)

    body = getattr(op.input, "body", None)
    if body is not None and getattr(body, "type", None) is not None:
        _walk_part(root, body.type)
    else:
        etree.SubElement(root, "payload").text = "<value>"

    return etree.tostring(root, encoding="utf-8", pretty_print=True).decode("utf-8")

