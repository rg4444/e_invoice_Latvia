from lxml import etree


def _el(tag, nsmap=None, text=None):
    el = etree.Element(tag, nsmap=nsmap) if nsmap else etree.Element(tag)
    if text is not None:
        el.text = text
    return el


def _safe_tag(ns_prefix, local):
    return f"{{{ns_prefix}}}{local}" if ns_prefix and local else local


def _walk_part(el, xsd_type, depth=0, max_depth=4):
    """Very simple recursive skeleton: sequences/elements -> empty tags, simple types -> placeholder text."""
    if depth > max_depth or xsd_type is None:
        return
    if hasattr(xsd_type, "elements"):
        for name, sub in xsd_type.elements:
            child = etree.SubElement(el, name.text if hasattr(name, "text") else name)
            sub_type = getattr(sub, "type", None)
            if sub_type is not None and getattr(sub_type, "elements", None):
                _walk_part(child, sub_type, depth + 1, max_depth)
            else:
                child.text = "<value>"
    else:
        el.text = "<value>"


def build_body_template(client, service_name, port_name, operation_name):
    """Return <ns:Operation>...</ns:Operation> skeleton based on input body type."""
    svc = client.wsdl.services[service_name]
    port = svc.ports[port_name]
    op = port.binding._operations[operation_name]

    target_ns = port.binding.wsdl.port_type._name.namespace
    nsmap = {"tns": target_ns}

    root = _el(_safe_tag(target_ns, operation_name), nsmap=nsmap)

    body = getattr(op.input, "body", None)
    if body is not None and getattr(body, "type", None) is not None:
        _walk_part(root, body.type)
    else:
        etree.SubElement(root, "payload").text = "<value>"

    return etree.tostring(root, encoding="utf-8", pretty_print=True).decode("utf-8")
