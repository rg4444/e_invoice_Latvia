from lxml import etree


def validate_xsd(xml_str: str, xsd_path: str):
    try:
        schema_doc = etree.parse(xsd_path)
        schema = etree.XMLSchema(schema_doc)
        doc = etree.fromstring(xml_str.encode("utf-8"))
        schema.assertValid(doc)
        return True, []
    except etree.DocumentInvalid as e:
        return False, [str(x) for x in e.error_log]
    except Exception as e:
        return False, [f"Validator error: {e}"]
