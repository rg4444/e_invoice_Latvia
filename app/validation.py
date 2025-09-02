from lxml import etree


def validate_xsd(xml_str: str, xsd_path: str):
    try:
        parser = etree.XMLParser(resolve_entities=False)
        with open(xsd_path, "rb") as f:
            schema_doc = etree.parse(f, parser)
        schema = etree.XMLSchema(schema_doc)
        doc = etree.fromstring(xml_str.encode("utf-8"))
        schema.assertValid(doc)
        return True, []
    except etree.DocumentInvalid as e:
        return False, [str(x) for x in schema.error_log]
    except Exception as e:
        return False, [f"Validator error: {e}"]
