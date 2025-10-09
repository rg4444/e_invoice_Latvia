import os
import subprocess
import tempfile

from lxml import etree

SVRL_NS = {"svrl": "http://purl.oclc.org/dsdl/svrl"}
SAXON_JAR = os.environ.get("SAXON_JAR", "/opt/saxon/saxon-he.jar")
XML_RESOLVER_JAR = os.environ.get("XML_RESOLVER_JAR", "/opt/saxon/xmlresolver.jar")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
ISO_DIR = os.environ.get("ISO_SCHEMATRON_DIR", os.path.join(ROOT_DIR, "data", "schematron", "iso"))
ISO_DSDL_INCLUDE = os.environ.get("ISO_DSDL_INCLUDE", os.path.join(ISO_DIR, "iso_dsdl_include.xsl"))
ISO_ABSTRACT_EXPAND = os.environ.get("ISO_ABSTRACT_EXPAND", os.path.join(ISO_DIR, "iso_abstract_expand.xsl"))
ISO_SVRL_FOR_XSLT2 = os.environ.get("ISO_SVRL_FOR_XSLT2", os.path.join(ISO_DIR, "iso_svrl_for_xslt2.xsl"))


def _saxon_command(src: str, xslt_path: str, out: str) -> list[str]:
    """Build the Java command for invoking Saxon."""

    if XML_RESOLVER_JAR and os.path.exists(XML_RESOLVER_JAR):
        classpath = os.pathsep.join(filter(None, [SAXON_JAR, XML_RESOLVER_JAR]))
        return [
            "java",
            "-cp",
            classpath,
            "net.sf.saxon.Transform",
            f"-s:{src}",
            f"-xsl:{xslt_path}",
            f"-o:{out}",
        ]
    return [
        "java",
        "-jar",
        SAXON_JAR,
        f"-s:{src}",
        f"-xsl:{xslt_path}",
        f"-o:{out}",
    ]


def _parse_svrl(svrl: str) -> tuple[bool, list[str], etree._Element | None]:
    """Parse SVRL XML and collect issues."""

    if not svrl:
        return False, ["Empty SVRL report"], None

    try:
        doc = etree.fromstring(svrl.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive guard
        lowered = svrl.lower()
        if "<html" in lowered and "</html>" in lowered:
            return False, [
                "Selected stylesheet does not produce SVRL output (looks like HTML preview). "
                "Please choose a compiled Schematron ruleset.",
            ], None
        return False, [f"SVRL parse error: {exc}"], None

    fails = doc.xpath("//svrl:failed-assert", namespaces=SVRL_NS)
    warns = doc.xpath("//svrl:successful-report", namespaces=SVRL_NS)

    issues: list[str] = []
    for node in fails:
        loc = node.get("location", "")
        test = node.get("test", "")
        text_el = node.find("svrl:text", namespaces=SVRL_NS)
        msg = (text_el.text or "").strip() if text_el is not None else ""
        issues.append(f"[FAIL] {msg} @ {loc} (test: {test})")

    for node in warns:
        loc = node.get("location", "")
        test = node.get("test", "")
        text_el = node.find("svrl:text", namespaces=SVRL_NS)
        msg = (text_el.text or "").strip() if text_el is not None else ""
        issues.append(f"[WARN] {msg} @ {loc} (test: {test})")

    ok = len([i for i in issues if i.startswith("[FAIL]")]) == 0
    return ok, issues, doc


def run_schematron_xslt(invoice_xml_text: str, xslt_path: str):
    """Execute compiled Schematron XSLT (SVRL output) using Saxon-HE."""

    if not os.path.exists(xslt_path):
        return False, "", [f"Ruleset not found: {xslt_path}"]

    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "invoice.xml")
        out = os.path.join(td, "report.svrl.xml")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(invoice_xml_text)
        cmd = _saxon_command(src, xslt_path, out)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return False, "", [f"Saxon error: {proc.stderr.strip() or proc.stdout.strip()}"]
        with open(out, "r", encoding="utf-8") as fh:
            svrl = fh.read()

    ok, issues, _ = _parse_svrl(svrl)
    return ok, svrl, issues


def run_schematron_sch(invoice_xml_text: str, schematron_path: str):
    """Execute a Schematron ruleset (.sch) by compiling it to XSLT 2.0."""

    if not os.path.exists(schematron_path):
        return False, "", [f"Ruleset not found: {schematron_path}"]

    missing = [
        path
        for path in (ISO_DSDL_INCLUDE, ISO_ABSTRACT_EXPAND, ISO_SVRL_FOR_XSLT2)
        if not os.path.exists(path)
    ]
    if missing:
        return False, "", [f"Schematron compiler prerequisites missing: {', '.join(missing)}"]

    with tempfile.TemporaryDirectory() as td:
        stage1 = os.path.join(td, "stage1.sch")
        stage2 = os.path.join(td, "stage2.sch")
        compiled = os.path.join(td, "compiled.xslt")
        pipeline = [
            (schematron_path, ISO_DSDL_INCLUDE, stage1),
            (stage1, ISO_ABSTRACT_EXPAND, stage2),
            (stage2, ISO_SVRL_FOR_XSLT2, compiled),
        ]
        for src, xsl, dst in pipeline:
            cmd = _saxon_command(src, xsl, dst)
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown Saxon error"
                return False, "", [f"Schematron compilation error: {msg}"]
        return run_schematron_xslt(invoice_xml_text, compiled)


def run_schematron(invoice_xml_text: str, ruleset_path: str):
    """Validate ``invoice_xml_text`` using a Schematron ruleset."""

    lower = ruleset_path.lower()
    if lower.endswith((".xsl", ".xslt")):
        return run_schematron_xslt(invoice_xml_text, ruleset_path)
    if lower.endswith(".sch"):
        return run_schematron_sch(invoice_xml_text, ruleset_path)
    return False, "", ["Unsupported Schematron ruleset format"]
