import os
import subprocess
import tempfile

from lxml import etree

SVRL_NS = {"svrl": "http://purl.oclc.org/dsdl/svrl"}
SAXON_JAR = os.environ.get("SAXON_JAR", "/opt/saxon/saxon-he.jar")
XML_RESOLVER_JAR = os.environ.get("XML_RESOLVER_JAR", "/opt/saxon/xmlresolver.jar")


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

def run_schematron_xslt(invoice_xml_text: str, xslt_path: str):
    """
    Execute compiled Schematron XSLT (SVRL output) using Saxon-HE.
    Returns (ok: bool, svrl_xml: str, errors: list[str])
    """
    if not os.path.exists(xslt_path):
        return False, "", [f"Ruleset not found: {xslt_path}"]
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "invoice.xml")
        out = os.path.join(td, "report.svrl.xml")
        with open(src, "w", encoding="utf-8") as f:
            f.write(invoice_xml_text)
        cmd = _saxon_command(src, xslt_path, out)
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            return False, "", [f"Saxon error: {p.stderr.strip() or p.stdout.strip()}"]
        with open(out, "r", encoding="utf-8") as f:
            svrl = f.read()
    # Parse SVRL, collect failures
    try:
        doc = etree.fromstring(svrl.encode("utf-8"))
    except Exception as e:
        # Some stylesheets (e.g. Peppol's HTML invoice viewer) generate HTML
        # instead of SVRL.  Provide a clearer error message when that happens
        # so users understand they selected the wrong ruleset.
        if "<html" in svrl.lower():
            return False, svrl, [
                "Selected stylesheet does not produce SVRL output (looks like HTML preview). "
                "Please choose a compiled Schematron ruleset."
            ]
        return False, svrl, [f"SVRL parse error: {e}"]
    fails = doc.xpath("//svrl:failed-assert", namespaces=SVRL_NS)
    warns = doc.xpath("//svrl:successful-report", namespaces=SVRL_NS)  # optional: some rule sets use this for warnings
    errs = []
    for n in fails:
        loc = n.get("location", "")
        test = n.get("test", "")
        text_el = n.find("svrl:text", namespaces=SVRL_NS)
        msg = (text_el.text or "").strip() if text_el is not None else ""
        errs.append(f"[FAIL] {msg} @ {loc} (test: {test})")
    for n in warns:
        loc = n.get("location", "")
        test = n.get("test", "")
        text_el = n.find("svrl:text", namespaces=SVRL_NS)
        msg = (text_el.text or "").strip() if text_el is not None else ""
        errs.append(f"[WARN] {msg} @ {loc} (test: {test})")
    ok = len([e for e in errs if e.startswith("[FAIL]")]) == 0
    return ok, svrl, errs
