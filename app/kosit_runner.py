import os, subprocess, time, pathlib, shlex
from typing import Dict

KOSIT_JAR = os.environ.get("KOSIT_JAR") or "/opt/kosit/bin/validator-1.5.2-standalone.jar"
KOSIT_CONF_DIR = os.environ.get("KOSIT_CONF_DIR") or "/data/kosit/bis"

def run_kosit(invoice_path: str, out_dir: str, html_report: bool = True) -> Dict:
    invoice_path = os.path.abspath(invoice_path)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    scenarios = os.path.join(KOSIT_CONF_DIR, "scenarios.xml")
    repo_dir  = KOSIT_CONF_DIR  # contains scenarios.xml and resources/

    if not os.path.exists(KOSIT_JAR):
        return {"ok": False, "error": f"KoSIT jar not found: {KOSIT_JAR}"}
    if not os.path.exists(scenarios):
        return {"ok": False, "error": f"scenarios.xml not found at: {scenarios}"}
    if not os.path.exists(invoice_path):
        return {"ok": False, "error": f"Invoice not found: {invoice_path}"}

    cmd = [
        "java", "-jar", KOSIT_JAR,
        "-s", scenarios,
        "-r", repo_dir,
        "-o", out_dir
    ]
    if html_report:
        cmd.append("-h")
    cmd.append(invoice_path)

    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    dt = round((time.time() - t0) * 1000)

    # KoSIT writes <file>-report.xml (+ html)
    stem = pathlib.Path(invoice_path).name
    xml_report = os.path.join(out_dir, f"{stem}-report.xml")
    html_report_path = os.path.join(out_dir, f"{stem}-report.html") if html_report else None

    result = {
        "ok": p.returncode == 0 and os.path.exists(xml_report),
        "took_ms": dt,
        "cmd": " ".join(shlex.quote(x) for x in cmd),
        "exit_code": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
        "xml_report": xml_report if os.path.exists(xml_report) else "",
        "html_report": html_report_path if (html_report and os.path.exists(html_report_path)) else ""
    }
    return result
