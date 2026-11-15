#!/usr/bin/env python3
"""End-to-end lab run.

1. Start the vulnerable LabShop app on localhost and scan it  -> reports/before/
2. Stop it, start the remediated build on the same ports, rescan -> reports/after/
3. Compare the two scans (retest) and build the combined report -> reports/VAPT_Report.md
   (and a PDF if pandoc + wkhtmltopdf are installed).

Everything runs on 127.0.0.1 only.
"""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scanner import report
from scanner.__main__ import main as scanner_main
from target.vulnapp import serve_in_thread

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
WEB_PORT, LEGACY_PORT = 5055, 2121
PORTS = f"{LEGACY_PORT},{WEB_PORT}"


def scan(secure, out, title):
    app = serve_in_thread(secure=secure, port=WEB_PORT, legacy_port=LEGACY_PORT)
    time.sleep(0.3)
    try:
        code = scanner_main(["scan", "--target", app.url, "--ports", PORTS,
                             "--out", str(out), "--title", title])
    finally:
        app.stop()
    return code


def build_pdf(md_path):
    if not (shutil.which("pandoc") and shutil.which("wkhtmltopdf")):
        print("pandoc/wkhtmltopdf not found; skipping PDF")
        return
    html = md_path.with_suffix(".html")
    css = ("<style>html,body{max-width:none!important;margin:0!important;padding:0!important}"
           "body{font-family:Arial,sans-serif;font-size:11px;line-height:1.4}"
           "table{border-collapse:collapse;width:100%;margin:8px 0}"
           "th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}"
           "th{background:#eee}code{font-size:11px;word-break:break-all}"
           "h1{border-bottom:2px solid #333}</style>")
    subprocess.run(["pandoc", "-f", "gfm", "-t", "html5", "-s", "--metadata", "pagetitle=VAPT Report",
                    "-H", "/dev/stdin", "-o", str(html), str(md_path)],
                   input=css.encode(), check=True)
    subprocess.run(["wkhtmltopdf", "--quiet", "--page-size", "A4", "-T", "14", "-B", "14", "-L", "14", "-R", "14", str(html), str(md_path.with_suffix(".pdf"))],
                   check=False)
    html.unlink(missing_ok=True)


def main():
    REPORTS.mkdir(exist_ok=True)
    print("== Scan 1: vulnerable build ==")
    scan(False, REPORTS / "before", "Vulnerability Assessment Report: LabShop (before fixes)")
    print("== Scan 2: remediated build ==")
    scan(True, REPORTS / "after", "Vulnerability Assessment Report: LabShop (after fixes)")

    before = json.loads((REPORTS / "before" / "findings.json").read_text(encoding="utf-8"))
    after = json.loads((REPORTS / "after" / "findings.json").read_text(encoding="utf-8"))
    cmp_ = report.compare(before, after)
    print(f"retest: fixed={len(cmp_['fixed'])} remaining={len(cmp_['remaining'])} new={len(cmp_['new'])}")

    combined = report.render_markdown(before, "VAPT Report: LabShop Practice Application")
    combined += "\n\n" + report.render_retest(before, after, cmp_)
    combined += ("\n\n## 5. Notes and limitations\n\n"
                 "- The target is a deliberately vulnerable practice application run on localhost.\n"
                 "- The scanner uses non-destructive indicator checks; it does not exploit or extract data.\n"
                 "- A clean rescan means these specific checks found nothing, not that the application "
                 "is free of vulnerabilities. Manual testing would still be required.\n")
    md = REPORTS / "VAPT_Report.md"
    md.write_text(combined, encoding="utf-8")
    build_pdf(md)
    print(f"report written: {md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
