"""CLI.

  python -m scanner scan --target http://127.0.0.1:5055 --ports 2121,5055 --out reports/before
  python -m scanner compare reports/before/findings.json reports/after/findings.json
"""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import checks, portscan, report
from .guard import UnauthorizedTarget, check_target

LEGAL = ("Only scan systems you own or have explicit written permission to test. "
         "Unauthorized scanning may be illegal.")


def cmd_scan(args):
    try:
        host = check_target(args.target, args.i_am_authorized)
    except UnauthorizedTarget as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if args.i_am_authorized:
        print(f"[!] {LEGAL}", file=sys.stderr)
    ports = portscan.parse_ports(args.ports)
    findings = checks.run_web_checks(args.target)
    open_ports = portscan.scan(host, ports)
    findings += checks.port_findings(urlparse(args.target).hostname or host, open_ports)

    meta = {"target": args.target, "ports": args.ports, "date": report.now_utc(),
            "scanner_version": "1.0.0"}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(report.to_json(findings, meta), encoding="utf-8")
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    (out / "report.md").write_text(report.render_markdown(data, args.title), encoding="utf-8")

    sev = {}
    for f in data["findings"]:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    print(f"{len(findings)} findings: " + ", ".join(
        f"{sev.get(s, 0)} {s}" for s in report.SEV_ORDER) + f"  -> {out}/")
    return 0


def cmd_compare(args):
    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    cmp_ = report.compare(before, after)
    text = report.render_retest(before, after, cmp_)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(f"fixed={len(cmp_['fixed'])} remaining={len(cmp_['remaining'])} new={len(cmp_['new'])}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="scanner", description=LEGAL)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a target")
    s.add_argument("--target", required=True, help="base URL, e.g. http://127.0.0.1:5055")
    s.add_argument("--ports", default="1-1024", help="e.g. 1-1024,2121,5055")
    s.add_argument("--out", default="reports/scan")
    s.add_argument("--title", default="Vulnerability Assessment Report")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="confirm you have permission to test a non-local target")
    s.set_defaults(func=cmd_scan)
    c = sub.add_parser("compare", help="compare two findings.json files (retest)")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--out")
    c.set_defaults(func=cmd_compare)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
