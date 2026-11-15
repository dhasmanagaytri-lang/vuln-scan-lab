"""Report rendering and before/after retest comparison."""
import json
from collections import Counter
from datetime import datetime, timezone

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def sort_findings(findings):
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    return sorted(findings, key=lambda f: (rank[f["severity"]], -f["cvss_score"], f["key"]))


def to_json(findings, meta):
    return json.dumps({"meta": meta,
                       "findings": sort_findings([f.to_dict() for f in findings])}, indent=2)


def render_markdown(data, title="Vulnerability Assessment Report"):
    meta, findings = data["meta"], data["findings"]
    counts = Counter(f["severity"] for f in findings)
    L = [f"# {title}", "",
         "## 1. Scope and method", "",
         f"- **Target:** `{meta['target']}`",
         f"- **Ports scanned:** `{meta['ports']}`",
         f"- **Date (UTC):** {meta['date']}",
         "- **Method:** automated, non-destructive probing (headers, cookies, exposed files, "
         "access control, reflected XSS, SQL injection indicators, TCP connect scan with banner grab).",
         "- **Scoring:** CVSS v3.1 base scores computed from the vector shown for each finding. "
         "The vectors are the assessor's contextual estimates for this lab application.", "",
         "## 2. Summary", "",
         "| Severity | Count |", "|---|---|"]
    L += [f"| {s} | {counts.get(s, 0)} |" for s in SEV_ORDER]
    L += ["", f"**Total findings: {len(findings)}**", "",
          "| # | Severity | CVSS | Finding | Location | OWASP / CWE |", "|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        loc = f["url"] + (f" (`{f['param']}`)" if f["param"] else "")
        score = f"{f['cvss_score']:.1f}" if f["vector"] else "-"
        L.append(f"| {i} | {f['severity']} | {score} | {f['title']} | {loc} | "
                 f"{f['owasp'].split(' ')[0]} / {f['cwe']} |")
    L += ["", "## 3. Detailed findings", ""]
    for i, f in enumerate(findings, 1):
        L += [f"### {i}. {f['title']} ({f['severity']})", "",
              f"- **Location:** {f['url']}" + (f", parameter `{f['param']}`" if f["param"] else ""),
              f"- **OWASP Top 10:** {f['owasp']}", f"- **CWE:** {f['cwe']}"]
        if f["vector"]:
            L.append(f"- **CVSS v3.1:** {f['cvss_score']:.1f} `{f['vector']}`")
        L += [f"- **Evidence:** {f['evidence']}", f"- **Remediation:** {f['remediation']}", ""]
    return "\n".join(L)


def compare(before, after):
    b = {f["key"]: f for f in before["findings"]}
    a = {f["key"]: f for f in after["findings"]}
    fixed = [b[k] for k in b if k not in a]
    remaining = [a[k] for k in a if k in b]
    new = [a[k] for k in a if k not in b]
    return {"fixed": sort_findings(fixed), "remaining": sort_findings(remaining),
            "new": sort_findings(new), "before_total": len(b), "after_total": len(a)}


def render_retest(before, after, cmp_):
    def sev_counts(d):
        c = Counter(f["severity"] for f in d["findings"])
        return [str(c.get(s, 0)) for s in SEV_ORDER]

    L = ["## 4. Remediation retest", "",
         f"The remediated build was scanned with the same scanner and settings "
         f"({after['meta']['date']}).", "",
         "| | " + " | ".join(SEV_ORDER) + " | Total |", "|---|" + "---|" * (len(SEV_ORDER) + 1),
         "| Before | " + " | ".join(sev_counts(before)) + f" | {cmp_['before_total']} |",
         "| After | " + " | ".join(sev_counts(after)) + f" | {cmp_['after_total']} |", "",
         f"- **Fixed:** {len(cmp_['fixed'])}",
         f"- **Still present:** {len(cmp_['remaining'])}",
         f"- **New:** {len(cmp_['new'])}", ""]
    for label, key in (("Fixed", "fixed"), ("Still present", "remaining"), ("New", "new")):
        if cmp_[key]:
            L += [f"### {label}", "", "| Severity | Finding | Location |", "|---|---|---|"]
            for f in cmp_[key]:
                loc = f["url"] + (f" (`{f['param']}`)" if f["param"] else "")
                L.append(f"| {f['severity']} | {f['title']} | {loc} |")
            L.append("")
    return "\n".join(L)


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
