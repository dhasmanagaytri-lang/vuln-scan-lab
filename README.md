# Vuln Scan Lab: Web Vulnerability Scanner and VAPT Report

[![CI](https://github.com/dhasmanagaytri-lang/vuln-scan-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/dhasmanagaytri-lang/vuln-scan-lab/actions/workflows/ci.yml)

A self-contained penetration-testing exercise in Python. It includes:

1. **LabShop**, a deliberately vulnerable web app (with a remediated build) that runs on localhost only.
2. **A scanner** that finds the planted weaknesses, scores them with a CVSS v3.1 calculator, and maps
   them to OWASP Top 10 (2021) and CWE.
3. **A VAPT report** (Markdown and PDF) with findings, evidence, remediation, and a **retest**
   showing the findings disappear after the fixes.

**Tech:** Python 3, Flask, requests, SQLite, pytest. Nothing leaves your machine.

> The target app is intentionally insecure. It binds to `127.0.0.1` only and has no option to
> listen elsewhere. Do not deploy it. Only scan systems you own or are authorized to test.

## Quick start

```bash
pip install -r requirements.txt
python run_lab.py        # scans vulnerable build, scans fixed build, writes reports/
pytest -q                # 19 tests
```

Or step by step:

```bash
python target/vulnapp.py --port 5055                    # terminal 1 (add --secure for the fixed build)
python -m scanner scan --target http://127.0.0.1:5055 --ports 2121,5055 --out reports/before
python -m scanner compare reports/before/findings.json reports/after/findings.json
```

## What the scanner checks

| Check | Technique | OWASP 2021 | CWE |
|---|---|---|---|
| SQL injection | error-based, boolean-based, login auth bypass | A03 Injection | 89 |
| Reflected XSS | unique marker reflected unencoded in HTML | A03 Injection | 79 |
| Broken access control | unauthenticated `/admin`; sequential-ID user API (IDOR) | A01 | 306 / 639 |
| Exposed files | `/.env`, `/backup.sql`, `/.git/HEAD` (values redacted in evidence) | A05 | 538 |
| Verbose errors | database error text shown to users | A05 | 209 |
| Security headers | CSP, X-Frame-Options, nosniff, Referrer-Policy | A05 | 693 |
| Cookie flags | missing HttpOnly / SameSite (and Secure on HTTPS) | A05 | 1004 |
| Server banner | software and version disclosure | A05 | 200 |
| Port scan | threaded TCP connect scan, banner grab, known-vulnerable banner to CVE | A06 | 1395 |

All probes are non-destructive: a quote character, an always-true/false condition, or a unique
marker string. The scanner does not extract data, exploit, or brute-force.

## Results (default run)

| | Critical | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|---|
| Before fixes | 3 | 6 | 2 | 3 | 2 | 16 |
| After fixes | 0 | 0 | 0 | 0 | 1 | 1 |

Retest: **15 fixed, 0 new**. The one remaining item is informational: the web port itself is open,
which is expected for a web server. See [`reports/VAPT_Report.md`](reports/VAPT_Report.md) and the PDF.

The fixes (see `create_app(secure=True)` in `target/vulnapp.py`) include parameterized queries, output
encoding, authentication plus ownership checks on the API, a role check on `/admin`, removing exposed files, generic
error messages, security headers, random HttpOnly/SameSite session cookies, a generic server banner, and no
legacy service.

## Design notes

- **CVSS v3.1 calculator** (`scanner/cvss.py`) implements the FIRST specification, including the
  scope-changed formula and the spec's round-up function. Tests check it against published scores
  (9.8, 6.1, 7.5, 7.8, 10.0, 0.0).
- **Avoiding false positives.** The boolean-based SQLi check strips the injected payload (raw and
  HTML-escaped) from each response before comparing, so an app that merely *echoes* the input is not
  flagged. The remediated app is the test: it reports no SQLi.
- **Authorization guard** (`scanner/guard.py`). Non-loopback, non-private targets are refused unless
  `--i-am-authorized` is passed; tests verify the CLI refuses a public IP before sending any request.
- **Retest logic** matches findings by `(id, location, parameter)` so the report can state exactly
  what was fixed, what remains, and what is new.

## Limitations (please read)

- This is a small, purpose-built learning scanner. It is **not** a replacement for Burp Suite, Nmap,
  or Nessus, and it only finds the classes listed above.
- CVSS vectors are the author's contextual estimates for this lab app, not vendor-assigned scores.
- The "legacy service" is a simulated text banner (`220 (vsFTPd 2.3.4)`) so the scanner's
  banner-to-CVE logic can be demonstrated. It is not a real FTP server and contains no backdoor.
  The CVE table has one entry.
- A clean rescan means these checks found nothing, not that the app is secure. Passwords in the lab
  database use unsalted SHA-256 for brevity, which you should not copy into real code.

## Ideas to extend it

Run the same LabShop target through Burp Suite, Nmap and Nessus and add their results next to this
scanner's findings. That comparison is a good way to learn what each tool does and misses. Other
extensions: add CSRF and open-redirect checks, an HTML report, or a JSON-to-SARIF exporter.

## License

MIT
