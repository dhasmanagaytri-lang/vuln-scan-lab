# Vulnerability Assessment Report: LabShop (after fixes)

## 1. Scope and method

- **Target:** `http://127.0.0.1:5055`
- **Ports scanned:** `2121,5055`
- **Date (UTC):** 2026-11-14 14:51
- **Method:** automated, non-destructive probing (headers, cookies, exposed files, access control, reflected XSS, SQL injection indicators, TCP connect scan with banner grab).
- **Scoring:** CVSS v3.1 base scores computed from the vector shown for each finding. The vectors are the assessor's contextual estimates for this lab application.

## 2. Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 1 |

**Total findings: 1**

| # | Severity | CVSS | Finding | Location | OWASP / CWE |
|---|---|---|---|---|---|
| 1 | Info | - | Open TCP port 5055 (unknown) | 127.0.0.1:5055 (`5055`) | A05:2021 / CWE-200 |

## 3. Detailed findings

### 1. Open TCP port 5055 (unknown) (Info)

- **Location:** 127.0.0.1:5055, parameter `5055`
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200
- **Evidence:** Port 5055 accepted a connection;
- **Remediation:** Close ports that are not required and restrict the rest with a firewall.
