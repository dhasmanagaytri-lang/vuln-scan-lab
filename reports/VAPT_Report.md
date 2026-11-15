# VAPT Report: LabShop Practice Application

## 1. Scope and method

- **Target:** `http://127.0.0.1:5055`
- **Ports scanned:** `2121,5055`
- **Date (UTC):** 2026-11-14 14:51
- **Method:** automated, non-destructive probing (headers, cookies, exposed files, access control, reflected XSS, SQL injection indicators, TCP connect scan with banner grab).
- **Scoring:** CVSS v3.1 base scores computed from the vector shown for each finding. The vectors are the assessor's contextual estimates for this lab application.

## 2. Summary

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 6 |
| Medium | 2 |
| Low | 3 |
| Info | 2 |

**Total findings: 16**

| # | Severity | CVSS | Finding | Location | OWASP / CWE |
|---|---|---|---|---|---|
| 1 | Critical | 9.8 | SQL injection allows authentication bypass | http://127.0.0.1:5055/login (`username`) | A03:2021 / CWE-89 |
| 2 | Critical | 9.8 | Service with known vulnerability (CVE-2011-2523) | 127.0.0.1:2121 (`2121`) | A06:2021 / CWE-1395 |
| 3 | Critical | 9.1 | Admin interface reachable without authentication | http://127.0.0.1:5055/admin | A01:2021 / CWE-306 |
| 4 | High | 8.2 | SQL injection (boolean-based) | http://127.0.0.1:5055/search (`q`) | A03:2021 / CWE-89 |
| 5 | High | 8.2 | SQL injection (error-based) | http://127.0.0.1:5055/login (`username`) | A03:2021 / CWE-89 |
| 6 | High | 8.2 | SQL injection (error-based) | http://127.0.0.1:5055/search (`q`) | A03:2021 / CWE-89 |
| 7 | High | 7.5 | Sensitive file publicly accessible | http://127.0.0.1:5055/.env | A05:2021 / CWE-538 |
| 8 | High | 7.5 | Sensitive file publicly accessible | http://127.0.0.1:5055/backup.sql | A05:2021 / CWE-538 |
| 9 | High | 7.5 | Insecure direct object reference exposes user records | http://127.0.0.1:5055/api/user/{id} | A01:2021 / CWE-639 |
| 10 | Medium | 6.1 | Reflected cross-site scripting | http://127.0.0.1:5055/search (`q`) | A03:2021 / CWE-79 |
| 11 | Medium | 5.3 | Verbose database errors disclosed to users | http://127.0.0.1:5055/search | A05:2021 / CWE-209 |
| 12 | Low | 3.7 | Server banner discloses software and version | http://127.0.0.1:5055/ | A05:2021 / CWE-200 |
| 13 | Low | 3.1 | Cookie set without security attributes | http://127.0.0.1:5055/ (`sid`) | A05:2021 / CWE-1004 |
| 14 | Low | 3.1 | Missing HTTP security headers | http://127.0.0.1:5055/ | A05:2021 / CWE-693 |
| 15 | Info | - | Open TCP port 2121 (unknown) | 127.0.0.1:2121 (`2121`) | A05:2021 / CWE-200 |
| 16 | Info | - | Open TCP port 5055 (unknown) | 127.0.0.1:5055 (`5055`) | A05:2021 / CWE-200 |

## 3. Detailed findings

### 1. SQL injection allows authentication bypass (Critical)

- **Location:** http://127.0.0.1:5055/login, parameter `username`
- **OWASP Top 10:** A03:2021 Injection
- **CWE:** CWE-89
- **CVSS v3.1:** 9.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Evidence:** Login with username "admin' -- " and a wrong password returned HTTP 200 (an unknown user returned 401)
- **Remediation:** Use parameterized queries, hash and compare passwords in application code, and add rate limiting / lockout.

### 2. Service with known vulnerability (CVE-2011-2523) (Critical)

- **Location:** 127.0.0.1:2121, parameter `2121`
- **OWASP Top 10:** A06:2021 Vulnerable and Outdated Components
- **CWE:** CWE-1395
- **CVSS v3.1:** 9.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Evidence:** Banner '220 (vsFTPd 2.3.4)' matches CVE-2011-2523: vsFTPd 2.3.4 shipped with a backdoor that opens a shell on port 6200
- **Remediation:** Upgrade to a supported, patched version or remove the service. Legacy plaintext protocols such as FTP should be replaced by SFTP/FTPS.

### 3. Admin interface reachable without authentication (Critical)

- **Location:** http://127.0.0.1:5055/admin
- **OWASP Top 10:** A01:2021 Broken Access Control
- **CWE:** CWE-306
- **CVSS v3.1:** 9.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **Evidence:** Unauthenticated GET returned HTTP 200 (59 bytes)
- **Remediation:** Require authentication and an admin-role check on every admin route; deny by default.

### 4. SQL injection (boolean-based) (High)

- **Location:** http://127.0.0.1:5055/search, parameter `q`
- **OWASP Top 10:** A03:2021 Injection
- **CWE:** CWE-89
- **CVSS v3.1:** 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Evidence:** Always-true and always-false conditions returned different results (205 vs 99 bytes)
- **Remediation:** Use parameterized queries / prepared statements.

### 5. SQL injection (error-based) (High)

- **Location:** http://127.0.0.1:5055/login, parameter `username`
- **OWASP Top 10:** A03:2021 Injection
- **CWE:** CWE-89
- **CVSS v3.1:** 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Evidence:** A single quote in 'username' triggered a database error: Database error: unrecognized token: "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a488...
- **Remediation:** Use parameterized queries / prepared statements.

### 6. SQL injection (error-based) (High)

- **Location:** http://127.0.0.1:5055/search, parameter `q`
- **OWASP Top 10:** A03:2021 Injection
- **CWE:** CWE-89
- **CVSS v3.1:** 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Evidence:** A single quote triggered a database error: Database error: unrecognized token: "'" Query: SELECT id, name, price FROM products WHERE name LIKE '%laptop'%...
- **Remediation:** Use parameterized queries / prepared statements for every query; never build SQL by string concatenation.

### 7. Sensitive file publicly accessible (High)

- **Location:** http://127.0.0.1:5055/.env
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-538
- **CVSS v3.1:** 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Evidence:** HTTP 200, 57 bytes, first line: DB_PASSWORD=<redacted>
- **Remediation:** Remove the file from the web root, deny access to dotfiles and backups at the web server, and rotate any secrets it contained.

### 8. Sensitive file publicly accessible (High)

- **Location:** http://127.0.0.1:5055/backup.sql
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-538
- **CVSS v3.1:** 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Evidence:** HTTP 200, 74 bytes, first line: -- LabShop backup (fake data)
- **Remediation:** Remove the file from the web root, deny access to dotfiles and backups at the web server, and rotate any secrets it contained.

### 9. Insecure direct object reference exposes user records (High)

- **Location:** http://127.0.0.1:5055/api/user/{id}
- **OWASP Top 10:** A01:2021 Broken Access Control
- **CWE:** CWE-639
- **CVSS v3.1:** 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Evidence:** Unauthenticated requests for ids [1, 2, 3] each returned HTTP 200 with id, username, email and role fields
- **Remediation:** Require authentication and verify the requesting user owns (or is authorized to view) the record; avoid sequential, guessable identifiers.

### 10. Reflected cross-site scripting (Medium)

- **Location:** http://127.0.0.1:5055/search, parameter `q`
- **OWASP Top 10:** A03:2021 Injection
- **CWE:** CWE-79
- **CVSS v3.1:** 6.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Evidence:** Marker markup '<svg onload=labc8c9f0d3>' returned unencoded in the HTML response
- **Remediation:** HTML-encode all user-controlled output (context-aware templating) and add a Content-Security-Policy.

### 11. Verbose database errors disclosed to users (Medium)

- **Location:** http://127.0.0.1:5055/search
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-209
- **CVSS v3.1:** 5.3 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Evidence:** Response exposed internal details: Database error: unrecognized token: "'" Query: SELECT id, name, price FROM products WHERE name LIKE '%laptop'%'
- **Remediation:** Return a generic error page, log details server-side only.

### 12. Server banner discloses software and version (Low)

- **Location:** http://127.0.0.1:5055/
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200
- **CVSS v3.1:** 3.7 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Evidence:** Server: Apache/2.2.8 (Ubuntu)
- **Remediation:** Remove version details from the Server header (e.g. ServerTokens Prod) and patch the server.

### 13. Cookie set without security attributes (Low)

- **Location:** http://127.0.0.1:5055/, parameter `sid`
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-1004
- **CVSS v3.1:** 3.1 `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`
- **Evidence:** Cookie 'sid' missing: HttpOnly, SameSite
- **Remediation:** Set HttpOnly and SameSite=Lax (or Strict) on session cookies, and Secure over HTTPS.

### 14. Missing HTTP security headers (Low)

- **Location:** http://127.0.0.1:5055/
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-693
- **CVSS v3.1:** 3.1 `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`
- **Evidence:** Absent: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Remediation:** Add the headers, e.g. Content-Security-Policy: default-src 'self'; X-Frame-Options: DENY; X-Content-Type-Options: nosniff; Referrer-Policy: no-referrer.

### 15. Open TCP port 2121 (unknown) (Info)

- **Location:** 127.0.0.1:2121, parameter `2121`
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200
- **Evidence:** Port 2121 accepted a connection; banner '220 (vsFTPd 2.3.4)'
- **Remediation:** Close ports that are not required and restrict the rest with a firewall.

### 16. Open TCP port 5055 (unknown) (Info)

- **Location:** 127.0.0.1:5055, parameter `5055`
- **OWASP Top 10:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200
- **Evidence:** Port 5055 accepted a connection;
- **Remediation:** Close ports that are not required and restrict the rest with a firewall.


## 4. Remediation retest

The remediated build was scanned with the same scanner and settings (2026-11-14 14:51).

| | Critical | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|---|
| Before | 3 | 6 | 2 | 3 | 2 | 16 |
| After | 0 | 0 | 0 | 0 | 1 | 1 |

- **Fixed:** 15
- **Still present:** 1
- **New:** 0

### Fixed

| Severity | Finding | Location |
|---|---|---|
| Critical | SQL injection allows authentication bypass | http://127.0.0.1:5055/login (`username`) |
| Critical | Service with known vulnerability (CVE-2011-2523) | 127.0.0.1:2121 (`2121`) |
| Critical | Admin interface reachable without authentication | http://127.0.0.1:5055/admin |
| High | SQL injection (boolean-based) | http://127.0.0.1:5055/search (`q`) |
| High | SQL injection (error-based) | http://127.0.0.1:5055/login (`username`) |
| High | SQL injection (error-based) | http://127.0.0.1:5055/search (`q`) |
| High | Sensitive file publicly accessible | http://127.0.0.1:5055/.env |
| High | Sensitive file publicly accessible | http://127.0.0.1:5055/backup.sql |
| High | Insecure direct object reference exposes user records | http://127.0.0.1:5055/api/user/{id} |
| Medium | Reflected cross-site scripting | http://127.0.0.1:5055/search (`q`) |
| Medium | Verbose database errors disclosed to users | http://127.0.0.1:5055/search |
| Low | Server banner discloses software and version | http://127.0.0.1:5055/ |
| Low | Cookie set without security attributes | http://127.0.0.1:5055/ (`sid`) |
| Low | Missing HTTP security headers | http://127.0.0.1:5055/ |
| Info | Open TCP port 2121 (unknown) | 127.0.0.1:2121 (`2121`) |

### Still present

| Severity | Finding | Location |
|---|---|---|
| Info | Open TCP port 5055 (unknown) | 127.0.0.1:5055 (`5055`) |


## 5. Notes and limitations

- The target is a deliberately vulnerable practice application run on localhost.
- The scanner uses non-destructive indicator checks; it does not exploit or extract data.
- A clean rescan means these specific checks found nothing, not that the application is free of vulnerabilities. Manual testing would still be required.
