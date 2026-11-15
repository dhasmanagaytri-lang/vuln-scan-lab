"""Web vulnerability checks.

Each check is non-destructive: it sends a small number of harmless probe
requests (a quote character, a unique marker string) and inspects the response.
No exploitation, data extraction or brute forcing is performed.
"""
import html as html_lib
import re
import secrets
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from . import cvss

DB_ERROR = re.compile(
    r"(sqlite3?\.|sqlite error|OperationalError|SQL syntax|syntax error|"
    r"unrecognized token|unclosed quotation|ORA-\d{4,5}|pg_query|database error)", re.I)


@dataclass
class Finding:
    id: str
    title: str
    owasp: str
    cwe: str
    vector: str
    url: str
    evidence: str
    remediation: str
    param: str = ""
    cvss_score: float = 0.0
    severity: str = "Info"

    def __post_init__(self):
        if self.vector:
            self.cvss_score = cvss.base_score(self.vector)
            self.severity = cvss.severity(self.cvss_score)

    @property
    def key(self):
        return f"{self.id}|{self.url}|{self.param}"

    def to_dict(self):
        d = dict(self.__dict__)
        d["key"] = self.key
        return d


# ------------------------------------------------------------- discovery
class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self._form = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and a.get("name"):
            self._form["inputs"].append((a["name"], a.get("type", "text").lower()))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


@dataclass
class Context:
    base: str
    http: requests.Session
    get_endpoints: list = field(default_factory=list)   # [(url, [param, ...])]
    forms: list = field(default_factory=list)            # [{url, method, inputs}]
    home: requests.Response = None

    def fetch(self, path_or_url, **kw):
        kw.setdefault("timeout", 5)
        kw.setdefault("allow_redirects", False)
        return self.http.get(urljoin(self.base, path_or_url), **kw)


def discover(base):
    ctx = Context(base=base.rstrip("/") + "/", http=requests.Session())
    ctx.home = ctx.fetch("/")
    page = _Page()
    page.feed(ctx.home.text)
    seen = set()
    for href in page.links:
        url = urljoin(ctx.base, href)
        if urlparse(url).netloc != urlparse(ctx.base).netloc:
            continue
        params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        if params and url not in seen:
            seen.add(url)
            ctx.get_endpoints.append((url, params))
    for f in page.forms:
        ctx.forms.append({"url": urljoin(ctx.base, f["action"] or "/"),
                          "method": f["method"], "inputs": f["inputs"]})
    return ctx


def _shorten(text, n=160):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n] + "..."


def _with_param(url, param, value):
    """Return (url_without_query, params dict) with `param` replaced by value."""
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = value
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params


# ---------------------------------------------------------------- checks
def check_headers(ctx):
    h = ctx.home.headers
    findings = []
    expected = {"Content-Security-Policy": "Content-Security-Policy: default-src 'self'",
                "X-Frame-Options": "X-Frame-Options: DENY",
                "X-Content-Type-Options": "X-Content-Type-Options: nosniff",
                "Referrer-Policy": "Referrer-Policy: no-referrer"}
    missing = [name for name in expected if name not in h]
    if missing:
        findings.append(Finding(
            "HDR-MISSING", "Missing HTTP security headers", "A05:2021 Security Misconfiguration",
            "CWE-693", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", ctx.base,
            "Absent: " + ", ".join(missing),
            "Add the headers, e.g. " + "; ".join(expected[m] for m in missing) + "."))
    server = h.get("Server", "")
    if re.search(r"/\d", server):
        findings.append(Finding(
            "INFO-BANNER", "Server banner discloses software and version",
            "A05:2021 Security Misconfiguration", "CWE-200",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", ctx.base,
            f"Server: {server}",
            "Remove version details from the Server header (e.g. ServerTokens Prod) and patch the server."))
    return findings


def check_cookies(ctx):
    findings = []
    raw = ctx.home.raw.headers.getlist("Set-Cookie")
    for cookie in raw:
        name = cookie.split("=", 1)[0]
        low = cookie.lower()
        problems = []
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "samesite" not in low:
            problems.append("SameSite")
        if ctx.base.startswith("https") and "secure" not in low:
            problems.append("Secure")
        if problems:
            findings.append(Finding(
                "COOKIE-FLAGS", "Cookie set without security attributes",
                "A05:2021 Security Misconfiguration", "CWE-1004",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", ctx.base,
                f"Cookie '{name}' missing: {', '.join(problems)}",
                "Set HttpOnly and SameSite=Lax (or Strict) on session cookies, and Secure over HTTPS.",
                param=name))
    return findings


def check_sensitive_files(ctx):
    findings = []
    for path in ["/.env", "/backup.sql", "/.git/HEAD", "/config.php.bak"]:
        r = ctx.fetch(path)
        ctype = r.headers.get("Content-Type", "")
        if r.status_code == 200 and r.text.strip() and "html" not in ctype:
            sample = re.sub(r"=\S+", "=<redacted>", r.text.strip().splitlines()[0])
            findings.append(Finding(
                "EXPOSED-FILE", "Sensitive file publicly accessible",
                "A05:2021 Security Misconfiguration", "CWE-538",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", urljoin(ctx.base, path),
                f"HTTP 200, {len(r.content)} bytes, first line: {_shorten(sample, 80)}",
                "Remove the file from the web root, deny access to dotfiles and backups at the "
                "web server, and rotate any secrets it contained."))
    return findings


def check_admin_access(ctx):
    r = ctx.fetch("/admin")
    if r.status_code == 200:
        return [Finding(
            "BAC-ADMIN", "Admin interface reachable without authentication",
            "A01:2021 Broken Access Control", "CWE-306",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", urljoin(ctx.base, "/admin"),
            f"Unauthenticated GET returned HTTP 200 ({len(r.content)} bytes)",
            "Require authentication and an admin-role check on every admin route; deny by default.")]
    return []


def check_xss(ctx):
    findings = []
    for url, params in ctx.get_endpoints:
        for p in params:
            token = "lab" + secrets.token_hex(4)
            payload = f'"><svg onload={token}>'
            base_url, query = _with_param(url, p, payload)
            r = ctx.http.get(base_url, params=query, timeout=5, allow_redirects=False)
            if f"<svg onload={token}>" in r.text and "html" in r.headers.get("Content-Type", ""):
                findings.append(Finding(
                    "XSS-REFLECTED", "Reflected cross-site scripting", "A03:2021 Injection",
                    "CWE-79", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", base_url,
                    f"Marker markup '<svg onload={token}>' returned unencoded in the HTML response",
                    "HTML-encode all user-controlled output (context-aware templating) and add a "
                    "Content-Security-Policy.", param=p))
    return findings


def _strip_payload(text, payload):
    for variant in (payload, html_lib.escape(payload), html_lib.escape(payload, quote=False)):
        text = text.replace(variant, "")
    return text


def check_sqli(ctx):
    findings, verbose_seen = [], False
    # --- GET parameters: error-based and boolean-based
    for url, params in ctx.get_endpoints:
        for p in params:
            base_val = dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get(p, "")
            base_url, q = _with_param(url, p, base_val + "'")
            r = ctx.http.get(base_url, params=q, timeout=5, allow_redirects=False)
            if DB_ERROR.search(r.text):
                findings.append(Finding(
                    "SQLI-ERROR", "SQL injection (error-based)", "A03:2021 Injection", "CWE-89",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", base_url,
                    f"A single quote triggered a database error: {_shorten(r.text, 110)}",
                    "Use parameterized queries / prepared statements for every query; never "
                    "build SQL by string concatenation.", param=p))
                if not verbose_seen:
                    verbose_seen = True
                    findings.append(_verbose_error(base_url, r.text))
            true_p, false_p = base_val + "' OR '1'='1' -- ", base_val + "' AND '1'='2' -- "
            rt = ctx.http.get(base_url, params=_with_param(url, p, true_p)[1], timeout=5,
                              allow_redirects=False)
            rf = ctx.http.get(base_url, params=_with_param(url, p, false_p)[1], timeout=5,
                              allow_redirects=False)
            if (rt.status_code == rf.status_code == 200 and
                    _strip_payload(rt.text, true_p) != _strip_payload(rf.text, false_p)):
                findings.append(Finding(
                    "SQLI-BOOLEAN", "SQL injection (boolean-based)", "A03:2021 Injection",
                    "CWE-89", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", base_url,
                    "Always-true and always-false conditions returned different results "
                    f"({len(rt.text)} vs {len(rf.text)} bytes)",
                    "Use parameterized queries / prepared statements.", param=p))
    # --- POST forms: error-based per field, plus login auth bypass
    for form in ctx.forms:
        if form["method"] != "post":
            continue
        fields = [n for n, _ in form["inputs"]]

        def post(**over):
            data = {n: "x" for n in fields}
            data.update(over)
            return ctx.http.post(form["url"], data=data, timeout=5, allow_redirects=False)

        for name, typ in form["inputs"]:
            if typ == "password":
                continue
            r = post(**{name: "'"})
            if DB_ERROR.search(r.text):
                findings.append(Finding(
                    "SQLI-ERROR", "SQL injection (error-based)", "A03:2021 Injection", "CWE-89",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", form["url"],
                    f"A single quote in '{name}' triggered a database error: {_shorten(r.text, 100)}",
                    "Use parameterized queries / prepared statements.", param=name))
                if not verbose_seen:
                    verbose_seen = True
                    findings.append(_verbose_error(form["url"], r.text))
        if any(t == "password" for _, t in form["inputs"]):
            user_field = next(n for n, t in form["inputs"] if t != "password")
            baseline = post(**{user_field: "lab_no_such_user"})
            attempt = post(**{user_field: "admin' -- "})
            if baseline.status_code in (401, 403) and attempt.status_code == 200:
                findings.append(Finding(
                    "SQLI-AUTHBYPASS", "SQL injection allows authentication bypass",
                    "A03:2021 Injection", "CWE-89",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", form["url"],
                    f"Login with username \"admin' -- \" and a wrong password returned "
                    f"HTTP {attempt.status_code} (an unknown user returned {baseline.status_code})",
                    "Use parameterized queries, hash and compare passwords in application code, "
                    "and add rate limiting / lockout.", param=user_field))
    return findings


def _verbose_error(url, body):
    return Finding(
        "ERR-VERBOSE", "Verbose database errors disclosed to users",
        "A05:2021 Security Misconfiguration", "CWE-209",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", url,
        f"Response exposed internal details: {_shorten(body, 120)}",
        "Return a generic error page, log details server-side only.")


def check_idor(ctx):
    seen = []
    for uid in (1, 2, 3):
        r = ctx.fetch(f"/api/user/{uid}", cookies={})
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            try:
                data = r.json()
            except ValueError:
                continue
            if "email" in data:
                seen.append(uid)
    if len(seen) >= 2:
        return [Finding(
            "IDOR-USER", "Insecure direct object reference exposes user records",
            "A01:2021 Broken Access Control", "CWE-639",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", urljoin(ctx.base, "/api/user/{id}"),
            f"Unauthenticated requests for ids {seen} each returned HTTP 200 with "
            "id, username, email and role fields",
            "Require authentication and verify the requesting user owns (or is authorized to "
            "view) the record; avoid sequential, guessable identifiers.")]
    return []


WEB_CHECKS = [check_headers, check_cookies, check_sensitive_files, check_admin_access,
              check_xss, check_sqli, check_idor]


def run_web_checks(base):
    ctx = discover(base)
    findings = []
    for chk in WEB_CHECKS:
        findings.extend(chk(ctx))
    return findings


def port_findings(host, open_ports):
    findings = []
    for p in open_ports:
        banner = f" banner '{p['banner']}'" if p["banner"] else ""
        findings.append(Finding(
            "PORT-OPEN", f"Open TCP port {p['port']} ({p['service']})",
            "A05:2021 Security Misconfiguration", "CWE-200", "", f"{host}:{p['port']}",
            f"Port {p['port']} accepted a connection;{banner}",
            "Close ports that are not required and restrict the rest with a firewall.",
            param=str(p["port"])))
        if p["cve"]:
            findings.append(Finding(
                "SVC-VULN", f"Service with known vulnerability ({p['cve']})",
                "A06:2021 Vulnerable and Outdated Components", "CWE-1395",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", f"{host}:{p['port']}",
                f"Banner '{p['banner']}' matches {p['cve']}: {p['cve_note']}",
                "Upgrade to a supported, patched version or remove the service. Legacy "
                "plaintext protocols such as FTP should be replaced by SFTP/FTPS.",
                param=str(p["port"])))
    return findings
