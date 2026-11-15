import json
import socket

import pytest

from scanner import checks, cvss, portscan, report
from scanner.__main__ import main as scanner_main
from scanner.guard import UnauthorizedTarget, check_target
from target.vulnapp import serve_in_thread


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


WEB_PORT, LEGACY_PORT = free_port(), free_port()  # same ports for both builds


def scan_app(secure):
    legacy = LEGACY_PORT
    app = serve_in_thread(secure=secure, port=WEB_PORT, legacy_port=legacy)
    try:
        findings = checks.run_web_checks(app.url)
        open_ports = portscan.scan("127.0.0.1", [legacy, app.port])
        findings += checks.port_findings("127.0.0.1", open_ports)
    finally:
        app.stop()
    return findings


@pytest.fixture(scope="module")
def vulnerable():
    return scan_app(secure=False)


@pytest.fixture(scope="module")
def secure():
    return scan_app(secure=True)


# ------------------------------------------------------------------ CVSS
@pytest.mark.parametrize("vector,score,sev", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "Info"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
])
def test_cvss_scores_match_published_values(vector, score, sev):
    assert cvss.base_score(vector) == score
    assert cvss.severity(score) == sev


def test_cvss_rejects_incomplete_vector():
    with pytest.raises(ValueError):
        cvss.base_score("CVSS:3.1/AV:N/AC:L")


# ----------------------------------------------------------------- guard
def test_guard_allows_loopback_and_private():
    assert check_target("http://127.0.0.1:5000") == "127.0.0.1"
    assert check_target("http://10.1.2.3") == "10.1.2.3"


def test_guard_refuses_public_address_without_flag():
    with pytest.raises(UnauthorizedTarget):
        check_target("http://8.8.8.8")
    assert check_target("http://8.8.8.8", authorized=True) == "8.8.8.8"


def test_cli_refuses_public_target_before_sending_anything(capsys):
    assert scanner_main(["scan", "--target", "http://8.8.8.8", "--out", "/tmp/x"]) == 2
    assert "refused" in capsys.readouterr().err


# ------------------------------------------------------------- port scan
def test_parse_ports():
    assert portscan.parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]
    with pytest.raises(ValueError):
        portscan.parse_ports("70000")


# ---------------------------------------------------- vulnerable app scan
EXPECTED = {"SQLI-AUTHBYPASS", "SQLI-ERROR", "SQLI-BOOLEAN", "XSS-REFLECTED", "IDOR-USER",
            "BAC-ADMIN", "EXPOSED-FILE", "ERR-VERBOSE", "HDR-MISSING", "COOKIE-FLAGS",
            "INFO-BANNER", "SVC-VULN", "PORT-OPEN"}


def test_vulnerable_app_findings_cover_every_planted_weakness(vulnerable):
    assert EXPECTED <= {f.id for f in vulnerable}


def test_findings_have_cvss_owasp_and_remediation(vulnerable):
    for f in vulnerable:
        assert f.owasp.startswith("A0") and f.cwe.startswith("CWE-") and f.remediation
        if f.id != "PORT-OPEN":
            assert f.cvss_score > 0 and f.severity != "Info"


def test_sqli_found_in_both_search_and_login(vulnerable):
    locs = {(f.id, f.param) for f in vulnerable if f.id.startswith("SQLI")}
    assert ("SQLI-ERROR", "q") in locs and ("SQLI-BOOLEAN", "q") in locs
    assert ("SQLI-ERROR", "username") in locs and ("SQLI-AUTHBYPASS", "username") in locs


def test_both_exposed_files_found_and_secrets_not_leaked_in_evidence(vulnerable):
    files = [f for f in vulnerable if f.id == "EXPOSED-FILE"]
    assert len(files) == 2
    assert all("FAKE-lab" not in f.evidence for f in files)


def test_known_vulnerable_banner_maps_to_cve(vulnerable):
    svc = next(f for f in vulnerable if f.id == "SVC-VULN")
    assert "CVE-2011-2523" in svc.title and svc.severity == "Critical"


# --------------------------------------------------------- secure app scan
def test_remediated_app_has_no_vulnerability_findings(secure):
    assert {f.id for f in secure} == {"PORT-OPEN"}
    assert len(secure) == 1  # only the web port itself; legacy service is gone


# ---------------------------------------------------------------- retest
def test_retest_comparison_counts(vulnerable, secure):
    def pack(fs):
        return {"meta": {"date": "x"}, "findings": [f.to_dict() for f in fs]}
    cmp_ = report.compare(pack(vulnerable), pack(secure))
    assert len(cmp_["new"]) == 0
    assert len(cmp_["fixed"]) == len(vulnerable) - len(secure)
    assert [f["id"] for f in cmp_["remaining"]] == ["PORT-OPEN"]


def test_report_renders_all_sections(vulnerable):
    data = json.loads(report.to_json(vulnerable, {"target": "t", "ports": "p", "date": "d"}))
    md = report.render_markdown(data)
    for heading in ("## 1. Scope and method", "## 2. Summary", "## 3. Detailed findings"):
        assert heading in md
    assert "CVSS:3.1/" in md
