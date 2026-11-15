"""TCP connect scan with banner grabbing and a tiny known-vulnerable-banner table."""
import socket
from concurrent.futures import ThreadPoolExecutor

# (substring of banner, CVE, description). A real scanner would use a full
# CPE/NVD feed; this is a small curated table for the lab.
KNOWN_VULNERABLE = [
    ("vsFTPd 2.3.4", "CVE-2011-2523",
     "vsFTPd 2.3.4 shipped with a backdoor that opens a shell on port 6200"),
]
COMMON = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
          110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
          3389: "rdp", 5432: "postgresql", 8080: "http-alt"}


def parse_ports(spec):
    """'1-1024,2121,5055' -> sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {bad[:3]}")
    return sorted(ports)


def _probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = b""
            try:
                banner = s.recv(128)
                if not banner:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(128)
            except (socket.timeout, OSError):
                pass
            return port, banner.decode("latin-1", "replace").strip()
    except OSError:
        return None


def scan(host, ports, timeout=0.5, workers=100):
    """Return [{'port', 'service', 'banner', 'cve', 'cve_note'}] for open ports."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = [r for r in pool.map(lambda p: _probe(host, p, timeout), ports) if r]
    out = []
    for port, banner in sorted(results):
        service = COMMON.get(port, "unknown")
        if banner.startswith("HTTP/"):
            service = "http"
        cve = note = None
        for needle, cve_id, text in KNOWN_VULNERABLE:
            if needle.lower() in banner.lower():
                cve, note = cve_id, text
        out.append({"port": port, "service": service,
                    "banner": banner.splitlines()[0] if banner else "",
                    "cve": cve, "cve_note": note})
    return out
