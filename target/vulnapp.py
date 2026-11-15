#!/usr/bin/env python3
"""LabShop - a deliberately vulnerable practice web app.

!!  FOR LOCAL SECURITY TRAINING ONLY. It binds to 127.0.0.1 and has no option
!!  to listen on other interfaces. Never deploy it anywhere reachable.

Two modes share one codebase so the fixes are easy to compare:

    python target/vulnapp.py --port 5055                 # vulnerable
    python target/vulnapp.py --port 5055 --secure        # remediated

Intentional weaknesses (vulnerable mode) and the matching fix (secure mode):

  SQL injection (login, search)  -> parameterized queries
  Reflected XSS (search)         -> output encoding
  IDOR on /api/user/<id>         -> authentication + ownership check
  Unauthenticated /admin         -> role check
  Exposed /.env and /backup.sql  -> removed (404)
  Verbose SQL errors             -> generic error message
  Missing security headers       -> CSP, X-Frame-Options, nosniff, Referrer-Policy
  Weak session cookie flags      -> random token, HttpOnly, SameSite=Lax
  Old server banner              -> generic banner
  Legacy service with a known-vulnerable banner (simulated) -> not started

Passwords are stored as unsalted SHA-256 purely to keep the lab short; do not
copy that into a real application.
"""
import argparse
import hashlib
import html
import secrets
import socketserver
import sqlite3
import threading

from flask import Flask, jsonify, make_response, request

BANNER = b"220 (vsFTPd 2.3.4)\r\n"  # simulated legacy service banner (text only)


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _build_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                           email TEXT, role TEXT);
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL);
    """)
    users = [(1, "admin", _sha("Adm1n-lab-pass"), "admin@lab.test", "admin"),
             (2, "alice", _sha("alice-lab-pass"), "alice@lab.test", "user"),
             (3, "bob", _sha("bob-lab-pass"), "bob@lab.test", "user")]
    db.executemany("INSERT INTO users VALUES (?,?,?,?,?)", users)
    db.executemany("INSERT INTO products VALUES (?,?,?)",
                   [(1, "Laptop Pro", 1299.0), (2, "Wireless Mouse", 25.5),
                    (3, "USB-C Hub", 45.0), (4, "Mechanical Keyboard", 89.9)])
    db.commit()
    return db


def create_app(secure=False):
    app = Flask(__name__)
    db, lock, sessions = _build_db(), threading.Lock(), {}

    @app.after_request
    def headers(resp):
        if secure:
            resp.headers["Content-Security-Policy"] = "default-src 'self'"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/")
    def home():
        body = ("<html><body><h1>LabShop</h1>"
                "<p><a href='/search?q=laptop'>Search products</a> | "
                "<a href='/api/user/1'>My profile (API)</a> | <a href='/admin'>Admin</a></p>"
                "<form method='POST' action='/login'>"
                "<input type='text' name='username'>"
                "<input type='password' name='password'>"
                "<input type='submit' value='Login'></form></body></html>")
        resp = make_response(body)
        if secure:
            resp.set_cookie("sid", secrets.token_hex(8), httponly=True, samesite="Lax")
        else:
            resp.set_cookie("sid", secrets.token_hex(8))  # no HttpOnly / SameSite
        return resp

    @app.post("/login")
    def login():
        user = request.form.get("username", "")
        pw = _sha(request.form.get("password", ""))
        sql = None
        try:
            with lock:
                if secure:
                    row = db.execute("SELECT id, username, role FROM users "
                                     "WHERE username=? AND password=?", (user, pw)).fetchone()
                else:
                    sql = (f"SELECT id, username, role FROM users "
                           f"WHERE username='{user}' AND password='{pw}'")
                    row = db.execute(sql).fetchone()
        except sqlite3.Error as exc:
            if secure:
                return "Internal error", 500
            return f"Database error: {exc}\nQuery: {sql}", 500
        if not row:
            return "Invalid credentials", 401
        resp = make_response(f"Welcome, {html.escape(row[1])}! role={row[2]}")
        if secure:
            token = secrets.token_urlsafe(24)
            sessions[token] = row[0]
            resp.set_cookie("session", token, httponly=True, samesite="Lax")
        else:
            resp.set_cookie("session", row[1])  # guessable, no flags
        return resp

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        sql = None
        try:
            with lock:
                if secure:
                    rows = db.execute("SELECT id, name, price FROM products WHERE name LIKE ?",
                                      (f"%{q}%",)).fetchall()
                else:
                    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
                    rows = db.execute(sql).fetchall()
        except sqlite3.Error as exc:
            if secure:
                return "Internal error", 500
            return f"Database error: {exc}\nQuery: {sql}", 500
        shown = html.escape(q) if secure else q  # vulnerable mode reflects raw input
        items = "".join(f"<li>{html.escape(r[1])} - ${r[2]:.2f}</li>" for r in rows) \
            or "<li>No results</li>"
        return f"<html><body><h1>Results for: {shown}</h1><ul>{items}</ul></body></html>"

    @app.get("/api/user/<int:uid>")
    def api_user(uid):
        if secure:
            current = sessions.get(request.cookies.get("session", ""))
            if current is None:
                return jsonify(error="authentication required"), 401
            with lock:
                me = db.execute("SELECT role FROM users WHERE id=?", (current,)).fetchone()
            if current != uid and (me is None or me[0] != "admin"):
                return jsonify(error="forbidden"), 403
        with lock:
            row = db.execute("SELECT id, username, email, role FROM users WHERE id=?",
                             (uid,)).fetchone()
        if not row:
            return jsonify(error="not found"), 404
        return jsonify(id=row[0], username=row[1], email=row[2], role=row[3])

    @app.get("/admin")
    def admin():
        if secure:
            current = sessions.get(request.cookies.get("session", ""))
            with lock:
                me = db.execute("SELECT role FROM users WHERE id=?", (current,)).fetchone() \
                    if current else None
            if not me or me[0] != "admin":
                return "Forbidden", 403
        return "Admin panel: user management, order export, system settings"

    @app.get("/robots.txt")
    def robots():
        return "User-agent: *\nDisallow: /admin\n", 200, {"Content-Type": "text/plain"}

    @app.get("/.env")
    def dotenv():
        if secure:
            return "Not found", 404
        return ("DB_PASSWORD=FAKE-lab-password\nSECRET_KEY=FAKE-lab-secret\n", 200,
                {"Content-Type": "text/plain"})

    @app.get("/backup.sql")
    def backup():
        if secure:
            return "Not found", 404
        return ("-- LabShop backup (fake data)\nINSERT INTO users VALUES (1,'admin','...');\n",
                200, {"Content-Type": "text/plain"})

    return app


class _BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(BANNER)


class _Banner(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Running:
    """Handle for an app started in background threads (used by tests and run_lab)."""

    def __init__(self, server, legacy):
        self.server, self.legacy = server, legacy
        self.port = server.server_port
        self.legacy_port = legacy.server_address[1] if legacy else None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        if self.legacy:
            self.legacy.shutdown()
            self.legacy.server_close()


def serve_in_thread(secure=False, port=0, legacy_port=None):
    import logging

    from werkzeug.serving import WSGIRequestHandler, make_server

    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # keep the console quiet

    class Handler(WSGIRequestHandler):
        # The dev server adds its own Server header, so the banner is set here.
        # Vulnerable mode advertises an old version string; secure mode a generic one.
        def version_string(self):
            return "webserver" if secure else "Apache/2.2.8 (Ubuntu)"

    server = make_server("127.0.0.1", port, create_app(secure), threaded=True,
                         request_handler=Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    legacy = None
    if legacy_port is not None and not secure:
        legacy = _Banner(("127.0.0.1", legacy_port), _BannerHandler)
        threading.Thread(target=legacy.serve_forever, daemon=True).start()
    return Running(server, legacy)


def main():
    ap = argparse.ArgumentParser(description="Deliberately vulnerable lab app (localhost only).")
    ap.add_argument("--port", type=int, default=5055)
    ap.add_argument("--legacy-port", type=int, default=2121,
                    help="port for the simulated legacy service (vulnerable mode only)")
    ap.add_argument("--secure", action="store_true", help="run the remediated version")
    args = ap.parse_args()
    run = serve_in_thread(args.secure, args.port, args.legacy_port)
    mode = "SECURE" if args.secure else "VULNERABLE"
    print(f"LabShop [{mode}] on {run.url}"
          + (f", legacy service on 127.0.0.1:{run.legacy_port}" if run.legacy else ""))
    print("Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        run.stop()


if __name__ == "__main__":
    main()
