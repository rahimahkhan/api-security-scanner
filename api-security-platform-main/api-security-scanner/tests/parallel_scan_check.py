"""Hermetic end-to-end check for the parallel endpoint scan.

Run by test_parallel_scan.py in a subprocess (own process, own DATABASE_URL)
so the scan writes to an isolated SQLite file instead of the shared dev DB.

Target: a tiny in-process HTTP server with one SQL-injectable endpoint
(quote -> SQL syntax error), one reflected-XSS endpoint, and one clean
endpoint. Exit 0 only when SQLi and XSS both Confirm and nothing Confirms
on /clean.
"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = sys.argv[1]
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["ALLOW_PRIVATE_SCAN_TARGETS"] = "1"
for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
            "ALL_PROXY", "all_proxy", "no_proxy", "NO_PROXY"):
    os.environ.pop(var, None)

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP)
os.chdir(APP)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/":
            body = (
                '<html><body>'
                '<a href="/sqli?id=1">sqli</a>'
                '<a href="/xss_r?name=x">xss</a>'
                '<a href="/clean">clean</a>'
                "</body></html>"
            )
        elif parsed.path == "/sqli":
            uid = qs.get("id", ["1"])[0]
            if "'" in uid or '"' in uid:
                body = "You have an error in your SQL syntax near ''"
            else:
                body = '{"id": "1"}'
        elif parsed.path == "/xss_r":
            name = qs.get("name", ["guest"])[0]
            body = f"<html><body>Hello {name}</body></html>"
        elif parsed.path == "/clean":
            body = '{"status": "ok"}'
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

from main import run_pipeline  # noqa: E402
from database.db import get_session_findings  # noqa: E402

session_id = run_pipeline(f"http://127.0.0.1:{server.server_port}", return_session_id=True)
findings = get_session_findings(session_id)
confirmed = sorted({
    (f.attack_type, (f.endpoint.url or "").split("?")[0])
    for f in findings if f.finding_status == "Confirmed"
})
clean_confirmed = [
    f for f in findings
    if f.finding_status == "Confirmed" and "/clean" in (f.endpoint.url or "")
]
print("CONFIRMED:", confirmed)
print("CLEAN_CONFIRMED:", len(clean_confirmed))
server.shutdown()
server.server_close()

confirmed_types = {attack for attack, _ in confirmed}
ok = "SQL_Injection" in confirmed_types and "XSS" in confirmed_types and not clean_confirmed
sys.exit(0 if ok else 1)
