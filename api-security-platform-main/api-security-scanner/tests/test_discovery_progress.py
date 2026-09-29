"""Discovery-phase live progress: the results-page banner must show crawl
progress ("Discovering pages: N crawled…") instead of sitting on
"Starting scan…" during long crawls."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import main as main_module
from core.discovery import EndpointDiscovery
from database.db import format_scan_eta


class _FakeScan:
    def __init__(self, done, total, stage="", start=None):
        self.progress_done = done
        self.progress_total = total
        self.progress_stage = stage
        self.scan_start_time = start


def test_format_scan_eta_empty_during_discovery():
    # Discovery phase: total unknown -> no ETA is claimed (honest blank).
    assert format_scan_eta(_FakeScan(done=142, total=0, stage="Discovering pages")) == ""


class _SiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><body><a href="/a">a</a><a href="/b">b</a></body></html>'
        else:
            body = b"<html><body>leaf</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_discovery_emits_progress_callback():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        calls = []
        disc = EndpointDiscovery(
            base_url=f"http://127.0.0.1:{server.server_port}",
            timeout=5,
            max_depth=1,
            progress_callback=lambda pages, eps: calls.append((pages, eps)),
        )
        endpoints = disc.discover()
        assert len(endpoints) >= 3  # / + /a + /b
        assert calls, "progress callback was never invoked"
        pages_seen = [c[0] for c in calls]
        assert pages_seen[-1] >= 3, f"expected >=3 pages crawled, saw {pages_seen}"
        assert pages_seen == sorted(pages_seen), "pages crawled must be non-decreasing"
    finally:
        server.shutdown()
        server.server_close()


def test_discovery_without_callback_still_works():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        disc = EndpointDiscovery(
            base_url=f"http://127.0.0.1:{server.server_port}", timeout=5, max_depth=0
        )
        assert len(disc.discover()) >= 1
    finally:
        server.shutdown()
        server.server_close()


def test_callback_factory_noop_without_session():
    cb = main_module._make_discovery_progress_callback(None)
    cb(10, 5)  # must not raise and must not touch the DB


def test_callback_factory_throttles_and_labels(monkeypatch):
    writes = []

    def fake_update(session_id, done=None, total=None, stage=None):
        writes.append((session_id, done, total, stage))

    monkeypatch.setattr(main_module, "update_scan_progress", fake_update)

    clock = {"t": 1000.0}
    monkeypatch.setattr(main_module.time, "monotonic", lambda: clock["t"])

    cb = main_module._make_discovery_progress_callback(7, min_interval=3.0)
    cb(1, 0)   # first call goes through
    cb(2, 1)   # throttled (only 0s elapsed)
    assert len(writes) == 1
    clock["t"] += 3.1
    cb(3, 2)   # allowed again
    assert len(writes) == 2
    sid, done, total, stage = writes[-1]
    assert sid == 7
    assert done == 3
    assert total == 0
    assert "Discovering pages" in stage
    assert "2 endpoints found" in stage
