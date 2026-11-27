"""Skip tracking + path-parameter injection probing (2026-11-27).

Two fixes from the VAmPI evaluation:
1. A scan that abandons an endpoint must record it on the session and show
   "Completed, N endpoint(s) skipped" — a bare "COMPLETE 50/50" overstates
   coverage. The per-endpoint budgets are lowered from evidence (replica
   log: slowest legitimate endpoint 12.5s; live DVWA avg ~59s/endpoint).
2. Object routes (/users/{id}, ...) got BOLA probes only, so injection
   sinks in path parameters were never tested (VAmPI's /users/v1/{username}
   SQLi). Injection probes are now selected for object routes too, and the
   payload is also appended to the last path segment when the endpoint has
   no query/form field to bind to.
"""
import logging

from database.db import (
    init_db, save_scan_session, complete_scan_session,
    get_session, delete_session,
)
from database.models import parse_skipped_endpoints, dump_skipped_endpoints

logging.disable(logging.CRITICAL)


def _queue():
    return [
        {"type": "SQL_Injection_GET", "method": "GET", "payload": "' OR 1=1 --"},
        {"type": "SQL_Injection_Error", "attack_category": "SQL_Injection",
         "method": "GET", "payload": "'"},
        {"type": "Cross_Site_Scripting", "method": "POST",
         "payload": "<script>alert(1)</script>"},
        {"type": "Command_Injection", "method": "GET", "payload": "; cat /etc/passwd"},
        {"type": "BOLA_IDOR", "payload": "", "method": "GET", "bola_id_mutation": True},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]


def test_object_route_selects_injection_probes_too():
    from main import _select_test_queue
    selected = _select_test_queue(
        {"url": "https://example.test/users/v1/name1", "method": "GET"}, _queue())
    types = [item["type"] for item in selected]
    assert types[0] == "BOLA_IDOR"
    assert "SQL_Injection_GET" in types
    assert "SQL_Injection_Error" in types
    assert "Cross_Site_Scripting" in types
    assert "Command_Injection" in types
    assert types[-1] == "Baseline_Inspection"


def test_append_payload_to_path_segment():
    from main import _append_payload_to_path_segment
    assert _append_payload_to_path_segment("http://t/users/v1/name1", "'") == \
        "http://t/users/v1/name1'"
    assert _append_payload_to_path_segment("http://t/users/v1/123", "' OR 1=1 --") == \
        "http://t/users/v1/123' OR 1=1 --"
    # Query string is preserved.
    assert _append_payload_to_path_segment("http://t/users/v1/name1?x=1", "'") == \
        "http://t/users/v1/name1'?x=1"
    # No value-like last segment: trailing slash, empty path, filename.
    assert _append_payload_to_path_segment("http://t/users/v1/", "'") is None
    assert _append_payload_to_path_segment("http://t/", "'") is None
    assert _append_payload_to_path_segment("http://t/api.json", "'") is None
    assert _append_payload_to_path_segment("http://t/users/v1/name1", "") is None


def test_skipped_endpoints_round_trip():
    assert parse_skipped_endpoints(None) == []
    assert parse_skipped_endpoints([]) == []
    assert parse_skipped_endpoints([{"url": "http://t/a", "reason": "x"}]) == \
        [{"url": "http://t/a", "reason": "x"}]
    dumped = dump_skipped_endpoints([("http://t/a", "abandoned after 180s")])
    assert parse_skipped_endpoints(dumped) == \
        [{"url": "http://t/a", "reason": "abandoned after 180s"}]
    assert parse_skipped_endpoints("not json") == []
    assert dump_skipped_endpoints([]) is None


def test_complete_scan_session_persists_skipped_endpoints():
    init_db()
    session_obj = save_scan_session("http://skip.example/api", total_endpoints=2)
    try:
        done = complete_scan_session(
            session_obj.id, 10.0, "Low", 0,
            skipped_endpoints=[("http://skip.example/api/slow", "abandoned after 180s (budget 180s)")],
        )
        assert done.status == "complete"
        got = get_session(session_obj.id)
        assert parse_skipped_endpoints(getattr(got, "skipped_endpoints", None)) == [
            {"url": "http://skip.example/api/slow",
             "reason": "abandoned after 180s (budget 180s)"}
        ]
    finally:
        delete_session(session_obj.id)


def test_endpoint_budgets_lowered_from_evidence():
    # Replica log (Nov 25): slowest legitimate endpoint 12.5s; live DVWA
    # avg ~59s/endpoint. 180s wall / 120s dispatch keeps a 3x margin over
    # the slowest legitimate live endpoint while saving ~7 min per wedged
    # endpoint vs the old 600s/300s.
    from main import ENDPOINT_WALL_BUDGET, ENDPOINT_DISPATCH_TIMEOUT
    assert ENDPOINT_WALL_BUDGET == 180
    assert ENDPOINT_DISPATCH_TIMEOUT == 120
    assert ENDPOINT_WALL_BUDGET > ENDPOINT_DISPATCH_TIMEOUT


def test_seed_endpoint_gets_baseline_only():
    """Seed/setup endpoints rewrite shared state on every call: concurrent
    probes race the seed and the resulting database errors masquerade as
    injection evidence (VAmPI /createdb Confirmed as SQLi from a 'database
    is locked' race, not from any payload). Baseline only — observe, don't
    attack."""
    from main import _select_test_queue
    for url in ("https://example.test/createdb",
                "https://example.test/api/seed",
                "https://example.test/migrate"):
        selected = _select_test_queue({"url": url, "method": "GET"}, _queue())
        assert [item["type"] for item in selected] == ["Baseline_Inspection"]
    # Ordinary object routes are unaffected.
    selected = _select_test_queue(
        {"url": "https://example.test/users/v1/name1", "method": "GET"}, _queue())
    assert "SQL_Injection_Error" in [item["type"] for item in selected]
