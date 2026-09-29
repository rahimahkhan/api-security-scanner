"""Regression tests for the manual-verification correctness fixes.

Covers three bugs found by scanning a local intentionally-vulnerable target:
1. baseline_telemetry now carries response_body, so the differential-signal
   check compares against the real baseline instead of always reading 1.0.
2. The generic "SQL syntax" error message confirms error-based SQLi.
3. The open-redirect probe is selected for common redirect parameter names
   (url, next, return, ...) instead of only path keywords.
"""
import main as pipeline
from detection.signature import SignatureDetector


def _sqli_req(body, status=200, size=17):
    return {
        "url": "http://t/health",
        "payload": "' OR 1=1 --",
        "attack_category": "SQL_Injection_GET",
        "status_code": status,
        "response_size": size,
        "response_time": 0.05,
        "response_headers": {"content-type": "application/json"},
        "response_body": body,
    }


def test_identical_baseline_body_gives_no_differential_signal():
    det = SignatureDetector()
    base = {"status_code": 200, "response_size": 17, "response_time": 0.04,
            "response_body": '{"status":"ok"}'}
    res = det.analyze(_sqli_req('{"status":"ok"}'), baseline_telemetry=base)
    assert res["points"] == 10
    assert res["finding_status"] == "Suspected"
    assert "without database error, differential response" in res["proof_of_concept"]


def test_changed_body_still_raises_differential_signal():
    det = SignatureDetector()
    base = {"status_code": 200, "response_size": 17, "response_time": 0.04,
            "response_body": '{"status":"ok"}'}
    res = det.analyze(_sqli_req('{"status":"ok","debug":true}', size=40),
                      baseline_telemetry=base)
    assert res["points"] == 15
    assert "differential response without database-error" in res["proof_of_concept"]


def test_generic_sql_syntax_error_confirms_sqli():
    det = SignatureDetector()
    base = {"status_code": 200, "response_size": 17, "response_time": 0.04,
            "response_body": '{"id":"1"}'}
    res = det.analyze(
        _sqli_req("Database error: SQL syntax error near '' OR 1=1 --'",
                  status=500, size=60),
        baseline_telemetry=base,
    )
    assert res["finding_status"] == "Confirmed"
    assert res["points"] == 40
    assert "SQL syntax" in res["proof_of_concept"]


def _mini_queue(*types):
    return [{"type": t, "payload": "", "method": "GET"} for t in types]


def test_open_redirect_probe_selected_for_url_param():
    queue = _mini_queue("SQL_Injection_GET", "Cross_Site_Scripting",
                        "Command_Injection", "Open_Redirect", "Baseline_Inspection")
    ep = {"url": "http://t/go?url=https://example.com", "query_fields": ["url"]}
    selected = [i["type"] for i in pipeline._select_test_queue(ep, queue)]
    assert "Open_Redirect" in selected


def test_open_redirect_probe_selected_for_next_param():
    queue = _mini_queue("SQL_Injection_GET", "Cross_Site_Scripting",
                        "Command_Injection", "Open_Redirect", "Baseline_Inspection")
    ep = {"url": "http://t/login", "query_fields": ["next"]}
    selected = [i["type"] for i in pipeline._select_test_queue(ep, queue)]
    assert "Open_Redirect" in selected


def test_open_redirect_not_selected_for_plain_params():
    queue = _mini_queue("SQL_Injection_GET", "Cross_Site_Scripting",
                        "Command_Injection", "Open_Redirect", "Baseline_Inspection")
    ep = {"url": "http://t/health", "query_fields": []}
    selected = [i["type"] for i in pipeline._select_test_queue(ep, queue)]
    assert "Open_Redirect" not in selected
