"""SQL-error verification: repeat + balanced-quote control (2026-11-27).

A database error in one probe response is not proof the payload caused it.
Before an error-based SQLi Confirm stands, the pipeline must show the error
reproduces on a sequential repeat AND is absent on a balanced-quote control
('' instead of "'"). A transient error (a lock, a race, a wedged seed)
fails one of the two gates and downgrades to Suspected.
"""
import logging

from detection.signature import SignatureDetector

logging.disable(logging.CRITICAL)

TRACEBACK = (
    "Traceback (most recent call last):\n"
    "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) "
    "unrecognized token: \"'\"\n"
    "[SQL: SELECT * FROM users WHERE username = ''']\n"
)
HEALTHY_BODY = '{"username": "name1", "email": "n@example.com"}'
JSON = {"content-type": "application/json"}


class FakeEngine:
    """Scripted request engine: returns canned responses per call index."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send_request(self, method, url, payload=None, custom_headers=None,
                     json_payload=None, query_params=None, form_data=None,
                     follow_redirects=True):
        self.calls.append({
            "method": method, "url": url, "payload": payload,
            "query_params": query_params, "form_data": form_data,
            "json_payload": json_payload,
        })
        if not self.responses:
            raise AssertionError("fake engine called more times than scripted")
        return self.responses.pop(0)


def _ok(body):
    return {"status_code": 200, "response_body": body, "response_time": 0.1, "error": None}


def _err(body):
    return {"status_code": 500, "response_body": body, "response_time": 0.1, "error": None}


def _confirmed_sig_res(det):
    req_data = dict(url="http://t/users/v1/name1'", payload="'",
                    attack_category="SQL_Injection", status_code=500,
                    response_size=len(TRACEBACK), response_headers=JSON,
                    response_body=TRACEBACK, response_time=0.1)
    baseline = dict(url="http://t/users/v1/name1", status_code=200,
                    response_size=len(HEALTHY_BODY), response_body=HEALTHY_BODY,
                    response_time=0.1, response_headers=JSON)
    sig_res = det.analyze(req_data, baseline_telemetry=baseline)
    assert sig_res["attack_type"] == "SQL_Injection"
    assert sig_res["finding_status"] == "Confirmed"
    return sig_res, req_data, baseline


def test_sql_error_confirms_when_repeat_reproduces_and_control_clean():
    from main import verify_sql_error_proof
    det = SignatureDetector()
    sig_res, req_data, baseline = _confirmed_sig_res(det)
    engine = FakeEngine([_err(TRACEBACK), _ok(HEALTHY_BODY)])
    out = verify_sql_error_proof(
        engine, det, sig_res, {"type": "SQL_Injection_Error"}, "GET",
        "http://t/users/v1/name1'", "'", None, None, None, None,
        req_data, baseline)
    assert out["finding_status"] == "Confirmed"
    assert out["has_proof"] is True
    # Repeat was the identical probe; control used the balanced payload in the path.
    assert engine.calls[0]["url"] == "http://t/users/v1/name1'"
    assert engine.calls[0]["payload"] == "'"
    assert engine.calls[1]["url"] == "http://t/users/v1/name1''"
    assert engine.calls[1]["payload"] == "''"


def test_sql_error_downgrades_when_repeat_does_not_reproduce():
    from main import verify_sql_error_proof
    det = SignatureDetector()
    sig_res, req_data, baseline = _confirmed_sig_res(det)
    engine = FakeEngine([_ok(HEALTHY_BODY)])
    out = verify_sql_error_proof(
        engine, det, sig_res, {"type": "SQL_Injection_Error"}, "GET",
        "http://t/users/v1/name1'", "'", None, None, None, None,
        req_data, baseline)
    assert out["finding_status"] == "Suspected"
    assert out["has_proof"] is False
    assert "did not reproduce" in out["proof_of_concept"]
    assert len(engine.calls) == 1  # control never runs after a failed repeat


def test_sql_error_downgrades_when_control_also_errors():
    from main import verify_sql_error_proof
    det = SignatureDetector()
    sig_res, req_data, baseline = _confirmed_sig_res(det)
    engine = FakeEngine([_err(TRACEBACK), _err(TRACEBACK)])
    out = verify_sql_error_proof(
        engine, det, sig_res, {"type": "SQL_Injection_Error"}, "GET",
        "http://t/users/v1/name1'", "'", None, None, None, None,
        req_data, baseline)
    assert out["finding_status"] == "Suspected"
    assert out["has_proof"] is False
    assert "balanced-quote control" in out["proof_of_concept"]


def test_sql_error_control_rebinds_query_param_payload():
    from main import verify_sql_error_proof, _control_request
    # Query-bound variant: the payload lives in a query param, not the path.
    url, q, f, j = _control_request(
        "http://t/search", "'", {"q": "'"}, None, None, "''")
    assert url == "http://t/search"
    assert q == {"q": "''"}
    assert f is None and j is None
    # Path-bound variant: the payload is the last segment's suffix.
    url, q, f, j = _control_request(
        "http://t/users/v1/name1'", "'", None, None, None, "''")
    assert url == "http://t/users/v1/name1''"


def test_dataset_logging_records_baseline_probe_pair(tmp_path, monkeypatch):
    """Dataset work (2026-11-27, fixed 2026-11-27): with DATASET_LOG_DIR
    set, every probe writes one JSON line with the raw baseline + probe
    bodies and the JOIN fields for offline labeling. The record carries NO
    training label (label is None until the labeling script joins it to
    ground truth); the scanner's verdict is stored as scanner_label, a
    feature column — a model trained on the scanner's own verdict would
    just copy the signature layer. Off by default (no dir set -> no file,
    no error)."""
    import json
    import main as main_mod

    monkeypatch.setenv("DATASET_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("DATASET_TARGET_APP", "toy-app")
    monkeypatch.setenv("DATASET_MODE", "vuln")
    main_mod.log_dataset_pair(
        session_id=7, target_url="http://t", test_item={"type": "SQL_Injection_Error"},
        test_method="GET", test_url="http://t/sqli?id=1", payload_str="'",
        baseline_telemetry={"status_code": 200, "response_time": 0.1,
                            "response_size": 12, "response_body": '{"id": "1"}'},
        req_data={"status_code": 500, "response_time": 0.12,
                  "response_size": 40, "response_body": "SQL syntax error"},
        features={"payload_length": 1},
        sig_res={"attack_type": "SQL_Injection", "has_proof": True},
        risk_summary={"finding_status": "Confirmed", "total_score": 100.0,
                      "severity": "CRITICAL"},
        parameter="id")
    path = tmp_path / "dataset-session-7.jsonl"
    assert path.exists()
    rec = json.loads(path.read_text().splitlines()[0])
    assert rec["baseline"]["response_body"] == '{"id": "1"}'
    assert rec["probe"]["response_body"] == "SQL syntax error"
    # Join fields for the offline labeling script.
    assert rec["target_app"] == "toy-app"
    assert rec["run_id"] == 7
    assert rec["mode"] == "vuln"
    assert rec["endpoint_template"] == "/sqli"
    assert rec["parameter"] == "id"
    assert rec["probe_type"] == "SQL_Injection_Error"
    # No training label in the log; the scanner's verdict is a feature.
    assert rec["telemetry"]["label"] is None
    assert rec["telemetry"]["label_name"] is None
    assert rec["telemetry"]["scanner_label"] == 1
    assert rec["telemetry"]["scanner_finding_status"] == "Confirmed"
    assert rec["finding"]["finding_status"] == "Confirmed"

    # Off by default: no env var -> no file, no exception.
    monkeypatch.delenv("DATASET_LOG_DIR")
    main_mod.log_dataset_pair(
        session_id=8, target_url="http://t", test_item={"type": "XSS"},
        test_method="GET", test_url="http://t/x", payload_str="<x>",
        baseline_telemetry={}, req_data={}, features={},
        sig_res={}, risk_summary={})
    assert not (tmp_path / "dataset-session-8.jsonl").exists()


def test_dataset_logging_refuses_held_out_targets(tmp_path, monkeypatch):
    """Held-out apps are never training data: logging a Juice Shop or
    crAPI target writes nothing, even with DATASET_LOG_DIR set. The guard
    keys on both the URL and the declared app name, because a local Juice
    Shop runs on 127.0.0.1:3000, which carries no marker in the URL."""
    import main as main_mod

    monkeypatch.setenv("DATASET_LOG_DIR", str(tmp_path))
    # Declared app name is the marker for a localhost held-out target.
    monkeypatch.setenv("DATASET_TARGET_APP", "juice-shop")
    main_mod.log_dataset_pair(
        session_id=9, target_url="http://127.0.0.1:3000",
        test_item={"type": "SQL_Injection"}, test_method="GET",
        test_url="http://127.0.0.1:3000/rest/products/search?q=x",
        payload_str="'", baseline_telemetry={}, req_data={}, features={},
        sig_res={}, risk_summary={})
    assert not (tmp_path / "dataset-session-9.jsonl").exists()
    # And a URL carrying the marker is refused regardless of the app name.
    monkeypatch.setenv("DATASET_TARGET_APP", "crapi")
    main_mod.log_dataset_pair(
        session_id=10, target_url="http://juice-shop:3000",
        test_item={"type": "SQL_Injection"}, test_method="GET",
        test_url="http://juice-shop:3000/rest/products/search?q=x",
        payload_str="'", baseline_telemetry={}, req_data={}, features={},
        sig_res={}, risk_summary={})
    assert not (tmp_path / "dataset-session-10.jsonl").exists()
