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
