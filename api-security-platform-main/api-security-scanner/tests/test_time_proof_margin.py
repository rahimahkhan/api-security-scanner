"""Regression tests: tightened time-based proof margin (2026-10-15).

Found live 2026-10-14: two fabricated Confirmed findings from a single slow
response under scan load —
  * CMDi @100 on /about.php: 3.64s against a `sleep 5` payload (the sleep did
    not execute — 3.64s < 5s — yet the old >3.0s floor Confirmed it);
  * SQLi @100 on /logout.php: a one-off 8.68s spike against SLEEP(5).
Neither page has a command/SQL sink; manual ground truth found nothing.

The tightened gate requires BOTH:
  1. proportionality — the delay reaches the payload's own injected delay
     (minus 1.0s tolerance), not merely a 3.0s floor;
  2. reproduction — an identical re-probe (pipeline-attached as
     "time_proof_repro_delta") shows the delay again.

Direct analyze() callers without a re-probe keep the single-measurement
contract (proportionality only); the live pipeline always re-probes via
main.verify_time_based_proof.
"""
from detection.signature import SignatureDetector, extract_delay_seconds


def _telemetry(payload, attack_category, response_time, body="ok", repro_delta=None,
               repro_failed=False):
    req = {
        "url": "http://example.test/vuln/",
        "payload": payload,
        "attack_category": attack_category,
        "status_code": 200,
        "response_size": 100,
        "response_headers": {},
        "response_body": body,
        "request_headers": {},
        "response_time": response_time,
    }
    if repro_delta is not None or repro_failed:
        req["time_proof_repro_delta"] = repro_delta
        req["time_proof_repro_failed"] = repro_failed
    return req


def _baseline(t=0.2):
    return {"response_time": t, "response_size": 100, "status_code": 200,
            "response_body": "ok"}


# --- delay parsing -----------------------------------------------------------

def test_extract_delay_seconds():
    assert extract_delay_seconds("1' AND SLEEP(5)--") == 5.0
    assert extract_delay_seconds("1' AND SLEEP(5) --") == 5.0
    assert extract_delay_seconds("1' AND pg_sleep(3)--") == 3.0
    assert extract_delay_seconds("'; EXEC sp_executesql N'';--") is None
    assert extract_delay_seconds("; cat /etc/passwd; sleep 5") == 5.0
    assert extract_delay_seconds("1; WAITFOR DELAY '0:0:7'--") == 7.0
    # BENCHMARK iterations have no knowable duration: unparseable on purpose.
    assert extract_delay_seconds("1' AND BENCHMARK(5000000,MD5(1))--") is None
    assert extract_delay_seconds("' OR 1=1--") is None
    assert extract_delay_seconds("") is None


# --- proportionality kills the /about.php false positive --------------------

def test_sqli_below_injected_delay_is_suspected_without_reprobe():
    # /about.php case: 3.64s against SLEEP(5) — the sleep never executed.
    res = SignatureDetector().analyze(
        _telemetry("1' AND SLEEP(5)--", "SQL_Injection", 3.84),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Suspected"
    assert res["has_proof"] is False
    assert "rejected" in res["proof_of_concept"]


def test_cmdi_below_injected_delay_is_suspected_without_reprobe():
    res = SignatureDetector().analyze(
        _telemetry("; cat /etc/passwd; sleep 5", "Command_Injection", 3.84),
        baseline_telemetry=_baseline())
    assert res["attack_type"] == "Command_Injection"
    assert res["finding_status"] == "Suspected"
    assert res["has_proof"] is False


# --- reproduction kills the /logout.php false positive -----------------------

def test_sqli_one_off_spike_fails_reproduction():
    # /logout.php case: 8.68s clears the injected 5s, but the re-probe is fast.
    res = SignatureDetector().analyze(
        _telemetry("1' AND SLEEP(5)--", "SQL_Injection", 8.88,
                   repro_delta=0.5),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Suspected"
    assert res["has_proof"] is False
    assert "did not reproduce" in res["proof_of_concept"]


def test_cmdi_one_off_spike_fails_reproduction():
    res = SignatureDetector().analyze(
        _telemetry("; cat /etc/passwd; sleep 5", "Command_Injection", 8.88,
                   repro_delta=0.4),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Suspected"
    assert res["has_proof"] is False


def test_failed_reprobe_downgrades():
    # A re-probe that failed/timed out is never proof.
    res = SignatureDetector().analyze(
        _telemetry("1' AND SLEEP(5)--", "SQL_Injection", 5.4,
                   repro_delta=None, repro_failed=True),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Suspected"
    assert res["has_proof"] is False


# --- real delays still confirm -----------------------------------------------

def test_sqli_real_delay_confirms_with_reproduction():
    res = SignatureDetector().analyze(
        _telemetry("1' AND SLEEP(5)--", "SQL_Injection", 5.4, repro_delta=5.2),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Confirmed"
    assert res["has_proof"] is True
    assert "re-probe" in res["proof_of_concept"]


def test_cmdi_real_delay_confirms_with_reproduction():
    res = SignatureDetector().analyze(
        _telemetry("; cat /etc/passwd; sleep 5", "Command_Injection", 5.5,
                   repro_delta=5.3),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Confirmed"
    assert res["has_proof"] is True


def test_unparseable_delay_uses_floor_plus_reproduction():
    # BENCHMARK has no knowable duration: 3.0s floor still applies, but the
    # delay must reproduce.
    ok = SignatureDetector().analyze(
        _telemetry("1' AND BENCHMARK(5000000,MD5(1))--", "SQL_Injection", 4.4,
                   repro_delta=4.6),
        baseline_telemetry=_baseline())
    assert ok["finding_status"] == "Confirmed"
    flaky = SignatureDetector().analyze(
        _telemetry("1' AND BENCHMARK(5000000,MD5(1))--", "SQL_Injection", 4.4,
                   repro_delta=0.3),
        baseline_telemetry=_baseline())
    assert flaky["finding_status"] == "Suspected"


def test_fast_response_is_still_suspected():
    res = SignatureDetector().analyze(
        _telemetry("1' AND SLEEP(5)--", "SQL_Injection", 0.2),
        baseline_telemetry=_baseline())
    assert res["finding_status"] == "Suspected"
    assert res["has_proof"] is False


# --- pipeline helper ----------------------------------------------------------

class _FakeEngine:
    def __init__(self, repro_time=None, status=200, error=None, explode=False):
        self.repro_time = repro_time
        self.status = status
        self.error = error
        self.explode = explode
        self.calls = 0

    def send_request(self, *a, **k):
        self.calls += 1
        if self.explode:
            raise RuntimeError("connection dropped")
        return {"status_code": self.status, "response_time": self.repro_time,
                "response_size": 100, "response_body": "ok",
                "response_headers": {}, "error": self.error}


def _import_helper():
    from main import verify_time_based_proof
    return verify_time_based_proof


def _req_data(response_time=5.4):
    return _telemetry("1' AND SLEEP(5)--", "SQL_Injection", response_time)


def test_pipeline_reprobe_confirms_when_delay_reproduces():
    helper = _import_helper()
    engine = _FakeEngine(repro_time=5.3)
    det = SignatureDetector()
    item = {"type": "SQL_Injection_Time", "follow_redirects": True}
    res = helper(engine, det, item, "GET", "http://example.test/vuln/",
                 "1' AND SLEEP(5)--", None, None, None, None,
                 _req_data(), _baseline())
    assert engine.calls == 1
    assert res["finding_status"] == "Confirmed"
    assert res["has_proof"] is True


def test_pipeline_reprobe_downgrades_when_delay_does_not_reproduce():
    helper = _import_helper()
    engine = _FakeEngine(repro_time=0.4)
    det = SignatureDetector()
    item = {"type": "SQL_Injection_Time", "follow_redirects": True}
    req = _req_data()
    res = helper(engine, det, item, "GET", "http://example.test/vuln/",
                 "1' AND SLEEP(5)--", None, None, None, None,
                 req, _baseline())
    assert res["finding_status"] == "Suspected"
    assert req["time_proof_repro_delta"] == 0.2  # 0.4 - baseline 0.2
    assert req["time_proof_repro_failed"] is False


def test_pipeline_reprobe_timeout_downgrades():
    helper = _import_helper()
    # A timed-out re-probe carries a synthetic ~30s response_time; it must
    # never count as a reproduced delay.
    engine = _FakeEngine(repro_time=31.2, status=408,
                         error="TimeoutException: request timed out")
    det = SignatureDetector()
    item = {"type": "SQL_Injection_Time"}
    req = _req_data()
    res = helper(engine, det, item, "GET", "http://example.test/vuln/",
                 "1' AND SLEEP(5)--", None, None, None, None,
                 req, _baseline())
    assert res["finding_status"] == "Suspected"
    assert req["time_proof_repro_failed"] is True


def test_pipeline_reprobe_exception_downgrades():
    helper = _import_helper()
    engine = _FakeEngine(explode=True)
    det = SignatureDetector()
    item = {"type": "SQL_Injection_Time"}
    req = _req_data()
    res = helper(engine, det, item, "GET", "http://example.test/vuln/",
                 "1' AND SLEEP(5)--", None, None, None, None,
                 req, _baseline())
    assert res["finding_status"] == "Suspected"
    assert req["time_proof_repro_failed"] is True
