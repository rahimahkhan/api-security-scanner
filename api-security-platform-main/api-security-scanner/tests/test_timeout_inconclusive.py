"""Regression tests: probe timeouts must never become vulnerability findings.

Found live on 2026-09-29: a scan of testphp.vulnweb.com while the site was
down (every request hung and hit the ~30s timeout, recorded as synthetic
status 408 with 0-byte bodies) produced HIGH "Suspected" SQLi/XSS/
Command-Injection findings plus a missing-headers misconfiguration — all from
probes that received no response at all.

A timeout carries no response to analyze, so when the baseline is also
unusable the probe is inconclusive: 0 points, no finding. Only a timeout
against a *healthy* baseline is kept as a weak differential signal, mirroring
the long-standing status-0 handling.
"""
from detection.signature import SignatureDetector
from detection.risk_scorer import RiskScorer


def _timeout_req(payload="' OR 1=1 --"):
    return {
        "url": "http://t/",
        "payload": payload,
        "attack_category": "SQL_Injection_GET",
        "status_code": 408,
        "response_size": 0,
        "response_time": 31.2,
        "response_headers": {},
        "response_body": "",
        "error": "TimeoutException: request timed out",
    }


def _dead_baseline():
    return {"status_code": 408, "response_size": 0, "response_time": 30.9,
            "response_body": ""}


def _healthy_baseline():
    return {"status_code": 200, "response_size": 120, "response_time": 0.2,
            "response_body": "<html>ok</html>"}


def test_timeout_with_dead_baseline_is_unreachable_not_suspected():
    res = SignatureDetector().analyze(_timeout_req(),
                                     baseline_telemetry=_dead_baseline())
    assert res["finding_status"] == "UNREACHABLE / NETWORK_DROPPED"
    assert res["matched"] is False
    assert res["points"] == 0
    assert res["is_vulnerable"] is False


def test_timeout_with_no_baseline_is_unreachable():
    res = SignatureDetector().analyze(_timeout_req(), baseline_telemetry=None)
    assert res["finding_status"] == "UNREACHABLE / NETWORK_DROPPED"
    assert res["matched"] is False
    assert res["points"] == 0


def test_timed_out_baseline_does_not_count_as_healthy():
    # 408 falls inside 200-499; it must still be treated as unusable.
    res = SignatureDetector().analyze(_timeout_req(),
                                     baseline_telemetry=_dead_baseline())
    assert res["attack_type"] == "Network_Error"


def test_timeout_against_healthy_baseline_keeps_weak_differential_signal():
    res = SignatureDetector().analyze(_timeout_req(),
                                     baseline_telemetry=_healthy_baseline())
    assert res["finding_status"] == "Suspected"
    assert res["matched"] is True
    assert res["attack_type"] == "Application_Request_Timeout"
    assert res["points"] == 10
    assert res["is_vulnerable"] is False


def test_timeout_never_fires_missing_header_misconfiguration():
    # Empty headers on a timed-out probe must not become
    # Security_Misconfiguration.
    res = SignatureDetector().analyze(_timeout_req(payload=""),
                                     baseline_telemetry=_dead_baseline())
    assert res["attack_type"] != "Security_Misconfiguration"


def test_risk_scorer_gates_timeout_to_zero():
    sig = {"matched": False, "has_proof": False, "is_vulnerable": False,
           "points": 0, "finding_status": "UNREACHABLE / NETWORK_DROPPED"}
    ml = {"is_anomaly": True, "points": 8.5}
    dl = {"lstm_points": 15.0, "autoencoder_points": 20.0,
          "total_layer3_points": 35.0}
    out = RiskScorer().calculate_risk(
        sig, ml, dl, "http://t/", "GET",
        telemetry_data={"status_code": 408, "response_size": 0,
                        "response_time": 31.2},
    )
    assert out["total_score"] == 0.0
    assert out["severity"] == "NONE"
    assert out["finding_status"] == "UNREACHABLE / NETWORK_DROPPED"
    assert out["is_vulnerable"] is False


def test_pipeline_save_condition_rejects_timeout_probe():
    # Mirrors main.py: a finding is persisted only when score > 0 or the
    # signature matched. A dead-baseline timeout satisfies neither, so the
    # probe leaves no finding behind.
    sig = SignatureDetector().analyze(_timeout_req(),
                                     baseline_telemetry=_dead_baseline())
    out = RiskScorer().calculate_risk(
        sig, {"points": 0}, {"lstm_points": 0, "autoencoder_points": 0},
        "http://t/", "GET",
        telemetry_data={"status_code": 408, "response_size": 0,
                        "response_time": 31.2},
    )
    assert not (out["total_score"] > 0 or sig.get("matched"))
