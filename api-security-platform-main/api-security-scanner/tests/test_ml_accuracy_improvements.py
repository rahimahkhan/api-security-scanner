import numpy as np

from detection.ml_model import MLAnomalyDetector
from detection.risk_scorer import RiskScorer
from ml_pipeline.telemetry_schema import build_telemetry_record, label_from_result


def test_telemetry_label_requires_proof_for_confirmation():
    assert label_from_result("Suspected", has_proof=False, response_status=200) == "suspected"
    assert label_from_result("Suspected", has_proof=True, response_status=200) == "confirmed"
    assert label_from_result("Confirmed", has_proof=False, response_status=200) == "confirmed"
    assert label_from_result("Blocked", has_proof=False, response_status=403) == "blocked"
    assert label_from_result("Network_Error", has_proof=False, response_status=0) == "network_error"


def test_telemetry_record_preserves_grouping_metadata():
    record = build_telemetry_record(
        {"payload_length": 12, "status_code": 200},
        finding_status="Suspected",
        has_proof=False,
        response_status=200,
        attack_type="SQL_Injection",
        target_id="dvwa",
        endpoint_id="exec",
        payload_family="sql_boolean",
    )
    assert record["label"] == 0
    assert record["label_name"] == "suspected"
    assert record["target_id"] == "dvwa"
    assert record["payload_family"] == "sql_boolean"


def test_ranker_signal_is_optional_and_bounded(tmp_path):
    detector = MLAnomalyDetector(model_path=str(tmp_path / "missing_isolation.pkl"))

    class FakeRanker:
        def predict_proba(self, features):
            assert features.shape == (1, len(MLAnomalyDetector.FEATURE_KEYS))
            return np.array([[0.1, 0.9]])

    detector.ranker = FakeRanker()
    result = detector.predict({key: 0 for key in MLAnomalyDetector.FEATURE_KEYS})
    assert result["ranker_available"] is True
    assert result["supervised_probability"] == 0.9
    assert result["supervised_points"] == 9.0
    assert result["is_anomaly"] is False


def test_ranker_signal_cannot_confirm_without_signature_proof():
    scorer = RiskScorer()
    result = scorer.calculate_risk(
        signature_result={
            "matched": True,
            "is_vulnerable": False,
            "has_proof": False,
            "points": 10,
            "attack_type": "SQL_Injection",
            "pattern_matched": "SQL syntax-like payload",
        },
        ml_result={
            "is_anomaly": False,
            "points": 0,
            "supervised_probability": 1.0,
            "supervised_points": 10.0,
        },
        dl_result={"lstm_points": 0, "autoencoder_points": 0},
        endpoint_url="http://example.test/login",
        http_method="POST",
        telemetry_data={"status_code": 200, "response_size": 100, "response_time": 0.1},
    )
    assert result["is_vulnerable"] is False
    assert result["finding_status"] == "Suspected"
    assert result["points_breakdown"]["supervised_points"] == 10.0
