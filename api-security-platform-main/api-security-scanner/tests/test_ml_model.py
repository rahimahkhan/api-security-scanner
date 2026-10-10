import pytest
import os
import pandas as pd
from pathlib import Path
from detection.ml_model import MLAnomalyDetector
from ml_pipeline.feature_extractor import FEATURE_KEYS
from config.settings import MODELS_DIR

def test_ml_anomaly_detector_inference():
    model_path = Path(MODELS_DIR) / "isolation_forest.pkl"
    detector = MLAnomalyDetector(model_path=str(model_path))

    # Benign probe: response identical to baseline -> near-zero anomaly.
    sample_features = {k: 0 for k in FEATURE_KEYS}
    sample_features.update({
        "status_class": 2,
        "response_size_log": 2.7,
        "response_time_s": 0.12,
        "encoded_method": 1,
    })

    res = detector.predict(sample_features)
    assert "anomaly_score" in res
    assert "points" in res
    assert 0.0 <= res["anomaly_score"] <= 1.0
    assert 0.0 <= res["points"] <= 25.0
    assert res["is_anomaly"] is False
    assert res["points"] < 5.0  # benign responses must not inflate risk


def test_ml_anomaly_detector_flags_error_page():
    model_path = Path(MODELS_DIR) / "isolation_forest.pkl"
    detector = MLAnomalyDetector(model_path=str(model_path))

    # SQL error page vs clean baseline -> strong anomaly.
    sample_features = {k: 0 for k in FEATURE_KEYS}
    sample_features.update({
        "status_changed": 1,
        "size_delta_ratio": -0.8,
        "body_diff_ratio": 0.6,
        "content_type_changed": 1,
        "error_keyword_delta": 3,
        "error_keyword_count": 3,
        "status_class": 5,
        "response_size_log": 1.8,
        "response_time_s": 0.3,
        "payload_length_log": 1.2,
        "encoded_method": 2,
    })

    res = detector.predict(sample_features)
    assert res["is_anomaly"] is True
    assert res["points"] > 10.0


def test_calibrated_mapping_is_smooth_not_binary():
    # The old 0.5 - (d * 5.0) mapping saturated to ~binary output.
    # The calibrated sigmoid must produce intermediate values *within its
    # transition band* (around the contamination quantile), not just 0/1.
    detector = MLAnomalyDetector(model_path=str(Path(MODELS_DIR) / "missing.pkl"))
    if detector.calibration is not None:
        q05, std = detector.calibration["decision_q05"], detector.calibration["decision_std"]
        decisions = (q05 + 2 * std, q05 + 0.5 * std, q05 - 0.5 * std, q05 - 2 * std)
    else:
        decisions = (0.3, 0.1, -0.1, -0.3)  # uncalibrated fallback scale
    scores = [detector.anomaly_score_from_decision(d) for d in decisions]
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert scores == sorted(scores)  # more negative d -> higher score
    assert any(0.05 < s < 0.95 for s in scores)  # smooth through the band, not a step
