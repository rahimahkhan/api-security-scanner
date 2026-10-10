import pytest
from detection.deep_learning import DeepLearningDetector
from ml_pipeline.feature_extractor import FEATURE_KEYS

def test_deep_learning_detector_inference():
    detector = DeepLearningDetector()

    sample_payload = "' OR 1=1 --"
    # Response-differential features: anomalous SQL-error-style response.
    sample_features = {k: 0 for k in FEATURE_KEYS}
    sample_features.update({
        "status_changed": 1,
        "body_diff_ratio": 0.6,
        "error_keyword_delta": 3,
        "error_keyword_count": 3,
        "status_class": 5,
        "response_size_log": 2.0,
        "response_time_s": 0.3,
        "payload_length_log": 1.0,
        "encoded_method": 2,
    })

    res = detector.analyze(sample_payload, sample_features)
    assert "lstm_probability" in res
    assert "lstm_points" in res
    assert "autoencoder_error" in res
    assert "autoencoder_points" in res
    assert 0.0 <= res["lstm_points"] <= 15.0
    assert 0.0 <= res["autoencoder_points"] <= 20.0
    # LSTM now trained: malicious payload should score higher than benign text.
    benign = detector.analyze("search?q=laptop", sample_features)
    assert res["lstm_probability"] >= benign["lstm_probability"]
