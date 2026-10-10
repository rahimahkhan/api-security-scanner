import pytest
from core.response_parser import ResponseParser
from detection.ml_model import MLAnomalyDetector
from ml_pipeline.feature_extractor import FEATURE_KEYS


def _benign_pair():
    baseline = {
        "method": "GET",
        "url": "http://example.com/api/v1/users",
        "payload": "",
        "status_code": 200,
        "response_size": 256,
        "response_time": 0.1,
        "response_body": '{"users": []}',
        "response_headers": {"Content-Type": "application/json"},
        "request_headers": {"Authorization": "Bearer abc.def.ghi"},
    }
    probe = dict(baseline, payload="hello")
    return baseline, probe


def test_feature_vector_length_matches_feature_keys():
    parser = ResponseParser()
    baseline, probe = _benign_pair()
    extracted = parser.extract_features(probe, baseline)

    assert "feature_vector" in extracted
    # Serving-time vector must align with the canonical schema detectors use.
    assert len(extracted["feature_vector"]) == len(MLAnomalyDetector.FEATURE_KEYS) == len(FEATURE_KEYS)


def test_benign_probe_has_zero_differentials():
    parser = ResponseParser()
    baseline, probe = _benign_pair()
    extracted = parser.extract_features(probe, baseline)

    assert extracted["status_changed"] == 0
    assert extracted["body_diff_ratio"] == 0.0
    assert extracted["error_keyword_delta"] == 0
    assert extracted["payload_reflected"] == 0
    assert extracted["status_class"] == 2


def test_none_status_code_does_not_crash():
    parser = ResponseParser()
    extracted = parser.extract_features({"status_code": None, "response_body": ""})
    assert extracted["status_class"] == 0
    assert extracted["status_changed"] == 0  # no baseline -> graceful degradation


def test_sensitive_fields_still_reported():
    parser = ResponseParser()
    baseline, probe = _benign_pair()
    probe["response_body"] = '{"token": "secret_token"}'
    probe["response_size"] = 32
    extracted = parser.extract_features(probe, baseline)
    assert "token" in extracted["sensitive_fields_leaked"]
