import pytest
from detection.deep_learning import DeepLearningDetector
from ml_pipeline.feature_extractor import FEATURE_KEYS

def test_deep_learning_detector_inference():
    detector = DeepLearningDetector()

    # The target's response body to a probe: a real SQL error page.
    sql_error_body = ("Warning: mysql_fetch_array() expects parameter 1 to be "
                      "resource, boolean given. You have an error in your SQL "
                      "syntax near '' OR 1=1 --''")
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

    res = detector.analyze(sql_error_body, sample_features)
    assert "lstm_probability" in res
    assert "lstm_points" in res
    assert "autoencoder_error" in res
    assert "autoencoder_points" in res
    assert 0.0 <= res["lstm_points"] <= 15.0
    assert 0.0 <= res["autoencoder_points"] <= 20.0
    # The response-body LSTM is trained on real response bodies: an
    # exploit-effect body must score higher than a normal response body.
    benign = detector.analyze('{"status":"ok","version":"1.0"}', sample_features)
    assert res["lstm_probability"] > benign["lstm_probability"]
    assert res["lstm_points"] > benign["lstm_points"]


def test_response_lstm_actually_loads():
    """Regression pair to the autoencoder load test: the production
    response-body LSTM artifacts must exist and load, or Layer 3's LSTM
    silently scores 0 on every scan."""
    from pathlib import Path
    models_dir = Path(__file__).resolve().parent.parent / "models"
    assert (models_dir / "response_lstm.pt").exists()
    assert (models_dir / "response_char_vocab.json").exists()
    detector = DeepLearningDetector()
    assert detector.lstm_model is not None


def test_autoencoder_actually_loads():
    """Regression: the shipped checkpoint was trained with bottleneck_dim=8
    while serving hardcoded 6, so the load failed silently and Layer 3's
    autoencoder scored 0 on every scan. The production model MUST load."""
    detector = DeepLearningDetector()
    assert detector.autoencoder is not None


def test_autoencoder_scores_anomalous_above_benign():
    """The autoencoder is trained on benign response-differential features:
    real anomalous rows from the shipped dataset must reconstruct with a
    higher mean error than real benign rows. (Synthetic all-zero vectors
    are themselves out-of-distribution, so this uses actual dataset rows.)"""
    import pandas as pd
    from pathlib import Path

    detector = DeepLearningDetector()
    data_path = (Path(__file__).resolve().parent.parent
                 / "ml_pipeline" / "datasets" / "response_diff_v1.csv")
    df = pd.read_csv(data_path)

    def mean_error(rows):
        errors = []
        for _, r in rows.iterrows():
            feats = {k: float(r[k]) for k in FEATURE_KEYS}
            feats["feature_vector"] = [float(r[k]) for k in FEATURE_KEYS]
            errors.append(detector.analyze("", feats)["autoencoder_error"])
        return sum(errors) / len(errors)

    benign_err = mean_error(df[df["label"] == 0].head(50))
    anomalous_err = mean_error(df[df["label"] == 1].head(50))
    assert anomalous_err > benign_err


def test_autoencoder_baseline_relative_scoring():
    """With a baseline, the autoencoder scores EXCESS error over the app's
    own normal response: an unchanged response earns 0 points even on an
    app unlike the training services, while a genuinely deviating response
    still earns points. Uses mean feature vectors of real dataset rows."""
    import pandas as pd
    from pathlib import Path

    detector = DeepLearningDetector()
    data_path = (Path(__file__).resolve().parent.parent
                 / "ml_pipeline" / "datasets" / "response_diff_v1.csv")
    df = pd.read_csv(data_path)

    def mean_feats(rows):
        feats = {k: float(rows[k].mean()) for k in FEATURE_KEYS}
        feats["feature_vector"] = [feats[k] for k in FEATURE_KEYS]
        return feats

    benign = mean_feats(df[df["label"] == 0].head(50))
    anomalous = mean_feats(df[df["label"] == 1].head(50))

    unchanged = detector.analyze("", benign, baseline_feature_dict=benign)
    assert unchanged["autoencoder_points"] == 0.0

    deviating = detector.analyze("", anomalous, baseline_feature_dict=benign)
    assert deviating["autoencoder_points"] > unchanged["autoencoder_points"]
