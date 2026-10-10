import os
import sys
import json
import math
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.numpy_compat import ensure_numpy2_pickle_compat  # noqa: E402  (applies NumPy 2.x pickle shim)

ensure_numpy2_pickle_compat()

from config.logging_config import logger
from config.settings import ISOLATION_FOREST_PATH, TABULAR_RANKER_PATH
# Canonical feature schema — the single source of truth. Train and serve
# share these exact definitions (ml_pipeline/feature_extractor.py).
from ml_pipeline.feature_extractor import FEATURE_KEYS, SCHEMA_VERSION


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    exp_z = math.exp(z)
    return exp_z / (1.0 + exp_z)


class MLAnomalyDetector:
    """
    Layer 2 — ML Anomaly Detection Engine (response-differential).

    Uses a trained Isolation Forest to score how anomalous a probe's *HTTP
    response* is relative to benign response telemetry (schema documented in
    ml_pipeline/feature_extractor.py). A benign probe returns a response that
    looks like the baseline and scores near 0; an exploited probe (SQL error
    page, reflection, delay, 5xx) scores high.

    Calibration
    -----------
    The raw Isolation Forest decision_function value `d` (negative = anomaly)
    is mapped to a 0..1 anomaly score with a sigmoid anchored at the model's
    own contamination quantile:

        score = sigmoid( -3 * (d - q05) / std )

    where q05/std are the 5th percentile and std of decision_function on the
    benign training data (saved in iforest_calibration.json at train time).
    This replaces the old unjustified `0.5 - (decision_score * 5.0)` mapping,
    which saturated to ~binary output. With contamination=0.05, roughly 5%
    of benign traffic scores above 0.5 — the model's own operating point.
    """

    # Re-exported so existing callers/tests keep working.
    FEATURE_KEYS = FEATURE_KEYS

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else Path(ISOLATION_FOREST_PATH)
        self.scaler_path = self.model_path.parent / "feature_scaler.pkl"
        self.calibration_path = self.model_path.parent / "iforest_calibration.json"
        self.ranker_path = Path(TABULAR_RANKER_PATH)
        self.model = self._load_model()
        self.scaler = self._load_scaler()
        self.calibration = self._load_calibration()
        self.ranker = self._load_ranker()

    def _load_model(self) -> Optional[Any]:
        if not self.model_path.exists():
            logger.warning(f"Isolation Forest model file not found at {self.model_path}. Layer 2 will return baseline scores.")
            return None
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Successfully loaded Isolation Forest model from {self.model_path}")
            return model
        except Exception as exc:
            logger.error(f"Error loading Isolation Forest model from {self.model_path}: {exc}")
            return None

    def _load_scaler(self) -> Optional[Any]:
        if not self.scaler_path.exists():
            return None
        try:
            return joblib.load(self.scaler_path)
        except Exception:
            return None

    def _load_calibration(self) -> Optional[Dict[str, float]]:
        """Load the decision_function calibration saved at train time."""
        if not self.calibration_path.exists():
            logger.warning(f"Isolation Forest calibration not found at {self.calibration_path}; "
                           "using uncalibrated sigmoid fallback.")
            return None
        try:
            with open(self.calibration_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {
                "decision_q05": float(data["decision_q05"]),
                "decision_std": float(data["decision_std"]) or 1.0,
            }
        except Exception as exc:
            logger.warning(f"Could not load Isolation Forest calibration: {exc}")
            return None

    def _load_ranker(self) -> Optional[Any]:
        if not self.ranker_path.exists():
            return None
        try:
            artifact = joblib.load(self.ranker_path)
            return artifact.get("model") if isinstance(artifact, dict) else artifact
        except Exception as exc:
            logger.warning(f"Calibrated tabular ranker could not be loaded: {exc}")
            return None

    def _ranker_signal(self, features_array: np.ndarray) -> Dict[str, Any]:
        if self.ranker is None:
            return {"supervised_probability": 0.0, "supervised_points": 0.0, "ranker_available": False}
        try:
            probability = float(self.ranker.predict_proba(features_array)[0][1])
            probability = float(np.clip(probability, 0.0, 1.0))
            return {
                "supervised_probability": round(probability, 4),
                "supervised_points": round(probability * 10.0, 2),
                "ranker_available": True,
            }
        except Exception as exc:
            logger.warning(f"Calibrated tabular ranker inference failed: {exc}")
            return {"supervised_probability": 0.0, "supervised_points": 0.0, "ranker_available": False}

    def anomaly_score_from_decision(self, decision_score: float) -> float:
        """Map a raw Isolation Forest decision_function value to 0..1.

        Calibrated: sigmoid anchored at the benign-training 5th percentile.
        Uncalibrated fallback (no calibration file): sigmoid(-3 * d), which
        still respects the sign convention (negative d = anomaly).
        """
        if self.calibration is not None:
            q05 = self.calibration["decision_q05"]
            std = self.calibration["decision_std"]
            z = -3.0 * (decision_score - q05) / std
        else:
            z = -3.0 * decision_score
        return float(np.clip(_sigmoid(z), 0.0, 1.0))

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs Isolation Forest anomaly prediction on the extracted feature vector (schema defined by FEATURE_KEYS).
        Returns normalized anomaly score (0.0 to 1.0) and points (0 to 25).
        """
        if self.model is None:
            result = {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "points": 0,
                "note": "Model file missing"
            }
            result.update(self._ranker_signal(np.array([[feature_dict.get(k, 0) for k in self.FEATURE_KEYS]], dtype=float)))
            return result

        # Extract feature vector in correct ordered array shape
        if "feature_vector" in feature_dict and len(feature_dict["feature_vector"]) == len(self.FEATURE_KEYS):
            vector = feature_dict["feature_vector"]
        else:
            vector = [feature_dict.get(k, 0) for k in self.FEATURE_KEYS]

        features_array = np.array(vector, dtype=float).reshape(1, -1)

        ranker_features = features_array.copy()
        if self.scaler is not None:
            try:
                features_array = self.scaler.transform(features_array)
            except Exception:
                pass
        ranker_signal = self._ranker_signal(ranker_features)

        try:
            # Raw decision function output (lower values indicate higher anomaly likelihood)
            decision_score = float(self.model.decision_function(features_array)[0])

            # Calibrated 0..1 mapping (documented in the class docstring).
            normalized_score = self.anomaly_score_from_decision(decision_score)

            is_anomaly = bool(decision_score < 0 or normalized_score > 0.5)
            points = round(normalized_score * 25.0, 2)

            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(normalized_score, 4),
                "points": min(points, 25.0),
                "note": "Model prediction complete",
                **ranker_signal,
            }
        except Exception as exc:
            logger.error(f"Error executing Isolation Forest inference: {exc}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "points": 0,
                "note": f"Inference error: {exc}",
                **ranker_signal,
            }


if __name__ == "__main__":
    detector = MLAnomalyDetector()
    # Benign probe: response identical to baseline -> should score ~0.
    benign_features = {k: 0 for k in FEATURE_KEYS}
    benign_features.update({
        "status_class": 2, "response_size_log": 2.7, "response_time_s": 0.12,
        "encoded_method": 1,
    })
    res = detector.predict(benign_features)
    print("\n[+] ML Anomaly Detector — benign probe:")
    for k, v in res.items():
        print(f"  {k}: {v}")
