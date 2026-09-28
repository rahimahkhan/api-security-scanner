import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.numpy_compat import ensure_numpy2_pickle_compat  # noqa: E402  (applies NumPy 2.x pickle shim)

ensure_numpy2_pickle_compat()

from config.logging_config import logger
from config.settings import ISOLATION_FOREST_PATH, TABULAR_RANKER_PATH

class MLAnomalyDetector:
    """
    Layer 2 — ML Anomaly Detection Engine
    Uses trained Isolation Forest model to evaluate the defined numerical HTTP features
    (schema available in FEATURE_KEYS, currently 17 features) and calculates anomaly scores and risk points (0 to 40).
    """

    FEATURE_KEYS = [
        "encoded_method",
        "path_depth",
        "url_length",
        "query_param_count",
        "query_string_length",
        "payload_length",
        "payload_entropy",
        "special_char_count",
        "header_count",
        "auth_header_present",
        "status_code",
        "response_size",
        "keyword_risk_score",
        "param_name_risk",
        "url_encoded_ratio",
        "payload_digit_ratio",
        "has_sql_structure"
    ]

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else Path(ISOLATION_FOREST_PATH)
        self.scaler_path = self.model_path.parent / "feature_scaler.pkl"
        self.ranker_path = Path(TABULAR_RANKER_PATH)
        self.model = self._load_model()
        self.scaler = self._load_scaler()
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
            decision_score = self.model.decision_function(features_array)[0]
            
            # Normalize decision score to an anomaly score between 0.0 and 1.0
            # For Isolation Forest, negative decision_score indicates anomaly
            raw_anomaly_score = 0.5 - (decision_score * 5.0)
            normalized_score = float(np.clip(raw_anomaly_score, 0.0, 1.0))
            
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
    sample_features = {
        "encoded_method": 2,
        "path_depth": 4,
        "url_length": 120,
        "query_param_count": 5,
        "query_string_length": 80,
        "payload_length": 250,
        "payload_entropy": 6.8,
        "special_char_count": 35,
        "header_count": 6,
        "auth_header_present": 0,
        "status_code": 500,
        "response_size": 4096
    }
    res = detector.predict(sample_features)
    print("\n[+] ML Anomaly Detector Test Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
