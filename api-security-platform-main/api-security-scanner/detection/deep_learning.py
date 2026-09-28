import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import torch
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import MODELS_DIR, LSTM_MODEL_PATH, AUTOENCODER_PATH
from training.train_lstm import PayloadLSTM, encode_text
from training.train_autoencoder import FeatureAutoencoder

class DeepLearningDetector:
    """
    Layer 3 — Deep Learning Detection Engine
    Integrates character-level LSTM (malicious payload probability)
    and PyTorch Autoencoder (reconstruction error score).
    """

    FEATURE_KEYS = [
        "encoded_method", "path_depth", "url_length", "query_param_count",
        "query_string_length", "payload_length", "payload_entropy",
        "special_char_count", "header_count", "auth_header_present",
        "status_code", "response_size", "keyword_risk_score",
        "param_name_risk", "url_encoded_ratio", "payload_digit_ratio",
        "has_sql_structure"
    ]

    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else Path(MODELS_DIR)
        
        self.lstm_model = self._load_lstm()
        self.vocab = self._load_vocab()
        
        self.autoencoder = self._load_autoencoder()
        self.scaler = self._load_scaler()
        self.ae_threshold = self._load_threshold()

    def _load_vocab(self) -> Dict[str, int]:
        vocab_path = self.models_dir / "char_vocab.json"
        if vocab_path.exists():
            with open(vocab_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"<PAD>": 0, "<UNK>": 1}

    def _load_lstm(self) -> Optional[PayloadLSTM]:
        lstm_path = Path(LSTM_MODEL_PATH)
        vocab_path = self.models_dir / "char_vocab.json"
        if not lstm_path.exists() or not vocab_path.exists():
            logger.warning("LSTM model file or character vocab missing. Layer 3 LSTM set to fallback.")
            return None
        try:
            with open(vocab_path, "r", encoding="utf-8") as f:
                vocab = json.load(f)
            model = PayloadLSTM(vocab_size=len(vocab))
            # weights_only=True: these are plain state_dict tensors; never
            # execute pickle payloads from model files. map_location="cpu"
            # keeps GPU-trained checkpoints loadable on CPU-only hosts.
            model.load_state_dict(torch.load(lstm_path, map_location="cpu", weights_only=True))
            model.eval()
            return model
        except Exception as exc:
            logger.error(f"Error loading LSTM model: {exc}")
            return None

    def _load_autoencoder(self) -> Optional[FeatureAutoencoder]:
        ae_path = Path(AUTOENCODER_PATH)
        if not ae_path.exists():
            logger.warning("Autoencoder model file missing. Layer 3 Autoencoder set to fallback.")
            return None
        try:
            model = FeatureAutoencoder(input_dim=17, bottleneck_dim=6)
            model.load_state_dict(torch.load(ae_path, map_location="cpu", weights_only=True))
            model.eval()
            return model
        except Exception as exc:
            logger.error(f"Error loading Autoencoder model: {exc}")
            return None

    def _load_scaler(self) -> Optional[Any]:
        scaler_path = self.models_dir / "autoencoder_scaler.pkl"
        if scaler_path.exists():
            return joblib.load(scaler_path)
        return None

    def _load_threshold(self) -> float:
        thresh_path = self.models_dir / "autoencoder_threshold.txt"
        if thresh_path.exists():
            try:
                with open(thresh_path, "r") as f:
                    return float(f.read().strip())
            except Exception:
                pass
        return 1.0

    def analyze(self, raw_payload: str, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes Layer 3 LSTM and Autoencoder inference.
        Returns points breakdown:
          - LSTM points: 0 to 30
          - Autoencoder points: 0 to 20
        """
        # 1. LSTM Inference
        lstm_prob = 0.0
        if self.lstm_model is not None and raw_payload:
            seq = encode_text(raw_payload, self.vocab)[:100]
            padded = seq + [0] * (100 - len(seq))
            inp_tensor = torch.tensor([padded], dtype=torch.long)
            with torch.no_grad():
                lstm_prob = float(self.lstm_model(inp_tensor).item())

        lstm_points = min(round(lstm_prob * 15.0, 2), 15.0)

        # 2. Autoencoder Inference
        ae_error = 0.0
        ae_score_norm = 0.0
        if self.autoencoder is not None:
            if "feature_vector" in feature_dict and len(feature_dict["feature_vector"]) == len(self.FEATURE_KEYS):
                raw_vec = np.array(feature_dict["feature_vector"]).reshape(1, -1)
            else:
                raw_vec = np.array([feature_dict.get(k, 0) for k in self.FEATURE_KEYS]).reshape(1, -1)

            if self.scaler is not None:
                scaled_vec = self.scaler.transform(raw_vec)
            else:
                scaled_vec = raw_vec

            inp_ae = torch.tensor(scaled_vec, dtype=torch.float32)
            with torch.no_grad():
                reconstructed = self.autoencoder(inp_ae)
                ae_error = float(torch.mean((inp_ae - reconstructed) ** 2).item())

            # Normalize error relative to 95th percentile threshold
            if self.ae_threshold > 0:
                ae_score_norm = float(np.clip(ae_error / (self.ae_threshold * 2.0), 0.0, 1.0))
            else:
                ae_score_norm = float(np.clip(ae_error, 0.0, 1.0))

        ae_points = min(round(ae_score_norm * 20.0, 2), 20.0)

        return {
            "lstm_probability": round(lstm_prob, 4),
            "lstm_points": lstm_points,
            "autoencoder_error": round(ae_error, 4),
            "autoencoder_threshold": self.ae_threshold,
            "autoencoder_points": ae_points,
            "total_layer3_points": round(lstm_points + ae_points, 2)
        }


if __name__ == "__main__":
    detector = DeepLearningDetector()
    sample_payload = "' UNION SELECT NULL, password FROM users --"
    sample_features = {
        "encoded_method": 2, "path_depth": 3, "url_length": 60,
        "query_param_count": 2, "query_string_length": 30, "payload_length": 45,
        "payload_entropy": 5.8, "special_char_count": 12, "header_count": 6,
        "auth_header_present": 0, "status_code": 200, "response_size": 1024
    }
    res = detector.analyze(sample_payload, sample_features)
    print("\n[+] Layer 3 Deep Learning Test Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
