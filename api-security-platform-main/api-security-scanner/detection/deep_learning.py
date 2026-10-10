import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import torch
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.numpy_compat import ensure_numpy2_pickle_compat  # noqa: E402  (applies NumPy 2.x pickle shim)

ensure_numpy2_pickle_compat()

from config.logging_config import logger
from config.settings import MODELS_DIR, LSTM_MODEL_PATH, AUTOENCODER_PATH
# Canonical feature schema — the single source of truth, shared with training
# (ml_pipeline/feature_extractor.py). The autoencoder is retrained on this
# schema; its input_dim follows FEATURE_KEYS instead of a hardcoded 17.
from ml_pipeline.feature_extractor import FEATURE_KEYS
from training.train_lstm import PayloadLSTM, encode_text
from training.train_autoencoder import FeatureAutoencoder

class DeepLearningDetector:
    """
    Layer 3 — Deep Learning Detection Engine
    Integrates character-level LSTM (malicious payload probability — a payload
    signal, kept as minor context by design) and PyTorch Autoencoder
    (reconstruction error over the canonical response-differential features).
    """

    FEATURE_KEYS = FEATURE_KEYS

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
            model = FeatureAutoencoder(input_dim=len(FEATURE_KEYS), bottleneck_dim=6)
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
        # Left-pad to match training: padding is a constant prefix so the
        # final LSTM state reflects the real payload content.
        lstm_prob = 0.0
        if self.lstm_model is not None and raw_payload:
            seq = encode_text(raw_payload, self.vocab)[:100]
            padded = [0] * (100 - len(seq)) + seq
            inp_tensor = torch.tensor([padded], dtype=torch.long)
            with torch.no_grad():
                lstm_prob = float(self.lstm_model(inp_tensor).item())

        # The LSTM classifies PAYLOAD text ("is this string attack-like"), not
        # target behavior. The scanner already knows what payload it sent, so
        # this adds zero information about the target's vulnerability — and
        # awarding points for it inflated EVERY probe (we always send attack
        # payloads). lstm_points is therefore always 0 in scoring; the raw
        # probability is kept as telemetry (what kind of payload was sent).
        # The autoencoder below is the honest DL signal: it measures whether
        # the RESPONSE's feature vector looks anomalous.
        lstm_points = 0.0

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
    # Response-differential features: SQL error page vs clean baseline.
    sample_features = {
        "status_changed": 1, "size_delta_ratio": -0.85, "time_delta_ratio": 0.2,
        "body_diff_ratio": 0.9, "content_type_changed": 1, "error_keyword_delta": 3,
        "payload_reflected": 0, "status_class": 5, "response_size_log": 1.8,
        "response_time_s": 0.15, "error_keyword_count": 3, "sensitive_field_count": 0,
        "payload_length_log": 1.6, "encoded_method": 2,
    }
    res = detector.analyze(sample_payload, sample_features)
    print("\n[+] Layer 3 Deep Learning Test Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
