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
from config.settings import MODELS_DIR, RESPONSE_LSTM_PATH, AUTOENCODER_PATH
# Canonical feature schema — the single source of truth, shared with training
# (ml_pipeline/feature_extractor.py). The autoencoder is retrained on this
# schema; its input_dim follows FEATURE_KEYS instead of a hardcoded 17.
from ml_pipeline.feature_extractor import FEATURE_KEYS
from training.train_lstm import PayloadLSTM, encode_text
from training.train_autoencoder import FeatureAutoencoder

class DeepLearningDetector:
    """
    Layer 3 — Deep Learning Detection Engine
    Integrates a character-level LSTM trained on real TARGET RESPONSE
    BODIES (exploit-effect responses vs normal responses — see
    ml_pipeline/train_response_lstm.py) and a PyTorch Autoencoder
    (reconstruction error over the canonical response-differential
    features). Both models measure the target's behavior, never our own
    payload text.
    """

    FEATURE_KEYS = FEATURE_KEYS
    LSTM_MAX_LEN = 512  # must match ml_pipeline/train_response_lstm.py

    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else Path(MODELS_DIR)

        self.lstm_model = self._load_lstm()
        self.vocab = self._load_vocab()

        self.autoencoder = self._load_autoencoder()
        self.scaler = self._load_scaler()
        self.ae_threshold = self._load_threshold()

    def _load_vocab(self) -> Dict[str, int]:
        vocab_path = self.models_dir / "response_char_vocab.json"
        if vocab_path.exists():
            with open(vocab_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"<PAD>": 0, "<UNK>": 1}

    def _load_lstm(self) -> Optional[PayloadLSTM]:
        lstm_path = Path(RESPONSE_LSTM_PATH)
        vocab_path = self.models_dir / "response_char_vocab.json"
        if not lstm_path.exists() or not vocab_path.exists():
            logger.warning("Response LSTM model file or character vocab missing. Layer 3 LSTM set to fallback.")
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
            state = torch.load(ae_path, map_location="cpu", weights_only=True)
            # Derive the architecture from the checkpoint itself instead of
            # hardcoding it: a hardcoded bottleneck_dim=6 silently rejected
            # the bottleneck-8 production checkpoint, leaving the
            # autoencoder dead (None) on every scan. The checkpoint is the
            # single source of truth for its own shape.
            input_dim = int(state["encoder.0.weight"].shape[1])
            bottleneck_dim = int(state["encoder.2.weight"].shape[0])
            if input_dim != len(FEATURE_KEYS):
                logger.error(
                    f"Autoencoder checkpoint expects {input_dim} features but the "
                    f"serving schema has {len(FEATURE_KEYS)}. Retrain the model on "
                    "the current schema; Layer 3 Autoencoder disabled."
                )
                return None
            model = FeatureAutoencoder(input_dim=input_dim, bottleneck_dim=bottleneck_dim)
            model.load_state_dict(state)
            model.eval()
            logger.info(
                f"Autoencoder loaded (input_dim={input_dim}, bottleneck_dim={bottleneck_dim})."
            )
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

    def _ae_error(self, feature_dict: Dict[str, Any]) -> float:
        """Reconstruction error of one response-feature vector (0.0 when the
        autoencoder is unavailable)."""
        if self.autoencoder is None:
            return 0.0
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
            return float(torch.mean((inp_ae - reconstructed) ** 2).item())

    def analyze(self, response_body: str, feature_dict: Dict[str, Any],
                baseline_feature_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Layer 3 LSTM and Autoencoder inference on the TARGET'S
        RESPONSE. Returns points breakdown:
          - LSTM points: 0 to 15 (response-body anomaly signal)
          - Autoencoder points: 0 to 20 (response-feature anomaly signal)

        When baseline_feature_dict is given, the autoencoder scores the
        EXCESS error of the probe over the target's own baseline response.
        The autoencoder's absolute error is domain-sensitive: an app whose
        normal responses differ from the training services (different page
        sizes, timing, field mix) reconstructs poorly even when a probe
        changes nothing — an identical response scored error 0.10 vs the
        0.026 training threshold on an unseen app. Scoring the excess over
        the app's own baseline cancels that shift: a probe that changes
        nothing earns 0, and only genuine deviations earn points.
        """
        # 1. Response-body LSTM Inference
        # The LSTM is trained on real response bodies (exploit-effect vs
        # normal), so its probability is evidence about the TARGET: a
        # response that looks like a SQL error page, a sensitive data dump,
        # or an unescaped reflection scores high; a normal response scores
        # low — regardless of what payload we sent. (The previous payload-
        # text LSTM could only describe our own input and earned 0 points;
        # it was replaced by this model.) Left-pad to match training.
        lstm_prob = 0.0
        if self.lstm_model is not None and response_body:
            seq = encode_text(response_body[:self.LSTM_MAX_LEN], self.vocab)
            padded = [0] * (self.LSTM_MAX_LEN - len(seq)) + seq
            inp_tensor = torch.tensor([padded], dtype=torch.long)
            with torch.no_grad():
                lstm_prob = float(self.lstm_model(inp_tensor).item())

        lstm_points = min(round(lstm_prob * 15.0, 2), 15.0)

        # 2. Autoencoder Inference
        ae_error = self._ae_error(feature_dict) if self.autoencoder is not None else 0.0
        ae_baseline_error = None
        if baseline_feature_dict is not None and self.autoencoder is not None:
            ae_baseline_error = self._ae_error(baseline_feature_dict)
            scored_error = max(0.0, ae_error - ae_baseline_error)
        else:
            scored_error = ae_error

        # Normalize the scored error relative to the 95th-percentile
        # benign threshold from training (2x threshold = full points).
        if self.ae_threshold > 0:
            ae_score_norm = float(np.clip(scored_error / (self.ae_threshold * 2.0), 0.0, 1.0))
        else:
            ae_score_norm = float(np.clip(scored_error, 0.0, 1.0))

        ae_points = min(round(ae_score_norm * 20.0, 2), 20.0)

        return {
            "lstm_probability": round(lstm_prob, 4),
            "lstm_points": lstm_points,
            "autoencoder_error": round(ae_error, 4),
            "autoencoder_baseline_error": (round(ae_baseline_error, 4)
                                           if ae_baseline_error is not None else None),
            "autoencoder_threshold": self.ae_threshold,
            "autoencoder_points": ae_points,
            "total_layer3_points": round(lstm_points + ae_points, 2)
        }


if __name__ == "__main__":
    detector = DeepLearningDetector()
    # The target's response to a probe: a real SQL error page body.
    sample_body = ("Warning: mysql_fetch_array() expects parameter 1 to be resource, "
                   "boolean given. You have an error in your SQL syntax near "
                   "'' OR 1=1 --''")
    # Response-differential features: SQL error page vs clean baseline.
    sample_features = {
        "status_changed": 1, "size_delta_ratio": -0.85, "time_delta_ratio": 0.2,
        "body_diff_ratio": 0.9, "content_type_changed": 1, "error_keyword_delta": 3,
        "payload_reflected": 0, "status_class": 5, "response_size_log": 1.8,
        "response_time_s": 0.15, "error_keyword_count": 3, "sensitive_field_count": 0,
        "payload_length_log": 1.6, "encoded_method": 2,
    }
    res = detector.analyze(sample_body, sample_features)
    print("\n[+] Layer 3 Deep Learning Test Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
