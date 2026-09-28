"""Isolated CSIC ML and DL inference script for request-side anomaly scoring."""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import numpy as np
import joblib
import torch
import torch.nn as nn

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from ml_pipeline.feature_extractor import extract_features_from_request, FEATURE_KEYS


class FeatureAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 17, hidden_dim: int = 10, bottleneck_dim: int = 6):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, bottleneck_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class PayloadLSTM(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int = 32, hidden_dim: int = 64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(x)
        _, (hn, _) = self.lstm(embedded)
        out = self.fc(hn[-1])
        return self.sigmoid(out)


def encode_text_vocab(text: str, vocab: Dict[str, int], max_len: int = 100) -> torch.Tensor:
    indices = [vocab.get(char, vocab.get("<UNK>", 1)) for char in str(text)[:max_len]]
    if len(indices) < max_len:
        indices += [vocab.get("<PAD>", 0)] * (max_len - len(indices))
    return torch.tensor([indices], dtype=torch.long)


class CSICModelBundle:
    def __init__(self, bundle_dir: Path):
        self.bundle_dir = bundle_dir
        self.ranker = self._load_ranker()
        self.iso_forest, self.iso_scaler = self._load_isolation_forest()
        self.autoencoder, self.ae_scaler, self.ae_threshold = self._load_autoencoder()
        self.lstm, self.char_vocab = self._load_lstm()

    def _load_ranker(self):
        ranker_path = self.bundle_dir / "tabular_ranker.pkl"
        if not ranker_path.exists():
            return None
        try:
            artifact = joblib.load(ranker_path)
            return artifact.get("model") if isinstance(artifact, dict) else artifact
        except Exception:
            return None

    def _load_isolation_forest(self):
        iso_path = self.bundle_dir / "isolation_forest.pkl"
        scaler_path = self.bundle_dir / "feature_scaler.pkl"
        iso_model, scaler = None, None
        if iso_path.exists():
            try:
                iso_model = joblib.load(iso_path)
            except Exception:
                pass
        if scaler_path.exists():
            try:
                scaler = joblib.load(scaler_path)
            except Exception:
                pass
        return iso_model, scaler

    def _load_autoencoder(self):
        ae_path = self.bundle_dir / "autoencoder.pt"
        scaler_path = self.bundle_dir / "autoencoder_scaler.pkl"
        thresh_path = self.bundle_dir / "autoencoder_threshold.txt"
        ae_model, scaler, threshold = None, None, 1.0

        if thresh_path.exists():
            try:
                threshold = float(thresh_path.read_text().strip())
            except Exception:
                threshold = 1.0

        if scaler_path.exists():
            try:
                scaler = joblib.load(scaler_path)
            except Exception:
                pass

        if ae_path.exists():
            try:
                model = FeatureAutoencoder(input_dim=len(FEATURE_KEYS))
                model.load_state_dict(torch.load(ae_path, map_location=torch.device("cpu"), weights_only=True))
                model.eval()
                ae_model = model
            except Exception:
                try:
                    model = FeatureAutoencoder(input_dim=len(FEATURE_KEYS))
                    model.load_state_dict(torch.load(ae_path, map_location=torch.device("cpu"), weights_only=False))
                    model.eval()
                    ae_model = model
                except Exception:
                    pass

        return ae_model, scaler, threshold

    def _load_lstm(self):
        lstm_path = self.bundle_dir / "lstm_model.pt"
        vocab_path = self.bundle_dir / "char_vocab.json"
        lstm_model, vocab = None, {"<PAD>": 0, "<UNK>": 1}

        if vocab_path.exists():
            try:
                vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        if lstm_path.exists():
            try:
                model = PayloadLSTM(vocab_size=max(len(vocab), 2))
                model.load_state_dict(torch.load(lstm_path, map_location=torch.device("cpu"), weights_only=True))
                model.eval()
                lstm_model = model
            except Exception:
                try:
                    model = PayloadLSTM(vocab_size=max(len(vocab), 2))
                    model.load_state_dict(torch.load(lstm_path, map_location=torch.device("cpu"), weights_only=False))
                    model.eval()
                    lstm_model = model
                except Exception:
                    pass

        return lstm_model, vocab

    def infer(self, req_data: Dict[str, Any]) -> Dict[str, Any]:
        features_dict = extract_features_from_request(req_data)
        feature_vector = np.array([[features_dict[k] for k in FEATURE_KEYS]], dtype=float)

        # 1. Supervised Probability (Calibrated Tabular Ranker)
        supervised_prob = 0.0
        if self.ranker is not None:
            try:
                prob = float(self.ranker.predict_proba(feature_vector)[0][1])
                supervised_prob = round(float(np.clip(prob, 0.0, 1.0)), 4)
            except Exception:
                pass

        # 2. Isolation Forest Novelty Score
        iso_score = 0.0
        if self.iso_model is not None:
            try:
                scaled_vec = self.iso_scaler.transform(feature_vector) if self.iso_scaler else feature_vector
                raw_score = float(self.iso_model.decision_function(scaled_vec)[0])
                # Lower decision function means higher anomaly
                iso_score = round(float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0)), 4)
            except Exception:
                pass

        # 3. Autoencoder Reconstruction Error & Score
        ae_recon_error = 0.0
        ae_score = 0.0
        if self.autoencoder is not None:
            try:
                scaled_vec = self.ae_scaler.transform(feature_vector) if self.ae_scaler else feature_vector
                tensor_x = torch.tensor(scaled_vec, dtype=torch.float32)
                with torch.no_grad():
                    reconstructed = self.autoencoder(tensor_x)
                    loss = torch.mean((tensor_x - reconstructed) ** 2).item()
                ae_recon_error = round(float(loss), 4)
                ae_score = round(float(min(loss / max(self.ae_threshold, 1e-6), 1.0)), 4)
            except Exception:
                pass

        # 4. Character LSTM Payload Probability
        # Feed the model exactly what it was trained on: the request content,
        # falling back to the URL query string (never the full URL). Requests
        # with neither carry no payload signal -> 0.0, not a false positive.
        lstm_prob = 0.0
        payload_text = str(req_data.get("content") if req_data.get("content") is not None else (req_data.get("payload") or ""))
        if not payload_text.strip():
            url_txt = str(req_data.get("URL") or req_data.get("url") or "")
            payload_text = url_txt.split("?", 1)[1].split(" HTTP")[0] if "?" in url_txt else ""
        payload_text = payload_text.strip()[:500]
        if self.lstm is not None and payload_text:
            try:
                encoded = encode_text_vocab(payload_text, self.char_vocab)
                with torch.no_grad():
                    lstm_out = self.lstm(encoded).item()
                lstm_prob = round(float(np.clip(lstm_out, 0.0, 1.0)), 4)
            except Exception:
                pass

        return {
            "supervised_probability": supervised_prob,
            "isolation_forest_novelty_score": iso_score,
            "autoencoder_reconstruction_error": ae_recon_error,
            "autoencoder_score": ae_score,
            "lstm_payload_probability": lstm_prob,
            "confirmation": "not_confirmed_model_signal_only",
            "response_telemetry_available": bool(req_data.get("status_code", 0) > 0),
        }

    @property
    def iso_model(self):
        return self.iso_forest


def run_inference(bundle_path: Path, input_json_path: Path, output_json_path: Optional[Path] = None) -> Dict[str, Any]:
    if not input_json_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_json_path}")

    with open(input_json_path, "r", encoding="utf-8") as f:
        req_data = json.load(f)

    bundle = CSICModelBundle(bundle_path)
    result = bundle.infer(req_data)

    formatted_json = json.dumps(result, indent=2)
    print(formatted_json)

    if output_json_path:
        output_json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_json_path, "w", encoding="utf-8") as f:
            f.write(formatted_json + "\n")

    return result


def main():
    parser = argparse.ArgumentParser(description="Run isolated CSIC ML and DL inference on an API request JSON record.")
    parser.add_argument(
        "--bundle",
        type=Path,
        default=ROOT_DIR / "models",
        help="Path to trained CSIC model artifact bundle directory.",
    )
    parser.add_argument(
        "--input-json",
        type=Path,
        required=True,
        help="Path to input JSON file containing request-side fields.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional path to write inference results.",
    )

    args = parser.parse_args()
    run_inference(args.bundle, args.input_json, args.output_json)


if __name__ == "__main__":
    main()
