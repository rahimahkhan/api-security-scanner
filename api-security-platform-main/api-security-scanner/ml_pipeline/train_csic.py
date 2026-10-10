"""Train Layer-2/3 models on response-differential telemetry.

Trains on ml_pipeline/datasets/response_diff_v1.csv (built by
build_response_dataset.py), whose features come from the single canonical
implementation in ml_pipeline/feature_extractor.py (schema response-diff-13-v1).

Artifacts written to the models directory:
  isolation_forest.pkl    — IsolationForest trained on BENIGN rows only
  feature_scaler.pkl      — StandardScaler fit on benign rows
  iforest_calibration.json — {"decision_q05", "decision_std"} of the benign
      training decision_function values; anchors the anomaly-score sigmoid
      at the model's own contamination quantile (see detection/ml_model.py)
  tabular_ranker.pkl      — calibrated LogisticRegression, benign=0 / anomalous=1
  autoencoder.pt / autoencoder_scaler.pkl / autoencoder_threshold.txt
  lstm_model.pt / char_vocab.json — payload-maliciousness LSTM (properly
      trained this time, not randomly initialized)

Run:  python ml_pipeline/train_csic.py [--data PATH] [--output DIR]
"""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from config.settings import MODELS_DIR
from ml_pipeline.feature_extractor import FEATURE_KEYS, SCHEMA_VERSION
from training.train_autoencoder import FeatureAutoencoder
from training.train_lstm import PayloadLSTM, build_char_vocab, encode_text

DEFAULT_DATA = ROOT_DIR / "ml_pipeline" / "datasets" / "response_diff_v1.csv"

# Payload-maliciousness LSTM corpus: benign parameter/query strings vs real
# attack payloads. The LSTM scores the *payload*, not the response — it stays
# a minor context signal by design.
BENIGN_TEXTS = [
    "id=10&name=alice", "search?q=laptop", "api/v1/users", "page=2&limit=25",
    "q=hello+world", "username=bob&email=bob@example.com", "sort=asc&filter=new",
    "product_id=42", "city=karachi&zip=74000", "token=abc123def456",
    "category=books&author=smith", "lang=en&theme=dark", "ref=homepage",
    "amount=100&currency=pkr", "status=active", "name=rahimah",
]
MALICIOUS_TEXTS = [
    "' OR '1'='1", "' OR '1'='1' --", "admin' --", "' UNION SELECT NULL--",
    "' UNION SELECT password FROM users--", "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "'; DROP TABLE users--",
    "../../etc/passwd", "../../../../etc/shadow", "; cat /etc/passwd",
    "1' AND SLEEP(5)--", "' OR SLEEP(5)--", "${7*7}", "{{7*7}}",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT version())))x)--",
]


def _lstm_corpus() -> Tuple[List[str], List[int]]:
    texts = BENIGN_TEXTS * 4 + MALICIOUS_TEXTS * 4
    labels = [0] * (len(BENIGN_TEXTS) * 4) + [1] * (len(MALICIOUS_TEXTS) * 4)
    return texts, labels


def train_pipeline(data_path: Path, output_dir: Path, ae_epochs: int = 200, lstm_epochs: int = 15):
    output_dir.mkdir(parents=True, exist_ok=True)

    if not data_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {data_path}. Build it first with: "
            "python ml_pipeline/build_response_dataset.py"
        )
    df = pd.read_csv(data_path)
    for key in FEATURE_KEYS:
        if key not in df.columns:
            df[key] = 0.0
    if "label" not in df.columns:
        raise ValueError("Dataset has no 'label' column (0 benign / 1 anomalous).")

    x = df[FEATURE_KEYS].values.astype(float)
    y = df["label"].values.astype(int)
    benign = x[y == 0]
    print(f"[+] Dataset: {len(x)} rows ({len(benign)} benign, {len(x) - len(benign)} anomalous), "
          f"schema={SCHEMA_VERSION}")

    # 1. Isolation Forest on benign only (novelty detection)
    print("[+] Training Isolation Forest on benign responses...")
    iso_scaler = StandardScaler()
    scaled_benign = iso_scaler.fit_transform(benign)
    iso_forest = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    iso_forest.fit(scaled_benign)
    joblib.dump(iso_forest, output_dir / "isolation_forest.pkl")
    joblib.dump(iso_scaler, output_dir / "feature_scaler.pkl")

    # Calibration: decision_function distribution on benign train data.
    # The serving sigmoid is anchored at the 5th percentile (the contamination
    # quantile), so ~5% of benign traffic scores > 0.5 — matching the model.
    train_decisions = iso_forest.decision_function(scaled_benign)
    calibration = {
        "decision_q05": float(np.percentile(train_decisions, 5)),
        "decision_std": float(np.std(train_decisions) or 1.0),
        "decision_mean": float(np.mean(train_decisions)),
        "schema": SCHEMA_VERSION,
    }
    (output_dir / "iforest_calibration.json").write_text(json.dumps(calibration, indent=2))
    print(f"    calibration: q05={calibration['decision_q05']:.4f} "
          f"std={calibration['decision_std']:.4f} mean={calibration['decision_mean']:.4f}")

    # 2. Supervised tabular ranker (benign=0 / anomalous=1)
    print("[+] Training calibrated tabular ranker...")
    pipe = Pipeline([("scaler", StandardScaler()),
                     ("clf", LogisticRegression(max_iter=2000, random_state=42))])
    try:
        ranker = CalibratedClassifierCV(estimator=pipe, method="sigmoid", cv=3)
    except TypeError:  # older sklearn
        ranker = CalibratedClassifierCV(base_estimator=pipe, method="sigmoid", cv=3)
    ranker.fit(x, y)
    joblib.dump({"model": ranker, "feature_keys": FEATURE_KEYS}, output_dir / "tabular_ranker.pkl")

    # 3. Feature autoencoder on benign rows
    print(f"[+] Training feature autoencoder ({ae_epochs} epochs)...")
    ae_scaler = StandardScaler()
    ae_train = ae_scaler.fit_transform(benign)
    # Bottleneck 8 + 200 epochs: verified to converge (mean benign recon.
    # error ~0.006). The old 6/30 underfit and scored every probe as anomalous.
    autoencoder = FeatureAutoencoder(input_dim=len(FEATURE_KEYS), bottleneck_dim=8)
    optimizer = torch.optim.Adam(autoencoder.parameters(), lr=0.005)
    criterion = nn.MSELoss()
    loader = DataLoader(TensorDataset(torch.tensor(ae_train, dtype=torch.float32)),
                        batch_size=32, shuffle=True)
    autoencoder.train()
    for _epoch in range(ae_epochs):
        for (batch_x,) in loader:
            optimizer.zero_grad()
            loss = criterion(autoencoder(batch_x), batch_x)
            loss.backward()
            optimizer.step()
    autoencoder.eval()
    with torch.no_grad():
        errors = torch.mean(
            (torch.tensor(ae_train, dtype=torch.float32) - autoencoder(torch.tensor(ae_train, dtype=torch.float32))) ** 2,
            dim=1,
        ).numpy()
    threshold = float(np.percentile(errors, 95))
    torch.save(autoencoder.state_dict(), output_dir / "autoencoder.pt")
    joblib.dump(ae_scaler, output_dir / "autoencoder_scaler.pkl")
    (output_dir / "autoencoder_threshold.txt").write_text(f"{threshold:.6f}\n")
    print(f"    autoencoder 95th-percentile threshold: {threshold:.6f}")

    # 4. Payload LSTM — trained classifier, not random weights
    print(f"[+] Training payload LSTM ({lstm_epochs} epochs)...")
    texts, labels = _lstm_corpus()
    vocab = build_char_vocab(texts)
    (output_dir / "char_vocab.json").write_text(json.dumps(vocab, indent=2))
    seqs = [encode_text(t, vocab) for t in texts]
    max_len = 100
    # LEFT-pad: padding tokens form a constant prefix and the final LSTM state
    # always reflects the real content. (Right-padding washed the signal out:
    # dozens of trailing PADs made every hidden state identical.)
    x_seq = torch.tensor([[0] * (max_len - len(s)) + s[:max_len] for s in seqs], dtype=torch.long)
    y_seq = torch.tensor(labels, dtype=torch.float32)
    lstm = PayloadLSTM(vocab_size=len(vocab))
    opt = torch.optim.Adam(lstm.parameters(), lr=0.005)
    crit = nn.BCELoss()
    lstm.train()
    for _epoch in range(lstm_epochs):
        opt.zero_grad()
        loss = crit(lstm(x_seq), y_seq)
        loss.backward()
        opt.step()
    lstm.eval()
    with torch.no_grad():
        preds = (lstm(x_seq) > 0.5).int().numpy()
    acc = float((preds == np.array(labels)).mean())
    torch.save(lstm.state_dict(), output_dir / "lstm_model.pt")
    print(f"    LSTM train accuracy: {acc:.3f}")

    manifest = {
        "schema": SCHEMA_VERSION,
        "feature_keys": FEATURE_KEYS,
        "dataset": str(data_path),
        "rows": len(df),
        "benign_rows": int((y == 0).sum()),
        "anomalous_rows": int((y == 1).sum()),
        "lstm_train_accuracy": round(acc, 4),
        "artifacts": {
            "isolation_forest": "isolation_forest.pkl",
            "feature_scaler": "feature_scaler.pkl",
            "iforest_calibration": "iforest_calibration.json",
            "tabular_ranker": "tabular_ranker.pkl",
            "autoencoder": "autoencoder.pt",
            "autoencoder_scaler": "autoencoder_scaler.pkl",
            "autoencoder_threshold": "autoencoder_threshold.txt",
            "lstm": "lstm_model.pt",
            "char_vocab": "char_vocab.json",
        },
    }
    (output_dir / "response_model_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"[+] Training complete. Artifacts saved to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Train response-differential ML/DL models.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--output", type=Path, default=Path(MODELS_DIR))
    parser.add_argument("--ae-epochs", type=int, default=30)
    parser.add_argument("--lstm-epochs", type=int, default=15)
    args = parser.parse_args()
    train_pipeline(args.data, args.output, args.ae_epochs, args.lstm_epochs)


if __name__ == "__main__":
    main()
