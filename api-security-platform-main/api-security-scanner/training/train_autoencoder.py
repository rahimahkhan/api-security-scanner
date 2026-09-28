import os
import sys
from pathlib import Path
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import DATASETS_DIR, MODELS_DIR

FEATURE_COLUMNS = [
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

class FeatureAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 17, bottleneck_dim: int = 6):
        super(FeatureAutoencoder, self).__init__()
        # Encoder: 17 -> 10 -> 6
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 10),
            nn.ReLU(),
            nn.Linear(10, bottleneck_dim),
            nn.ReLU()
        )
        # Decoder: 6 -> 10 -> 17
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, 10),
            nn.ReLU(),
            nn.Linear(10, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


def train_autoencoder():
    logger.info("Starting Layer 3 Autoencoder reconstruction model training...")
    processed_dir = Path(DATASETS_DIR) / "processed"
    # NOTE: train on RAW features from features.csv, not the pre-scaled train.csv.
    # Fitting the scaler on already-standardized data yields a near-identity
    # scaler, so inference-time raw features would enter the model unscaled and
    # reconstruction error would explode. See models/metrics history.
    raw_features_path = processed_dir / "features.csv"

    if not raw_features_path.exists():
        logger.error(f"Raw features file not found at {raw_features_path}. Run training/prepare_dataset.py first.")
        print(f"[!] Missing features.csv dataset in {processed_dir}")
        return

    df = pd.read_csv(raw_features_path).fillna(0.0)

    # Filter normal traffic only (label == 0)
    normal_df = df[df["label"] == 0]
    X_normal = normal_df[FEATURE_COLUMNS].values

    # Scale RAW features; this scaler is what inference applies to raw requests.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)

    # Save scaler for inference
    scaler_path = Path(MODELS_DIR) / "autoencoder_scaler.pkl"
    joblib.dump(scaler, scaler_path)

    tensor_x = torch.tensor(X_scaled, dtype=torch.float32)
    dataset = TensorDataset(tensor_x)
    loader = DataLoader(dataset, batch_size=32, shuffle=True)

    model = FeatureAutoencoder(input_dim=17, bottleneck_dim=6)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005)

    epochs = 20
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0
        for (batch_x,) in loader:
            optimizer.zero_grad()
            reconstructed = model(batch_x)
            loss = criterion(reconstructed, batch_x)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

    # Compute reconstruction errors on normal training set to set 95th percentile threshold
    model.eval()
    with torch.no_grad():
        reconstructed_x = model(tensor_x)
        errors = torch.mean((tensor_x - reconstructed_x) ** 2, dim=1).numpy()

    threshold_95 = float(np.percentile(errors, 95))

    print("\n" + "="*50)
    print(" LAYER 3: AUTOENCODER MODEL SUMMARY")
    print("="*50)
    print(f" Normal Training Samples  : {len(normal_df)}")
    print(f" Mean Reconstruction Error: {np.mean(errors):.4f}")
    print(f" 95th Percentile Threshold: {threshold_95:.4f}")
    print("="*50)

    # Save model weights & threshold text file
    os.makedirs(MODELS_DIR, exist_ok=True)
    model_output_path = Path(MODELS_DIR) / "autoencoder.pt"
    threshold_output_path = Path(MODELS_DIR) / "autoencoder_threshold.txt"

    torch.save(model.state_dict(), model_output_path)
    with open(threshold_output_path, "w") as f:
        f.write(str(threshold_95))

    logger.info(f"Saved Autoencoder weights to {model_output_path} and threshold to {threshold_output_path}")
    print(f"\n[+] Autoencoder model saved to: {model_output_path}")
    print(f"[+] Reconstruction threshold saved to: {threshold_output_path}\n")


if __name__ == "__main__":
    train_autoencoder()
