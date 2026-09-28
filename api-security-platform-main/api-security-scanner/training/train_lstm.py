import os
import sys
import json
import random
from pathlib import Path
from typing import List, Tuple, Dict
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import PAYLOADS_DIR, MODELS_DIR

# --- Dataset and Model Definitions ---

class SequenceDataset(Dataset):
    def __init__(self, sequences: List[List[int]], labels: List[int], max_len: int = 100):
        self.sequences = sequences
        self.labels = labels
        self.max_len = max_len

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        seq = self.sequences[idx][:self.max_len]
        padded = seq + [0] * (self.max_len - len(seq))
        return torch.tensor(padded, dtype=torch.long), torch.tensor(self.labels[idx], dtype=torch.float32)


class PayloadLSTM(nn.Module):
    def __init__(self, vocab_size: int, embedding_dim: int = 32, hidden_dim: int = 64):
        super(PayloadLSTM, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        embedded = self.embedding(x)
        _, (hn, _) = self.lstm(embedded)
        output = self.fc(hn[-1])
        return self.sigmoid(output).squeeze(-1)


# --- Vocabulary Builder ---

def build_char_vocab(payload_texts: List[str]) -> Dict[str, int]:
    vocab = {"<PAD>": 0, "<UNK>": 1}
    for text in payload_texts:
        for char in text:
            if char not in vocab:
                vocab[char] = len(vocab)
    return vocab


def encode_text(text: str, vocab: Dict[str, int]) -> List[int]:
    return [vocab.get(char, vocab["<UNK>"]) for char in text]


# --- Training Script ---

def load_csic_texts(csv_path: Path, max_per_class: int = 30000) -> Tuple[List[str], List[int]]:
    """Load (payload_text, label) pairs from the raw CSIC 2010 CSV.

    Prefers the ``content`` column, falling back to the URL query string.
    Returns balanced-ish samples capped at ``max_per_class`` per class.
    """
    import pandas as pd

    df = pd.read_csv(csv_path, usecols=lambda c: c in {"content", "URL", "classification"},
                     dtype=str, keep_default_na=False)
    texts: List[str] = []
    labels: List[int] = []
    counts = {0: 0, 1: 0}
    for _, row in df.iterrows():
        try:
            label = int(float(row.get("classification", "0") or "0"))
        except ValueError:
            continue
        if label not in (0, 1) or counts[label] >= max_per_class:
            continue
        content = (row.get("content") or "").strip()
        if not content:
            url = row.get("URL") or ""
            content = url.split("?", 1)[1].split(" HTTP")[0] if "?" in url else ""
        content = content.strip()
        if not content:
            continue
        texts.append(content[:500])
        labels.append(label)
        counts[label] += 1
    logger.info(f"Loaded {len(texts)} CSIC texts (normal={counts[0]}, attack={counts[1]})")
    return texts, labels


def train_lstm_model():
    logger.info("Starting Layer 3 LSTM model training...")
    os.makedirs(MODELS_DIR, exist_ok=True)
    payloads_dir = Path(PAYLOADS_DIR)

    texts: List[str] = []
    labels: List[int] = []

    # Primary: CSIC 2010 request payloads (tens of thousands of real samples).
    csic_csv = Path(__file__).resolve().parent.parent / "datasets" / "raw" / "csic_2010" / "csic_database.csv"
    if csic_csv.exists():
        try:
            texts, labels = load_csic_texts(csic_csv)
        except Exception as exc:
            logger.warning(f"Could not load CSIC texts ({exc}); falling back to payload files.")

    # Augment with hand-written payload files (attack samples).
    malicious_texts = []
    for file_name in ["sqli.txt", "xss.txt", "cmd_injection.txt", "bola.txt", "auth.txt"]:
        fpath = payloads_dir / file_name
        if fpath.exists():
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_clean = line.strip()
                    if line_clean and not line_clean.startswith("#"):
                        malicious_texts.append(line_clean)

    # Additional high-risk attack vectors
    additional_malicious = [
        # Encoded payloads
        "%27%20OR%201%3D1--",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "&#x27;OR&#x20;1=1--",
        "\\x27 OR 1=1--",
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1#",
        "') OR ('1'='1",
        # Path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2f",
        "....//....//etc/passwd",
        # Second order injection
        "admin'/*",
        "1; SELECT SLEEP(5)--",
        "1 WAITFOR DELAY '0:0:5'--",
        "'; EXEC xp_cmdshell('dir')--"
    ]
    malicious_texts.extend(additional_malicious)

    if texts and labels:
        # CSIC path: merge hand-written attacks in as extra positives.
        all_texts = texts + malicious_texts
        all_labels = labels + [1] * len(malicious_texts)
    else:
        # Legacy fallback: tiny hand-written lists only.
        # Benign text samples
        benign_base = [
        "user_login_request", "page=1&sort=asc", "id=10&category=books",
        "search_query=python", "action=view_profile", "status=active",
        "format=json&version=1.0", "limit=20&offset=0", "filter=recent",
        "session_id=abc123xyz", "lang=en-US", "user_agent=browser",
        "username=john&password=pass123",
        "search=laptop&category=electronics",
        "page=1&limit=20&sort=created_at",
        "name=John+Doe&email=john@example.com",
        "token=abc123&action=view",
        "filter=active&type=user"
    ]
        benign_texts = (benign_base * (len(malicious_texts) // len(benign_base) + 1))[:len(malicious_texts)]

    if not malicious_texts:
        logger.warning("No payload files found. Using fallback payload samples for training.")
        malicious_texts = ["' OR 1=1 --", "<script>alert(1)</script>", "; cat /etc/passwd"] * 50

    if not (texts and labels):
        all_texts = list(malicious_texts) + list(benign_texts)
        all_labels = [1] * len(malicious_texts) + [0] * len(benign_texts)

    # Stratified train/test split (80/20)
    X_train_texts, X_test_texts, y_train, y_test = train_test_split(
        all_texts, all_labels, test_size=0.20, random_state=42, stratify=all_labels
    )

    # Build vocab & encode sequences
    vocab = build_char_vocab(all_texts)
    vocab_path = Path(MODELS_DIR) / "char_vocab.json"
    with open(vocab_path, "w", encoding="utf-8") as f:
        json.dump(vocab, f)

    train_seqs = [encode_text(t, vocab) for t in X_train_texts]
    test_seqs = [encode_text(t, vocab) for t in X_test_texts]

    train_ds = SequenceDataset(train_seqs, y_train)
    test_ds = SequenceDataset(test_seqs, y_test)

    train_loader = DataLoader(train_ds, batch_size=16, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=16, shuffle=False)

    # Instantiate model
    model = PayloadLSTM(vocab_size=len(vocab))
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005)

    # Training loop
    epochs = 15
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0
        for x_batch, y_batch in train_loader:
            optimizer.zero_grad()
            preds = model(x_batch)
            loss = criterion(preds, y_batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

    # Evaluation
    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for x_batch, y_batch in test_loader:
            preds = model(x_batch)
            predicted_labels = (preds > 0.5).float().tolist()
            y_true.extend(y_batch.tolist())
            y_pred.extend(predicted_labels)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print("\n" + "="*50)
    print(" LAYER 3: LSTM MODEL EVALUATION METRICS")
    print("="*50)
    print(f" Precision : {precision*100:.2f}%")
    print(f" Recall    : {recall*100:.2f}%")
    print(f" F1-Score  : {f1*100:.2f}%")
    print("="*50)

    # Save model weights
    model_output_path = Path(MODELS_DIR) / "lstm_model.pt"
    torch.save(model.state_dict(), model_output_path)
    logger.info(f"Saved trained LSTM model weights to {model_output_path}")
    print(f"\n[+] LSTM model saved to: {model_output_path}\n")


if __name__ == "__main__":
    train_lstm_model()
