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
    """RETIRED — the payload-text LSTM trainer.

    This module's PayloadLSTM class, build_char_vocab and encode_text are
    still the shared architecture/encoding utilities used by serving
    (detection/deep_learning.py) and by the response-body trainer. But
    training an LSTM on payload text is retired: the model could only
    describe our own input, never the target. The production LSTM is
    trained on real response bodies — run:

        python ml_pipeline/train_response_lstm.py

    (dataset: ml_pipeline/datasets/response_bodies_v1.csv, built by
    ml_pipeline/build_response_body_dataset.py). This stub intentionally
    writes no artifacts so the retired payload model cannot come back by
    accident.
    """
    raise SystemExit(
        "train_lstm_model() is retired. Train the response-body LSTM with: "
        "python ml_pipeline/train_response_lstm.py"
    )


if __name__ == "__main__":
    train_lstm_model()
