"""Live deep-learning model classes (moved from training/, 2026-11-27).

The model architectures used at serving time live here, next to the
detector that loads them (detection/deep_learning.py). They used to live
in training/train_lstm.py and training/train_autoencoder.py, alongside
the retired CSIC training scripts — which made training/ look like dead
code and invited deleting the live classes with it. The training entry
points that used these classes now live in ml_pipeline/:
  - response-body LSTM: ml_pipeline/train_response_lstm.py (200 epochs,
    trained on real response bodies, never on payload text)
  - feature autoencoder: ml_pipeline/train_csic.py train_pipeline()
    (200 epochs, bottleneck 8)

The payload-text LSTM trainer is retired (its train function raised
SystemExit); the CSIC autoencoder trainer (20 epochs on features.csv)
is superseded by train_pipeline. Only the architectures and the
encoding helpers are kept here.
"""
from typing import Dict, List

import torch
import torch.nn as nn


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


def build_char_vocab(payload_texts: List[str]) -> Dict[str, int]:
    vocab = {"<PAD>": 0, "<UNK>": 1}
    for text in payload_texts:
        for char in text:
            if char not in vocab:
                vocab[char] = len(vocab)
    return vocab


def encode_text(text: str, vocab: Dict[str, int]) -> List[int]:
    return [vocab.get(char, vocab["<UNK>"]) for char in text]


# The 17 runtime features the autoencoder reconstructs (schema
# runtime-http-17-v1). The class takes input_dim; this list documents what
# those 17 inputs are.
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
    "has_sql_structure",
]


class FeatureAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 17, bottleneck_dim: int = 6):
        super(FeatureAutoencoder, self).__init__()
        # Encoder: 17 -> 10 -> 6
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 10),
            nn.ReLU(),
            nn.Linear(10, bottleneck_dim),
            nn.ReLU(),
        )
        # Decoder: 6 -> 10 -> 17
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, 10),
            nn.ReLU(),
            nn.Linear(10, input_dim),
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
