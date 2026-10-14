"""Train the response-body LSTM (Layer 3 sequence model).

The model reads the TARGET'S RESPONSE BODY (first 512 chars) and estimates
the probability that the response is an exploit-effect response (SQL error
text, sensitive data dump, unescaped reflection, redirect-to-attacker page)
versus a normal application response.

Training data: ml_pipeline/datasets/response_bodies_v1.csv — real HTTP
response bodies captured live from public test services (httpbin.org,
example.com, postman-echo.com), a local ground-truth app with planted
vulnerabilities, and VAmPI (a real vulnerable API). Labels were reviewed
body-by-body; ambiguous captures were dropped, never guessed. Augmented
rows (declared '+aug' in the source column) are JSON re-serializations and
whitespace variants of real captures.

Honesty protocol: the shipped model trains on all rows, and this script
ALSO runs a grouped holdout experiment (aug variants and same-template
captures never straddle the split) whose accuracy is recorded in the
metrics file as the generalization estimate.

Run: python ml_pipeline/train_response_lstm.py [--epochs 80]
Outputs: models/response_lstm.pt, models/response_char_vocab.json,
         models/response_lstm_metrics.json
"""
import argparse
import csv
import json
import os
import random
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
os.environ.setdefault("PYTHONHASHSEED", "42")

import torch
import torch.nn as nn

from config.settings import MODELS_DIR
from training.train_lstm import PayloadLSTM, build_char_vocab, encode_text

DATA_PATH = ROOT_DIR / "ml_pipeline" / "datasets" / "response_bodies_v1.csv"
MAX_LEN = 512


def _group_key(source: str) -> str:
    base = source.split("+aug")[0].split("[")[0]
    # The ground-truth app returns one identical SQL-error body for several
    # payloads; those captures are a single template group.
    if base.startswith("gt:sqli-") and base not in ("gt:sqli-normal", "gt:sqli-normal2", "gt:sqli-union-normal"):
        return "gt:sqli-error"
    return base


def _encode(text, vocab):
    seq = encode_text(text[:MAX_LEN], vocab)
    return [0] * (MAX_LEN - len(seq)) + seq  # LEFT-pad, matches serving


def _train_model(texts, labels, vocab, epochs, seed=42):
    torch.manual_seed(seed)
    random.seed(seed)
    x = torch.tensor([_encode(t, vocab) for t in texts], dtype=torch.long)
    y = torch.tensor(labels, dtype=torch.float32)
    n_pos = max(1, int(sum(labels)))
    n_neg = max(1, len(labels) - n_pos)
    w = torch.tensor([n_neg / n_pos if l == 1 else 1.0 for l in labels], dtype=torch.float32)
    model = PayloadLSTM(vocab_size=len(vocab))
    opt = torch.optim.Adam(model.parameters(), lr=0.005)
    model.train()
    n = len(texts)
    batch = 16
    for epoch in range(epochs):
        perm = torch.randperm(n)
        for i in range(0, n, batch):
            idx = perm[i:i + batch]
            opt.zero_grad()
            losses = nn.functional.binary_cross_entropy(model(x[idx]), y[idx], reduction="none")
            loss = (losses * w[idx]).mean()
            loss.backward()
            opt.step()
    model.eval()
    return model


# Canonical bodies the shipped model MUST get right — enforced, not hoped.
SANITY_GATES = [
    ("sql error page", "Warning: mysql_fetch_array() expects parameter 1 to be resource, "
     "boolean given. You have an error in your SQL syntax near '' OR 1=1 --''", 0.5, "above"),
    ("xss reflection", "<html><body><h1>Hello <script>alert(1)</script></h1></body></html>", 0.5, "above"),
    ("clean json", '{"status":"ok","version":"1.0"}', 0.5, "below"),
    ("normal greeting page", "<html><body><h1>Hello alice</h1></body></html>", 0.5, "below"),
]


def _prob(model, text, vocab):
    x = torch.tensor([_encode(text, vocab)], dtype=torch.long)
    with torch.no_grad():
        return float(model(x).item())


def _gates_pass(model, vocab):
    for _name, body, thresh, direction in SANITY_GATES:
        p = _prob(model, body, vocab)
        if direction == "above" and p <= thresh:
            return False
        if direction == "below" and p >= thresh:
            return False
    return True


def _accuracy(model, texts, labels, vocab):
    if not texts:
        return None
    x = torch.tensor([_encode(t, vocab) for t in texts], dtype=torch.long)
    with torch.no_grad():
        preds = (model(x) > 0.5).int().tolist()
    return sum(int(p == l) for p, l in zip(preds, labels)) / len(labels)


def train_response_lstm(output_dir: Path, epochs: int = 200) -> dict:
    with open(DATA_PATH, newline="") as f:
        rows = list(csv.DictReader(f))
    texts = [r["body"] for r in rows]
    labels = [int(r["label"]) for r in rows]
    sources = [r["source"] for r in rows]
    vocab = build_char_vocab(texts)

    # --- grouped holdout experiment (generalization estimate) ---
    groups = {}
    for i, s in enumerate(sources):
        groups.setdefault(_group_key(s), []).append(i)
    rng = random.Random(7)
    holdout_idx = set()
    for label in (0, 1):
        g = [k for k in groups if labels[groups[k][0]] == label]
        rng.shuffle(g)
        for k in g[: max(1, len(g) // 5)]:
            holdout_idx.update(groups[k])
    tr = [i for i in range(len(rows)) if i not in holdout_idx]
    ho = sorted(holdout_idx)
    exp_model = _train_model([texts[i] for i in tr], [labels[i] for i in tr], vocab, epochs)
    holdout_acc = _accuracy(exp_model, [texts[i] for i in ho], [labels[i] for i in ho], vocab)
    print(f"    grouped holdout: {len(ho)} rows, accuracy {holdout_acc}")

    # --- shipped model: seed sweep on all rows, sanity gates enforced ---
    best = None
    for seed in (42, 7, 123, 2024, 5, 99):
        candidate = _train_model(texts, labels, vocab, epochs, seed=seed)
        acc = _accuracy(candidate, texts, labels, vocab)
        ok = _gates_pass(candidate, vocab)
        print(f"    seed {seed}: train accuracy {acc}, sanity gates {'PASS' if ok else 'FAIL'}")
        if ok and (best is None or acc > best[1]):
            best = (candidate, acc, seed)
        if best is not None and best[1] >= 0.97:
            break
    if best is None:
        raise SystemExit("No seed passed the sanity gates — refusing to ship a bad model.")
    model, train_acc, chosen_seed = best
    print(f"    shipping seed {chosen_seed} (train accuracy {train_acc})")

    output_dir.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), output_dir / "response_lstm.pt")
    (output_dir / "response_char_vocab.json").write_text(json.dumps(vocab, indent=2))
    metrics = {
        "model": "response-body char LSTM (PayloadLSTM architecture)",
        "trains_on": "target response bodies (first 512 chars), never payload text",
        "dataset": "ml_pipeline/datasets/response_bodies_v1.csv",
        "rows": len(rows),
        "benign_rows": labels.count(0),
        "anomalous_rows": labels.count(1),
        "vocab_size": len(vocab),
        "max_len": MAX_LEN,
        "epochs": epochs,
        "train_accuracy": round(train_acc, 4) if train_acc is not None else None,
        "grouped_holdout_accuracy": round(holdout_acc, 4) if holdout_acc is not None else None,
        "grouped_holdout_rows": len(ho),
        "chosen_seed": chosen_seed,
        "sanity_gates": "passed (sql error & xss reflection > 0.5; clean json & normal page < 0.5)",
    }
    (output_dir / "response_lstm_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"    train accuracy: {train_acc} | artifacts -> {output_dir}")
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train the response-body LSTM.")
    parser.add_argument("--output", type=Path, default=Path(MODELS_DIR))
    parser.add_argument("--epochs", type=int, default=200)
    args = parser.parse_args()
    print(f"[+] Training response-body LSTM ({args.epochs} epochs)...")
    metrics = train_response_lstm(args.output, args.epochs)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
