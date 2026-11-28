#!/usr/bin/env python3
"""Measure the SHIPPED models on the labeled dataset — without changing them.

Usage:
    python3 evaluation/measure_models.py <labeled.jsonl> [<labeled.jsonl> ...]

This answers the original question — do the ML/DL models work, and where
do they fail — with evidence, before any retraining. It scores the models
as shipped (their per-layer scores were logged with each pair) against
the ground-truth labels:

- PR-AUC (average precision) and recall at fixed false-positive rates
  (0.01, 0.05, 0.10) for the ML anomaly score, the LSTM probability and
  the autoencoder error.
- A simple rule baseline (error keyword appeared, or the payload was
  reflected) and the scanner's own verdict, for comparison.
- The ablation: signature only, signature + ML, signature + ML + DL
  (the shipped total), using the logged per-layer points.
- Everything is reported twice: on all positives, and on effective-only
  positives (probe_effective == 1 — the probe's response actually shows
  the bug). A probe that never triggered the bug looks normal, so no
  model can detect it; the effective-only numbers are the fair ceiling.

The scanner_label feature is EXCLUDED from every "ML alone" score: it is
the scanner's own verdict, and a model that uses it just copies Layer 1.
It is reported only as the scanner-verdict comparison.

The dataset is a pilot (429 pairs, ~10 unique bugs, 3 independent
groups), so every PR-AUC carries a bootstrap 95% confidence interval
and the numbers are labeled preliminary. Splits must group by target
app (VAmPI's vulnerable and secure modes are one group).
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

FPRS = (0.01, 0.05, 0.10)


def average_precision(y, s):
    """Average precision (PR-AUC) for binary labels y and scores s."""
    order = sorted(range(len(y)), key=lambda i: -s[i])
    tp = fp = 0
    total_pos = sum(y)
    if total_pos == 0:
        return 0.0
    ap = 0.0
    prev_recall = 0.0
    for i in order:
        if y[i]:
            tp += 1
        else:
            fp += 1
        precision = tp / (tp + fp)
        recall = tp / total_pos
        ap += precision * (recall - prev_recall)
        prev_recall = recall
    return ap


def recall_at_fpr(y, s, fpr_target):
    """Highest recall at a false-positive rate <= fpr_target."""
    order = sorted(range(len(y)), key=lambda i: -s[i])
    total_pos = sum(y)
    total_neg = len(y) - total_pos
    if total_pos == 0 or total_neg == 0:
        return 0.0
    tp = fp = 0
    best = 0.0
    for i in order:
        if y[i]:
            tp += 1
        else:
            fp += 1
        if fp / total_neg <= fpr_target:
            best = max(best, tp / total_pos)
    return best


def precision_at_k(y, s, k):
    """Precision among the top-k ranked items (ties keep input order —
    the same stable sort average_precision uses). k is clipped to n.
    Returns 0.0 when there are no positives or k <= 0. K is a protocol
    choice (which top-k a reviewer actually looks at), not a property
    of the data — see evaluation/METHODOLOGY.md."""
    order = sorted(range(len(y)), key=lambda i: -s[i])
    k = max(0, min(int(k), len(y)))
    if k == 0 or sum(y) == 0:
        return 0.0
    return sum(1 for i in order[:k] if y[i]) / k


def recall_at_k(y, s, k):
    """Recall captured in the top-k ranked items. Same tie and
    clipping rules as precision_at_k."""
    order = sorted(range(len(y)), key=lambda i: -s[i])
    k = max(0, min(int(k), len(y)))
    total_pos = sum(y)
    if k == 0 or total_pos == 0:
        return 0.0
    return sum(1 for i in order[:k] if y[i]) / total_pos


def bootstrap_ci(y, s, metric, n_boot=1000, seed=42):
    """Bootstrap 95% CI for a metric function(y, s)."""
    rng = random.Random(seed)
    n = len(y)
    vals = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        yb = [y[i] for i in idx]
        sb = [s[i] for i in idx]
        if sum(yb) == 0 or sum(yb) == len(yb):
            continue
        vals.append(metric(yb, sb))
    if not vals:
        return (0.0, 0.0)
    vals.sort()
    lo = vals[int(0.025 * len(vals))]
    hi = vals[int(0.975 * len(vals)) - 1]
    return (lo, hi)


def load(paths):
    records = []
    for path in paths:
        records.extend(json.loads(line) for line in open(path)
                       if line.strip())
    return records


def score_columns(records):
    """The scores to measure, each a (name, fn) pair."""
    def ls(r, key, default=0.0):
        v = (r.get("layer_scores") or {}).get(key)
        return default if v is None else float(v)

    def rule(r):
        t = r.get("telemetry", {}) or {}
        try:
            if float(t.get("error_keyword_delta") or 0) > 0:
                return 1.0
        except (TypeError, ValueError):
            pass
        return 1.0 if t.get("payload_reflected") else 0.0

    return [
        ("ML anomaly score", lambda r: ls(r, "ml_anomaly_score")),
        ("LSTM probability", lambda r: ls(r, "lstm_probability")),
        ("Autoencoder error", lambda r: ls(r, "autoencoder_error")),
        ("Signature points", lambda r: ls(r, "signature_points")),
        ("Signature + ML", lambda r: ls(r, "signature_points") + ls(r, "ml_points")),
        ("Signature + ML + DL (shipped total)",
         lambda r: ls(r, "total_score")),
        ("Rule baseline (error keyword / reflection)", rule),
        ("Scanner verdict (Confirmed = 1)",
         lambda r: float((r.get("telemetry", {}) or {}).get("scanner_label") or 0)),
    ]


def report(records, title):
    y_all = [r.get("label", 0) for r in records]
    y_eff = [r.get("label", 0) if r.get("probe_effective") else 0
             for r in records]
    # Effective-only positives: drop the not-effective positives from the
    # positive set (they stay out of both classes — they are neither a
    # fair positive nor a negative).
    eff_records = [r for r in records
                   if r.get("label", 0) == 0 or r.get("probe_effective")]
    y_eff2 = [r.get("label", 0) for r in eff_records]
    print(f"\n### {title}")
    print(f"n={len(records)}  positives={sum(y_all)}  "
          f"effective positives={sum(y_eff)}  negatives={len(records) - sum(y_all)}")
    print(f"{'score':42s} {'PR-AUC':>7s} {'95% CI':>17s}  "
          + "  ".join(f"R@{f:.2f}" for f in FPRS)
          + "   P@10   R@10")
    for name, fn in score_columns(records):
        s = [fn(r) for r in records]
        ap = average_precision(y_all, s)
        lo, hi = bootstrap_ci(y_all, s, average_precision)
        recalls = "  ".join(f"{recall_at_fpr(y_all, s, f):.2f}" for f in FPRS)
        print(f"{name:42s} {ap:7.3f} [{lo:.3f}, {hi:.3f}]  {recalls}"
              f"   {precision_at_k(y_all, s, 10):.2f}  {recall_at_k(y_all, s, 10):.2f}")
    print("-- effective-only positives --")
    for name, fn in score_columns(records):
        s = [fn(r) for r in eff_records]
        ap = average_precision(y_eff2, s)
        recalls = "  ".join(f"{recall_at_fpr(y_eff2, s, f):.2f}" for f in FPRS)
        print(f"{name:42s} {ap:7.3f} {'':17s}  {recalls}"
              f"   {precision_at_k(y_eff2, s, 10):.2f}  {recall_at_k(y_eff2, s, 10):.2f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("labeled", nargs="+",
                    help="labeled dataset JSONL files (from label_dataset.py)")
    args = ap.parse_args()
    records = load(args.labeled)
    groups = sorted({r.get("group", "?") for r in records})
    print("PRELIMINARY — pilot dataset: 3 independent groups "
          f"({', '.join(groups)}). "
          "PR-AUC CIs are wide; do not quote without them.")
    report(records, "All groups pooled")
    for group in groups:
        subset = [r for r in records if r.get("group") == group]
        if len(subset) >= 20 and sum(r.get("label", 0) for r in subset) >= 1:
            report(subset, f"Group: {group}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
