#!/usr/bin/env python3
"""Retrain and compare ML models on the labeled dataset — Claude's plan.

Usage:
    python3 evaluation/retrain.py <labeled.jsonl> [<labeled.jsonl> ...]
        [--report retraining-report-YYYY-MM-DD.md]

Implements the retraining plan from the Claude review (2026-11-27):

- Compare Logistic Regression, Random Forest and a gradient-boosted
  model against the rule baseline, using group-based splits
  (leave-one-group-out; each vulnerable app + its patched twin is ONE
  group, so training on one twin and testing on the other is leakage).
- For text, test TF-IDF + Logistic Regression against the LSTM. The LSTM
  itself is NOT retrained here: 15 positives cannot train one. The
  comparison is TF-IDF+LR (trained per fold) vs the shipped LSTM's logged
  probability on the same folds.
- Success = beating the rule baseline, and specifically ranking Suspected
  findings better, measured WITHIN the Suspected group (the pairs the
  scanner already called Suspected — the layer where the noise lives).
  **The within-Suspected block is the PRIMARY result; the pooled blocks
  are secondary.** A model scored on all positives is partly graded on
  re-learning Layer 1's rules (see the feature audit, 2026-11-28); among
  findings the rules could not prove, can the model tell real from
  false? That is the question.
- Differential-only ablation arm (planned, 2026-11-28): the same three
  tabular models trained on the 8 features that do NOT mirror Layer 1
  evidence (status/size/time/body diffs, content-type change,
  status class, response size/time). If an ablation model beats the
  rules, that is independent signal. If it does not, say so.
- If the autoencoder is still near chance, remove it and say why
  (measured here; the removal itself is a separate code change).
- Protocol: evaluation/PROTOCOL-2026-11-28.md fixes the groups, folds,
  K (per scan, K=10; pooled secondary), metrics, baseline and success
  rule BEFORE any result is seen. Do not change K or the metric after
  seeing the numbers.

Design rules inherited from the dataset design:
- Labels come from the ground-truth join only. `scanner_label` is
  EXCLUDED from every "ML alone" model: it is the scanner's own verdict,
  and a model that uses it just copies Layer 1.
- Features are the logged 15 differential keys (telemetry.feature_vector,
  schema response-diff-14-v1). No payload text in the tabular features.
- Report results on all positives AND on effective-only positives
  (probe_effective == 1). A probe that never triggered the bug looks
  normal, so no model can detect it.
- Everything is preliminary with bootstrap 95% CIs. Leave-one-group-out
  on 2 groups is very unstable; do not quote a number without its
  interval.

Dedupe guard: the same (group, mode) must not arrive from two different
session ids (a re-scan supersedes the old log — e.g. php vuln session 5
was superseded by session 6). If it does, only the latest session is
kept and a warning is printed.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from measure_models import (average_precision, bootstrap_ci, precision_at_k,
                            recall_at_fpr, recall_at_k)  # noqa: E402
from ml_pipeline.feature_extractor import FEATURE_KEYS  # noqa: E402

from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

FPRS = (0.01, 0.05, 0.10)
RANDOM_STATE = 42


def load(paths):
    records = []
    seen = set()
    for path in paths:
        for line in open(path):
            if not line.strip():
                continue
            key = line.strip()
            if key in seen:
                print(f"WARNING: duplicate pair skipped (same file passed "
                      f"twice?): {path}")
                continue
            seen.add(key)
            records.append(json.loads(line))
    return records


def dedupe_guard(records):
    """Keep only the latest session per (group, mode)."""
    by_key = defaultdict(list)
    for r in records:
        by_key[(r.get("group", "?"), r.get("mode", "?"))].append(r)
    kept, dropped = [], 0
    for key, rows in by_key.items():
        sessions = sorted({r.get("session_id") for r in rows})
        if len(sessions) > 1:
            latest = sessions[-1]
            print(f"WARNING: {key} appears in sessions {sessions} — "
                  f"keeping only the latest (session {latest}); "
                  f"the older log is superseded, not extra data.")
            rows = [r for r in rows if r.get("session_id") == latest]
            dropped += len(by_key[key]) - len(rows)
        kept.extend(rows)
    if dropped:
        print(f"WARNING: dropped {dropped} superseded pairs.")
    return kept


def tabular_X(records):
    """The 15 logged differential features, in FEATURE_KEYS order."""
    X = []
    for r in records:
        t = r.get("telemetry", {}) or {}
        vec = t.get("feature_vector")
        if vec is None or len(vec) != len(FEATURE_KEYS):
            vec = [float(t.get(k, 0) or 0) for k in FEATURE_KEYS]
        X.append([float(v) for v in vec])
    return np.array(X, dtype=float)


# Differential-only ablation (feature audit 2026-11-28): the 8 features
# that do NOT mirror Layer 1 rule evidence. Excluded: error_keyword_delta,
# payload_reflected, unsafe_reflection (the proof features), and
# error_keyword_count / sensitive_field_count (the rule's keyword/pattern
# evidence). Kept: the generic anomaly shape — how the response changed
# vs its baseline, and its absolute size/time/class. If a model trained
# on ONLY these beats the rule baseline, that is independent signal.
ABLATION_KEYS = [
    "status_changed",
    "size_delta_ratio",
    "time_delta_ratio",
    "body_diff_ratio",
    "content_type_changed",
    "status_class",
    "response_size_log",
    "response_time_s",
]
_ABLATION_IDX = [FEATURE_KEYS.index(k) for k in ABLATION_KEYS]


def ablation_X(records):
    """The 8 differential-only features, same rows as tabular_X."""
    return tabular_X(records)[:, _ABLATION_IDX]


def probe_text(r):
    probe = r.get("probe") or {}
    body = probe.get("response_body") or ""
    return body if isinstance(body, str) else str(body)


def rule_score(r):
    t = r.get("telemetry", {}) or {}
    try:
        if float(t.get("error_keyword_delta") or 0) > 0:
            return 1.0
    except (TypeError, ValueError):
        pass
    return 1.0 if t.get("payload_reflected") else 0.0


def layer_score(r, key, default=0.0):
    v = (r.get("layer_scores") or {}).get(key)
    return default if v is None else float(v)


def suspected_mask(records):
    out = []
    for r in records:
        t = r.get("telemetry", {}) or {}
        status = t.get("scanner_finding_status") or \
            (r.get("finding") or {}).get("finding_status")
        out.append(status == "Suspected")
    return np.array(out, dtype=bool)


def balanced_sample_weight(y):
    """Per-class weights inversely proportional to class frequency."""
    y = np.asarray(y)
    n_pos = int(y.sum())
    n_neg = len(y) - n_pos
    w = np.where(y == 1,
                 len(y) / (2.0 * max(n_pos, 1)),
                 len(y) / (2.0 * max(n_neg, 1)))
    return w


def build_tabular_models():
    return {
        "Logistic Regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(class_weight="balanced", max_iter=1000,
                               random_state=RANDOM_STATE)),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            random_state=RANDOM_STATE, n_jobs=-1),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.06, random_state=RANDOM_STATE),
    }


def metric_row(name, y, s, out):
    y = list(y)
    s = [float(v) for v in s]
    if sum(y) == 0:
        out.append(f"{name:42s} {'no positives':>7s}")
        return
    ap = average_precision(y, s)
    lo, hi = bootstrap_ci(y, s, average_precision)
    recalls = "  ".join(f"{recall_at_fpr(y, s, f):.2f}" for f in FPRS)
    # Ranking at K=10 (provisional — the experimental protocol, step 7,
    # defines K: the number of top-ranked findings a reviewer actually
    # looks at). P@10/R@10 are reported in every block, including
    # within-Suspected, where ranking is the question.
    out.append(f"{name:42s} {ap:7.3f} [{lo:.3f}, {hi:.3f}]  {recalls}"
               f"   {precision_at_k(y, s, 10):.2f}  {recall_at_k(y, s, 10):.2f}")


def per_scan_p_at_k(y, s, sessions, k=10):
    """Mean per-scan Precision@K and Recall@K.

    Each scan (one session_id) is ranked separately — this is the
    primary ranking view (protocol 2026-11-28): a reviewer looks at
    the top-k findings of ONE scan, not a pooled list. A scan with
    fewer than k pairs in the subset uses min(k, n) as the precision
    denominator. Recall averages only over scans with >= 1 positive
    in the subset. Returns (mean_p, mean_r, n_scans_for_p,
    n_scans_for_r).
    """
    by_scan = {}
    for yi, si, sess in zip(y, s, sessions):
        by_scan.setdefault(sess, []).append((yi, si))
    ps, rs = [], []
    for pairs in by_scan.values():
        pairs.sort(key=lambda p: -p[1])
        kk = min(k, len(pairs))
        tp = sum(1 for yi, _ in pairs[:kk] if yi)
        ps.append(tp / kk if kk else 0.0)
        pos = sum(1 for yi, _ in pairs if yi)
        if pos:
            rs.append(tp / pos)
    mean_p = sum(ps) / len(ps) if ps else 0.0
    mean_r = sum(rs) / len(rs) if rs else 0.0
    return mean_p, mean_r, len(ps), len(rs)


def report_block(title, y, scores, out):
    out.append(f"\n### {title}")
    out.append(f"n={len(y)}  positives={int(sum(y))}  "
               f"chance PR-AUC ~ {sum(y) / max(len(y), 1):.3f}")
    out.append(f"{'score':42s} {'PR-AUC':>7s} {'95% CI':>17s}  "
               + "  ".join(f"R@{f:.2f}" for f in FPRS)
               + "   P@10   R@10")
    for name, s in scores.items():
        metric_row(name, y, s, out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("labeled", nargs="+",
                    help="labeled dataset JSONL files (from label_dataset.py)")
    ap.add_argument("--report", default=None,
                    help="write the report to this markdown file too")
    args = ap.parse_args()

    records = dedupe_guard(load(args.labeled))
    groups = sorted({r.get("group", "?") for r in records})
    y = np.array([r.get("label", 0) for r in records], dtype=int)
    y_eff_mask = np.array(
        [(r.get("label", 0) == 0 or r.get("probe_effective")) for r in records],
        dtype=bool)
    susp = suspected_mask(records)
    n_trunc = sum(1 for r in records
                  if (r.get("probe") or {}).get("truncated"))
    print(f"Loaded {len(records)} pairs, {int(y.sum())} positive "
          f"({int(((y == 1) & np.array([r.get('probe_effective') for r in records], dtype=bool)).sum())} effective), "
          f"{len(records) - int(y.sum())} negative; "
          f"groups: {', '.join(groups)}; "
          f"truncated probe bodies: {n_trunc}.")

    X = tabular_X(records)
    X_abl = ablation_X(records)
    texts = [probe_text(r) for r in records]

    # Leave-one-group-out: train on all groups but one, test on the held
    # out group. Collect out-of-fold predictions for every pair.
    oof = defaultdict(lambda: np.zeros(len(records)))
    fold_info = []
    for held in groups:
        test_idx = np.array([r.get("group") == held for r in records])
        train_idx = ~test_idx
        if y[train_idx].sum() == 0 or y[test_idx].sum() == 0:
            print(f"Fold held-out={held}: skipped "
                  f"(train pos={int(y[train_idx].sum())}, "
                  f"test pos={int(y[test_idx].sum())}).")
            continue
        fold_info.append((held, int(train_idx.sum()), int(y[train_idx].sum()),
                          int(test_idx.sum()), int(y[test_idx].sum())))
        for name, model in build_tabular_models().items():
            if name == "Gradient Boosting":
                model.fit(X[train_idx], y[train_idx],
                          sample_weight=balanced_sample_weight(y[train_idx]))
            else:
                model.fit(X[train_idx], y[train_idx])
            oof[name][test_idx] = model.predict_proba(X[test_idx])[:, 1]
        # Differential-only ablation arm: same models, rule-overlap
        # features removed. Independent signal is measured here.
        for name, model in build_tabular_models().items():
            aname = name + " (differential-only)"
            if name == "Gradient Boosting":
                model.fit(X_abl[train_idx], y[train_idx],
                          sample_weight=balanced_sample_weight(y[train_idx]))
            else:
                model.fit(X_abl[train_idx], y[train_idx])
            oof[aname][test_idx] = model.predict_proba(X_abl[test_idx])[:, 1]
        vec = TfidfVectorizer(max_features=2000, ngram_range=(1, 2),
                              sublinear_tf=True, min_df=1)
        Xtr = vec.fit_transform([texts[i] for i in np.where(train_idx)[0]])
        Xte = vec.transform([texts[i] for i in np.where(test_idx)[0]])
        tfidf = LogisticRegression(class_weight="balanced", max_iter=1000,
                                   random_state=RANDOM_STATE)
        tfidf.fit(Xtr, y[train_idx])
        oof["TF-IDF + Logistic Regression"][test_idx] = \
            tfidf.predict_proba(Xte)[:, 1]

    for held, n_tr, p_tr, n_te, p_te in fold_info:
        print(f"Fold held-out={held}: train n={n_tr} ({p_tr} pos), "
              f"test n={n_te} ({p_te} pos).")

    # Fixed (untrained) scores for comparison on the same pairs.
    fixed = {
        "Rule baseline (error keyword / reflection)":
            np.array([rule_score(r) for r in records], dtype=float),
        "Shipped ML anomaly score":
            np.array([layer_score(r, "ml_anomaly_score") for r in records]),
        "Shipped LSTM probability":
            np.array([layer_score(r, "lstm_probability") for r in records]),
        "Shipped autoencoder error":
            np.array([layer_score(r, "autoencoder_error") for r in records]),
        "Signature points":
            np.array([layer_score(r, "signature_points") for r in records]),
        "Scanner verdict (Confirmed = 1)":
            np.array([float((r.get("telemetry", {}) or {}).get("scanner_label") or 0)
                      for r in records]),
    }
    for name in oof:
        fixed[name] = oof[name]
    order = ["Logistic Regression", "Random Forest", "Gradient Boosting",
             "Logistic Regression (differential-only)",
             "Random Forest (differential-only)",
             "Gradient Boosting (differential-only)",
             "TF-IDF + Logistic Regression",
             "Rule baseline (error keyword / reflection)",
             "Shipped ML anomaly score", "Shipped LSTM probability",
             "Shipped autoencoder error", "Signature points",
             "Scanner verdict (Confirmed = 1)"]
    scores = {name: fixed[name] for name in order if name in fixed}

    out = []
    out.append("# Retraining comparison (Claude's plan)")
    out.append("")
    out.append(f"Date: {date.today().isoformat()}. "
               f"n={len(records)}, positives={int(y.sum())} "
               f"({int(((y == 1) & np.array([bool(r.get('probe_effective')) for r in records])).sum())} effective), "
               f"groups: {', '.join(groups)} (leave-one-group-out).")
    out.append("PRELIMINARY — small dataset, "
               f"{len(groups)} independent group(s); "
               "PR-AUC CIs are wide; do not quote a number without its "
               "interval. `scanner_label` is excluded from every ML-alone "
               "model. Signature points are optimistic (tuned on dev apps).")
    # PRIMARY result first: within-Suspected ranking. The pooled blocks
    # are secondary — a model scored on all positives is partly graded
    # on re-learning Layer 1's rules.
    sessions = [r.get("session_id", "?") for r in records]
    if susp.sum() > 0 and y[susp].sum() > 0:
        report_block("PRIMARY — WITHIN the Suspected group "
                     "(scanner called Suspected)",
                     y[susp],
                     {k: np.asarray(v)[susp] for k, v in scores.items()},
                     out)
        out.append(f"(Suspected subset: n={int(susp.sum())}, "
                   f"positives={int(y[susp].sum())}.)")
        # Per-scan P@10 / R@10 (K=10, protocol 2026-11-28): each scan
        # ranked separately, averaged across scans. Pooled P@10/R@10 in
        # the table above are secondary.
        out.append("\nPer-scan ranking (K=10, mean across scans):")
        susp_idx = np.where(susp)[0]
        susp_sessions = [sessions[i] for i in susp_idx]
        for name, v in scores.items():
            mp, mr, np_, nr = per_scan_p_at_k(
                list(y[susp]), [float(x) for x in np.asarray(v)[susp]],
                susp_sessions, k=10)
            out.append(f"  {name:42s} P@10 {mp:.2f} (n={np_} scans)  "
                       f"R@10 {mr:.2f} (n={nr} scans)")
    else:
        out.append("\nNo Suspected pairs with positives — the "
                   "within-Suspected ranking could not be measured.")
    report_block("Secondary — pooled out-of-fold, all positives", y, scores, out)
    report_block("Secondary — pooled out-of-fold, effective-only positives",
                 y[y_eff_mask],
                 {k: np.asarray(v)[y_eff_mask] for k, v in scores.items()},
                 out)
    ae_ap = average_precision(list(y), list(fixed["Shipped autoencoder error"]))
    chance = y.sum() / max(len(y), 1)
    out.append("")
    if ae_ap <= max(chance * 2, 0.05):
        out.append(f"AUTOENCODER VERDICT: PR-AUC {ae_ap:.3f} vs chance "
                   f"~{chance:.3f} — still near chance. Per the plan, "
                   "remove it and say why: it adds noise, not signal, "
                   "and its points no longer reach the score (weight 0 "
                   "since 2026-11-27), so removal is dead code, not a "
                   "capability loss.")
    else:
        out.append(f"AUTOENCODER VERDICT: PR-AUC {ae_ap:.3f} vs chance "
                   f"~{chance:.3f} — above chance; keep for now and "
                   "re-measure on more data.")

    text = "\n".join(out)
    print(text)
    if args.report:
        Path(args.report).write_text(text + "\n")
        print(f"\nWrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
