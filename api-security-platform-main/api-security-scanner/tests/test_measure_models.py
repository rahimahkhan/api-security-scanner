"""Ranking metrics for the Suspected experiment (2026-11-28).

Precision@K / Recall@K answer the reviewer's question directly: how
many of the top-ranked findings are actually useful, and how many
useful findings appear in the top-k. PR-AUC alone does not say that.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                       / "evaluation"))

from measure_models import precision_at_k, recall_at_k  # noqa: E402
from retrain import per_scan_p_at_k  # noqa: E402


def test_precision_and_recall_at_k():
    # Scores rank the two positives first, then a negative, then a
    # positive: top-2 is perfect, top-3 is 2/3, top-4 catches all 3.
    y = [1, 1, 0, 1, 0, 0]
    s = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4]
    assert precision_at_k(y, s, 2) == 1.0
    assert recall_at_k(y, s, 2) == 2 / 3
    assert precision_at_k(y, s, 3) == 2 / 3
    assert recall_at_k(y, s, 4) == 1.0
    assert precision_at_k(y, s, 6) == 0.5


def test_at_k_edge_cases():
    # k larger than n clips to n; k <= 0 and no positives give 0.
    assert precision_at_k([1, 0], [0.9, 0.1], 10) == 0.5
    assert recall_at_k([1, 0], [0.9, 0.1], 10) == 1.0
    assert precision_at_k([1, 0], [0.9, 0.1], 0) == 0.0
    assert recall_at_k([1, 0], [0.9, 0.1], 0) == 0.0
    assert precision_at_k([0, 0], [0.9, 0.1], 2) == 0.0
    assert recall_at_k([0, 0], [0.9, 0.1], 2) == 0.0
    # A model that ranks all negatives first scores 0 at small k.
    assert precision_at_k([1, 0, 0], [0.1, 0.9, 0.8], 2) == 0.0
    assert recall_at_k([1, 0, 0], [0.1, 0.9, 0.8], 2) == 0.0


def test_per_scan_p_at_k():
    # Two scans: scan A ranks its positive first (P@2 0.5, R@2 1.0);
    # scan B ranks its positive third (P@2 0.0, R@2 0.0). Means 0.25/0.5.
    y = [1, 0, 0, 1, 0, 0]
    s = [0.9, 0.8, 0.7, 0.1, 0.9, 0.8]
    sessions = ["A", "A", "A", "B", "B", "B"]
    mp, mr, np_, nr = per_scan_p_at_k(y, s, sessions, k=2)
    assert mp == 0.25
    assert mr == 0.5
    assert (np_, nr) == (2, 2)
    # A scan with no positives counts for precision but not recall.
    mp, mr, np_, nr = per_scan_p_at_k(
        [1, 0, 0], [0.9, 0.8, 0.7], ["A", "A", "B"], k=2)
    assert mp == 0.25  # A: 0.5, B: 0.0
    assert mr == 1.0
    assert (np_, nr) == (2, 1)
