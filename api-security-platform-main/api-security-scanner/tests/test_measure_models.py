"""Ranking metrics for the Suspected experiment (2026-11-28).

Precision@K / Recall@K answer the reviewer's question directly: how
many of the top-ranked findings are actually useful, and how many
useful findings appear in the top-k. PR-AUC alone does not say that.
"""
import sys
from pathlib import Path

import pytest

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


def test_average_precision_is_tie_independent():
    from measure_models import average_precision, bootstrap_ci

    # Binary score: 4 positives + 20 negatives tie at 1.0, rest at 0.0.
    # The old item-by-item version gave AP 1.0 with positives first
    # among the ties and 0.109 with positives last, and the bootstrap CI
    # excluded the point estimate. Both orderings must now agree, and
    # the CI must contain the estimate. Tie-independent value: after the
    # 1.0 group, tp=4, fp=20, precision=4/24, recall=1.0 -> AP=1/6.
    s = [1.0] * 24 + [0.0] * 142
    y_first = [1] * 4 + [0] * 20 + [0] * 142
    y_last = [0] * 20 + [1] * 4 + [0] * 142
    ap_first = average_precision(y_first, s)
    ap_last = average_precision(y_last, s)
    assert ap_first == ap_last == pytest.approx(1 / 6)
    lo, hi = bootstrap_ci(y_first, s, average_precision)
    assert lo <= ap_first <= hi


def test_average_precision_matches_old_value_without_ties():
    from measure_models import average_precision

    # Distinct scores: grouping changes nothing. y=[1,0,1,0],
    # s=[0.9,0.8,0.7,0.6] -> 0.5 + (2/3)*0.5 = 5/6.
    assert average_precision([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.6]) == pytest.approx(5 / 6)
    assert average_precision([0, 0], [0.9, 0.1]) == 0.0


def test_recall_at_fpr_is_tie_independent():
    from measure_models import recall_at_fpr

    # One positive and one negative tie at 1.0, FPR target 0.0: the
    # group as a whole has FPR 1.0, so no threshold qualifies in either
    # ordering. The old version gave 1.0 or 0.0 depending on order.
    assert recall_at_fpr([1, 0], [1.0, 1.0], 0.0) == 0.0
    assert recall_at_fpr([0, 1], [1.0, 1.0], 0.0) == 0.0
    # Distinct scores keep the old behaviour.
    assert recall_at_fpr([1, 0, 0], [0.9, 0.8, 0.7], 0.0) == 1.0
