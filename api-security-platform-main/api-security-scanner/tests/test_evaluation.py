"""Tests for the evaluation harness (evaluation/score_scan.py).

The scorer is the tool that produces the project's numbers, so it gets
its own tests — including the standing rule it inherited from the retired
PlatformEvaluator: a missing input must fail loudly, never be replaced
with invented numbers.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

from score_scan import score  # noqa: E402


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return str(path)


GT_SQLI = """items:
  - id: GT-01
    template: /users/v1/{username}
    parameter: username (path)
    category: SQL_Injection
    how_verified: "manual"
    date: 2026-11-27
    added_after_scan: false
"""

GT_VERBOSE = """items:
  - id: GT-10
    template: "*"
    parameter: null
    category: Verbose_Error_Exposure
    how_verified: "manual"
    date: 2026-11-27
    added_after_scan: true
    also_detected_by: [SQL_Injection]
"""


def test_scorer_counts_unique_bugs_not_findings(tmp_path):
    """Four Confirmed SQLi rows on the same sink are ONE bug, not four."""
    gt = _write(tmp_path, "gt.yaml", GT_SQLI)
    findings = _write(tmp_path, "findings.txt", "\n".join(
        f"[Confirmed] CRITICAL SQL_Injection :: "
        f"http://127.0.0.1:5000/users/v1/{u}' (score=100.0)"
        for u in ("name1", "admin", "login", "x")
    ) + "\n")
    report = score(gt, findings)
    assert report["confirmed"]["tp_unique_bugs"] == 1
    assert report["confirmed"]["recall"] == 1.0
    assert report["confirmed"]["fp_unique_pairs"] == 0
    assert report["results"][0]["confirmed_findings"] == 4


def test_scorer_wrong_category_bucket(tmp_path):
    """A bug found but filed under another category stays FN for recall
    and is reported separately — it never improves the headline numbers."""
    gt = _write(tmp_path, "gt.yaml", GT_VERBOSE)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:5000/users/v1/login' (score=100.0)\n")
    report = score(gt, findings)
    assert report["confirmed"]["tp_unique_bugs"] == 0
    assert report["confirmed"]["recall"] == 0.0
    assert len(report["detected_wrong_category"]) == 1
    assert report["detected_wrong_category"][0]["id"] == "GT-10"
    assert report["detected_wrong_category"][0]["detected_as"] == ["SQL_Injection"]
    assert report["results"][0]["verdict"].startswith("FN (detected, wrong category")


def test_missing_input_is_not_replaced_with_fake_numbers(tmp_path):
    """The no-fake-numbers rule, migrated from the retired PlatformEvaluator:
    a missing findings file must fail loudly instead of producing invented
    metrics. No report dict, no zeros dressed up as a score."""
    gt = _write(tmp_path, "gt.yaml", GT_SQLI)
    with pytest.raises(FileNotFoundError):
        score(gt, str(tmp_path / "does-not-exist.txt"))
    with pytest.raises(FileNotFoundError):
        score(str(tmp_path / "missing-gt.yaml"),
              _write(tmp_path, "findings.txt", ""))


# --- label_dataset.py -------------------------------------------------------
GT_LABEL = """
items:
  - id: T-01
    template: /users/v1/{username}
    parameter: username
    category: SQL_Injection
    modes: [vulnerable]
    date: "2026-11-27"
  - id: T-02
    template: /users/v1/_debug
    parameter: ""
    category: Sensitive_Data_Exposure
    modes: [vulnerable, secure]
    date: "2026-11-27"
"""


def _rec(url, parameter, probe_type, mode):
    return {"endpoint_url": url, "parameter": parameter,
            "probe_type": probe_type, "mode": mode,
            "finding": {"attack_type": None}}


def test_labeler_joins_to_ground_truth_not_the_scanner_verdict(tmp_path):
    """The label comes from the ground-truth join, never from the
    scanner's verdict: a path-appended SQLi probe on a real sink is
    positive; the same probe in secure mode is negative (the item is
    mode-scoped); a probe on a clean endpoint is negative."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                           / "evaluation"))
    from label_dataset import label

    gt = _write(tmp_path, "gt.yaml", GT_LABEL)
    records = [
        _rec("http://127.0.0.1:5000/users/v1/name1'", "path",
             "SQL_Injection_Error", "vulnerable"),
        _rec("http://127.0.0.1:5000/users/v1/name1'", "path",
             "SQL_Injection_Error", "secure"),
        _rec("http://127.0.0.1:5000/users/v1/_debug", "",
             "Sensitive_Data_Exposure", "secure"),
        _rec("http://127.0.0.1:5000/users/v1/other", "path",
             "XSS", "vulnerable"),
    ]
    labeled, stats = label(records, gt)
    assert [r["label"] for r in labeled] == [1, 0, 1, 0]
    assert labeled[0]["matched_item"] == "T-01"
    assert labeled[2]["matched_item"] == "T-02"
    assert stats["positive"] == 2 and stats["negative"] == 2
