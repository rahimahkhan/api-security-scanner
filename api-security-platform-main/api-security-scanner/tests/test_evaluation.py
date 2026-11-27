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
