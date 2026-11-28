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


# --- scorer --mode ----------------------------------------------------------
GT_MODED = """items:
  - id: M-01
    template: /api/posts/search
    parameter: q
    category: SQL_Injection
    modes: [vulnerable]
    how_verified: "manual"
    date: 2026-11-27
    added_after_scan: false
  - id: M-02
    template: /api/error
    parameter: null
    category: Verbose_Error_Exposure
    modes: [vulnerable, safe]
    how_verified: "manual"
    date: 2026-11-27
    added_after_scan: false
"""


def test_scorer_mode_filters_ground_truth(tmp_path):
    """Mode-scoped items only score in their mode: a safe-twin run must
    not report phantom TP matches on findings that are false alarms by
    construction (the 2026-11-27 fastapi safe run printed 'TP 4, recall
    44%' against vuln-only ground truth)."""
    gt = _write(tmp_path, "gt.yaml", GT_MODED)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/posts/search?q=x (score=70.0)\n"
        "[Suspected] HIGH Verbose_Error_Exposure :: "
        "http://127.0.0.1:13312/api/error (score=40.0)\n")
    # Vulnerable mode: both items apply.
    report = score(gt, findings, mode="vulnerable")
    assert report["ground_truth_items"] == 2
    assert report["confirmed"]["tp_unique_bugs"] == 1
    assert report["confirmed_plus_suspected"]["tp_unique_bugs"] == 2
    # Safe mode: only the shared item applies; the SQLi finding is an FP.
    report = score(gt, findings, mode="safe")
    assert report["ground_truth_items"] == 1
    assert report["confirmed"]["tp_unique_bugs"] == 0
    assert report["confirmed"]["fp_unique_pairs"] == 1
    assert report["confirmed_plus_suspected"]["tp_unique_bugs"] == 1
    assert report["confirmed_plus_suspected"]["fp_unique_pairs"] == 1
    assert report["missed_bugs"] == []
    # No mode: old behaviour — all items apply.
    report = score(gt, findings)
    assert report["ground_truth_items"] == 2
    assert report["mode"] is None


def test_scorer_safe_mode_with_no_applicable_items(tmp_path):
    """When no ground-truth item applies in the mode, the run scores
    zero items and every finding is an FP — never a phantom recall."""
    gt_vuln_only = """items:
  - id: GT-01
    template: /users/v1/{username}
    parameter: username (path)
    category: SQL_Injection
    modes: [vulnerable]
    how_verified: "manual"
    date: 2026-11-27
    added_after_scan: false
"""
    gt = _write(tmp_path, "gt.yaml", gt_vuln_only)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:5000/users/v1/name1' (score=70.0)\n")
    report = score(gt, findings, mode="safe")
    assert report["ground_truth_items"] == 0
    assert report["confirmed"]["tp_unique_bugs"] == 0
    assert report["confirmed"]["fp_unique_pairs"] == 1
    assert report["confirmed"]["recall"] == 0.0
    assert report["confirmed"]["precision"] == 0.0
    assert report["mode"] == "safe"


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


def _rec(url, parameter, probe_type, mode, telemetry=None):
    return {"endpoint_url": url, "parameter": parameter,
            "probe_type": probe_type, "mode": mode,
            "finding": {"attack_type": None},
            "telemetry": telemetry or {}}


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
             "SQL_Injection_Error", "vulnerable",
             {"status_changed": True}),
        _rec("http://127.0.0.1:5000/users/v1/name1'", "path",
             "SQL_Injection_Error", "secure"),
        _rec("http://127.0.0.1:5000/users/v1/_debug", "",
             "Sensitive_Data_Exposure", "secure",
             {"body_diff_ratio": 0.5}),
        _rec("http://127.0.0.1:5000/users/v1/other", "path",
             "XSS", "vulnerable"),
    ]
    labeled, stats = label(records, gt)
    assert [r["label"] for r in labeled] == [1, 0, 1, 0]
    assert labeled[0]["matched_item"] == "T-01"
    assert labeled[2]["matched_item"] == "T-02"
    assert stats["positive"] == 2 and stats["negative"] == 2
    # probe_effective is a response-based rule, not the verdict: the
    # first and third probes visibly changed the response, the second
    # (secure mode, no error) did not.
    assert [r["probe_effective"] for r in labeled] == [1, 0, 1, 0]
    assert stats["positive_effective"] == 2
    assert stats["positive_not_effective"] == 0
    # VAmPI's modes are one group for splitting.
    assert all(r["group"] == "" for r in labeled)  # no target_app here

# --- needs_auth (2026-11-27) ------------------------------------------------
GT_NEEDS_AUTH = """items:
  - id: T-01
    template: /api/posts/search
    parameter: q
    category: SQL_Injection
    modes: [vulnerable]
    date: "2026-11-27"
needs_auth:
  - id: IDOR-001
    template: /api/posts/{id}
    parameter: id (path)
    category: BOLA_IDOR
    date: "2026-11-27"
"""


def test_scorer_needs_auth_is_neither_tp_nor_fp(tmp_path):
    """A finding on a needs_auth template is neither a TP (not scored)
    nor an FP (the bug exists, the scanner just cannot log in to reach
    it) — it goes in its own bucket and changes no headline number."""
    gt = _write(tmp_path, "gt.yaml", GT_NEEDS_AUTH)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/posts/search?q=x (score=70.0)\n"
        "[Confirmed] CRITICAL BOLA_IDOR :: "
        "http://127.0.0.1:13312/api/posts/123 (score=70.0)\n"
        "[Suspected] HIGH XSS :: "
        "http://127.0.0.1:13312/api/other (score=40.0)\n")
    report = score(gt, findings)
    assert report["ground_truth_items"] == 1
    assert report["confirmed"]["tp_unique_bugs"] == 1
    # Only the /api/other XSS is an FP; the BOLA finding on the
    # needs_auth template is not.
    assert report["confirmed"]["fp_unique_pairs"] == 0
    assert report["confirmed_plus_suspected"]["fp_unique_pairs"] == 1
    assert report["needs_auth_items"] == 1
    assert report["needs_auth_matches"] == [
        "/api/posts/123 :: BOLA_IDOR"]


# --- incidental items (2026-11-28) ----------------------------------------
GT_INCIDENTAL = """items:
  - id: T-01
    template: /api/posts/search
    parameter: q
    category: SQL_Injection
    modes: [vulnerable]
    date: "2026-11-27"
  - id: FA-INC-01
    template: /api/reports/dashboard
    parameter: name
    category: XSS
    modes: [vulnerable, safe]
    incidental: true
    date: "2026-11-28"
"""


def test_scorer_incidental_is_neither_tp_nor_fp(tmp_path):
    """A finding on an incidental item — a real bug the bench's answer
    key does not list, verified with request + response — is neither a
    TP (not a scored item) nor an FP (the bug is real). It goes in its
    own bucket and changes no headline number, in either mode."""
    gt = _write(tmp_path, "gt.yaml", GT_INCIDENTAL)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/posts/search?q=x (score=70.0)\n"
        "[Confirmed] CRITICAL XSS :: "
        "http://127.0.0.1:13312/api/reports/dashboard?name=x (score=70.0)\n"
        "[Suspected] HIGH XSS :: "
        "http://127.0.0.1:13312/api/other (score=40.0)\n")
    report = score(gt, findings, mode="vulnerable")
    assert report["ground_truth_items"] == 1
    assert report["confirmed"]["tp_unique_bugs"] == 1
    # Only the /api/other XSS is an FP; the dashboard XSS is incidental.
    assert report["confirmed"]["fp_unique_pairs"] == 0
    assert report["confirmed_plus_suspected"]["fp_unique_pairs"] == 1
    assert report["incidental_items"] == 1
    assert report["incidental_matches"] == [
        "/api/reports/dashboard :: XSS"]
    # Safe mode: the scored item does not apply, the incidental one
    # still does — the dashboard finding is still neither TP nor FP,
    # but the SQLi finding IS an FP now (that bug does not exist in
    # the safe twin).
    report = score(gt, findings, mode="safe")
    assert report["ground_truth_items"] == 0
    assert report["confirmed"]["tp_unique_bugs"] == 0
    assert report["confirmed"]["fp_unique_pairs"] == 1
    assert report["confirmed_plus_suspected"]["fp_unique_pairs"] == 2
    assert report["incidental_matches"] == [
        "/api/reports/dashboard :: XSS"]


def test_labeler_labels_incidental_pairs_positive(tmp_path):
    """A pair on an incidental item is labeled 1 — the bug is real —
    in BOTH modes, since the reflection exists in both twins."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                           / "evaluation"))
    from label_dataset import label

    gt = _write(tmp_path, "gt.yaml", GT_INCIDENTAL)
    records = [
        _rec("http://127.0.0.1:13312/api/reports/dashboard?name=x",
             "name", "Cross_Site_Scripting", "vulnerable",
             {"payload_reflected": True}),
        _rec("http://127.0.0.1:13312/api/reports/dashboard?name=x",
             "name", "Cross_Site_Scripting", "safe",
             {"payload_reflected": True}),
        _rec("http://127.0.0.1:13312/api/posts/search?q=x", "q",
             "SQL_Injection_Error", "safe"),
    ]
    labeled, stats = label(records, gt)
    assert [r["label"] for r in labeled] == [1, 1, 0]
    assert labeled[0]["matched_item"] == "FA-INC-01"
    assert labeled[1]["matched_item"] == "FA-INC-01"
    assert stats["positive"] == 2 and stats["negative"] == 1


def test_labeler_excludes_needs_auth_pairs(tmp_path):
    """A pair on a needs_auth route is dropped from the labeled output —
    never a positive, never a negative. A different-category probe on
    the same endpoint is still a negative for its own category (the
    endpoint has an IDOR bug, not a SQLi bug)."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                           / "evaluation"))
    from label_dataset import label

    gt = _write(tmp_path, "gt.yaml", GT_NEEDS_AUTH)
    records = [
        _rec("http://127.0.0.1:13312/api/posts/123", "path",
             "BOLA_IDOR", "vulnerable"),
        _rec("http://127.0.0.1:13312/api/posts/123", "path",
             "SQL_Injection_Error", "vulnerable"),
        _rec("http://127.0.0.1:13312/api/posts/search?q=x", "q",
             "SQL_Injection_Error", "vulnerable",
             {"status_changed": True}),
    ]
    labeled, stats = label(records, gt)
    assert len(labeled) == 2
    assert stats["excluded_needs_auth"] == 1
    assert stats["total"] == 2
    assert [r["label"] for r in labeled] == [0, 1]
    assert labeled[1]["matched_item"] == "T-01"


# --- near-misses (2026-11-28) ----------------------------------------------
GT_NEAR_MISS = """items:
  - id: FA-01
    template: /api/posts/search
    parameter: q
    category: SQL_Injection
    modes: [vulnerable]
    date: "2026-11-27"
near_misses:
  - id: FA-NM-01
    template: /api/posts/list
    parameter: q
    category: SQL_Injection
    modes: [vulnerable, safe]
    date: "2026-11-28"
  - id: FA-NM-02
    template: /api/attachments/avatar-download
    parameter: name
    category: Local_File_Inclusion
    modes: [vulnerable, safe]
    date: "2026-11-28"
"""


def test_scorer_near_miss_is_a_false_positive_but_listed_separately(tmp_path):
    """A finding on a near-miss endpoint — bench-documented safe code —
    IS a false positive (it counts in the headline FP), and it is also
    listed in its own bucket so the report can say how many FPs were on
    hard negatives. The real bug on the neighbouring endpoint still
    scores TP; the near-miss never shadows it."""
    gt = _write(tmp_path, "gt.yaml", GT_NEAR_MISS)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/posts/search?q=x (score=70.0)\n"
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/posts/list?q=x (score=70.0)\n"
        "[Suspected] HIGH XSS :: "
        "http://127.0.0.1:13312/api/other (score=40.0)\n")
    report = score(gt, findings, mode="vulnerable")
    assert report["ground_truth_items"] == 1
    assert report["confirmed"]["tp_unique_bugs"] == 1
    # The list-endpoint SQLi is an FP; the /api/other XSS is the other.
    assert report["confirmed"]["fp_unique_pairs"] == 1
    assert report["confirmed_plus_suspected"]["fp_unique_pairs"] == 2
    assert report["near_miss_items"] == 2
    assert report["near_miss_matches"] == [
        "/api/posts/list :: SQL_Injection"]
    # Safe mode: the near-miss still applies (modes include safe), so
    # the list-endpoint finding is still an FP in its bucket — but the
    # search-endpoint finding is an FP too now (that bug does not exist
    # in the safe twin).
    report = score(gt, findings, mode="safe")
    assert report["ground_truth_items"] == 0
    assert report["confirmed"]["fp_unique_pairs"] == 2
    assert report["near_miss_matches"] == [
        "/api/posts/list :: SQL_Injection"]


def test_labeler_labels_near_miss_pairs_negative_with_match(tmp_path):
    """A pair on a near-miss endpoint labels 0 — the code is safe — but
    with matched_item set and near_miss True, so the dataset can tell a
    deliberate hard negative from a default negative. A pair on the
    neighbouring real bug still labels 1."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                           / "evaluation"))
    from label_dataset import label

    gt = _write(tmp_path, "gt.yaml", GT_NEAR_MISS)
    records = [
        _rec("http://127.0.0.1:13312/api/posts/list?q=x", "q",
             "SQL_Injection_Error", "vulnerable"),
        _rec("http://127.0.0.1:13312/api/attachments/avatar-download?name=x",
             "name", "Local_File_Inclusion", "safe"),
        _rec("http://127.0.0.1:13312/api/posts/search?q=x", "q",
             "SQL_Injection_Error", "vulnerable",
             {"status_changed": True}),
        _rec("http://127.0.0.1:13312/api/other", "",
             "SQL_Injection_Error", "vulnerable"),
    ]
    labeled, stats = label(records, gt)
    assert [r["label"] for r in labeled] == [0, 0, 1, 0]
    assert labeled[0]["matched_item"] == "FA-NM-01"
    assert labeled[0]["near_miss"] is True
    assert labeled[1]["matched_item"] == "FA-NM-02"
    assert labeled[1]["near_miss"] is True
    assert labeled[2]["matched_item"] == "FA-01"
    assert labeled[2]["near_miss"] is False
    assert labeled[3]["matched_item"] is None
    assert labeled[3]["near_miss"] is False
    assert stats["positive"] == 1 and stats["negative"] == 3
    assert stats["near_miss_negatives"] == 2

# --- two-part recall (2026-11-27) -------------------------------------------
SURFACE_TWO_PART = """app: test
operations:
  - id: a.search.get
    kind: http
    method: GET
    path: "/api/search"
    reachability: pre-auth
  - id: a.item.get
    kind: http
    method: GET
    path: "/api/items/{id}"
    reachability: pre-auth
  - id: a.admin.get
    kind: http
    method: GET
    path: "/api/admin"
    reachability: user
  - id: a.export.post
    kind: http
    method: POST
    path: "/api/export"
    reachability: pre-auth
"""

GT_TWO_PART = """items:
  - id: T-01
    template: /api/search
    parameter: q
    category: SQL_Injection
    date: "2026-11-27"
  - id: T-02
    template: /api/export
    parameter: null
    category: Command_Injection
    date: "2026-11-27"
"""


def test_scorer_two_part_recall(tmp_path):
    """Recall splits in two: discovery (surface operations found) and
    detection given found (ground-truth items on found endpoints). A
    miss on an undiscovered endpoint is a discovery miss, not a
    detection miss — the php run's 6 misses were all of this kind."""
    gt = _write(tmp_path, "gt.yaml", GT_TWO_PART)
    surf = _write(tmp_path, "surface.yaml", SURFACE_TWO_PART)
    disc = _write(tmp_path, "discovered.txt",
                  "GET /api/search?q=x\nGET /api/items/1\n")
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/search?q=x (score=70.0)\n")
    report = score(gt, findings, surface_path=surf, discovered_path=disc)
    d = report["discovery"]
    assert d["surface_operations"] == 4
    assert d["found_operations"] == 2
    assert d["discovery_recall"] == 0.5
    assert d["pre_auth_operations"] == 3
    assert d["pre_auth_found"] == 2
    assert d["ground_truth_on_found_endpoints"] == 1
    assert d["detected_given_found_confirmed"] == {
        "tp": 1, "total": 1, "recall": 1.0}
    assert d["detected_given_found_any"] == {
        "tp": 1, "total": 1, "recall": 1.0}
    assert d["missed_by_discovery"] == ["T-02"]
    assert d["missed_despite_found"] == []
    assert report["results"][0]["discovered"] is True
    assert report["results"][1]["discovered"] is False
    # A raw dataset JSONL works as the discovered input too.
    disc_jsonl = _write(tmp_path, "discovered.jsonl",
        '{"endpoint_url": "http://127.0.0.1:13312/api/search?q=x", '
        '"http_method": "GET"}\n'
        '{"endpoint_url": "http://127.0.0.1:13312/api/items/1", '
        '"http_method": "GET"}\n')
    report2 = score(gt, findings, surface_path=surf,
                    discovered_path=disc_jsonl)
    assert report2["discovery"] == d


def test_scorer_without_surface_is_unchanged(tmp_path):
    """Without --surface/--discovered the report has no discovery block
    and the old numbers are untouched."""
    gt = _write(tmp_path, "gt.yaml", GT_TWO_PART)
    findings = _write(tmp_path, "findings.txt",
        "[Confirmed] CRITICAL SQL_Injection :: "
        "http://127.0.0.1:13312/api/search?q=x (score=70.0)\n")
    report = score(gt, findings)
    assert report["discovery"] is None
    assert report["confirmed"]["tp_unique_bugs"] == 1
    assert report["confirmed"]["recall"] == 0.5

# --- FA-06 regression (2026-11-27) ------------------------------------------
# The fastapi ground truth originally listed FA-06 (LFI on
# /api/attachments/download) with parameter 'filename' — misread from the
# answer key's prose ("user filename"). The key's match.params, the app's
# OpenAPI spec and the scan all say 'name'. With 'filename' the labeler
# gave the Confirmed LFI +0: a false negative in the training data.
# These tests pin the real file so the error cannot return silently.


def test_fa06_ground_truth_parameter_is_name():
    """FA-06 must name the parameter the answer key and the app use:
    'name'. A mapping error here silently turns a Confirmed LFI into a
    labeling false negative."""
    import yaml
    gt_path = (Path(__file__).resolve().parent.parent
               / "evaluation" / "fastapi-ground-truth.yaml")
    gt = yaml.safe_load(gt_path.read_text())
    fa06 = next(i for i in gt["items"] if i["id"] == "FA-06")
    assert fa06["template"] == "/api/attachments/download"
    assert fa06["parameter"] == "name"
    assert fa06["category"] == "Local_File_Inclusion"


def test_labeler_matches_fa06_on_name_not_filename():
    """The labeler joins on the parameter: an LFI probe bound to 'name'
    on /api/attachments/download is FA-06 (label 1); the same probe
    bound to 'filename' matches nothing (label 0) — the exact failure
    the pre-fix ground truth produced."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                           / "evaluation"))
    from label_dataset import label

    gt_path = (Path(__file__).resolve().parent.parent
               / "evaluation" / "fastapi-ground-truth.yaml")
    records = [
        _rec("http://127.0.0.1:13312/api/attachments/download?name=x",
             "name", "Local_File_Inclusion", "vulnerable",
             {"status_changed": True}),
        _rec("http://127.0.0.1:13312/api/attachments/download?filename=x",
             "filename", "Local_File_Inclusion", "vulnerable",
             {"status_changed": True}),
    ]
    labeled, stats = label(records, str(gt_path))
    assert [r["label"] for r in labeled] == [1, 0]
    assert labeled[0]["matched_item"] == "FA-06"
    assert stats["positive"] == 1 and stats["negative"] == 1


def test_dataset_card_summarize_counts():
    from dataset_card import summarize

    records = [
        {"label": 1, "probe_effective": True, "near_miss": False,
         "category": "XSS", "probe_type": "Cross_Site_Scripting"},
        {"label": 1, "probe_effective": False, "near_miss": False,
         "category": "SQL_Injection", "probe_type": "SQL_Injection_GET"},
        {"label": 0, "probe_effective": False, "near_miss": True,
         "category": "SQL_Injection", "probe_type": "SQL_Injection_GET"},
        {"label": 0, "probe_effective": False, "near_miss": False,
         "category": "XSS", "probe_type": "Cross_Site_Scripting"},
    ]
    s = summarize(records)
    assert s["pairs"] == 4
    assert s["positive"] == 2
    assert s["positive_effective"] == 1
    assert s["negative"] == 2
    assert s["near_miss_negatives"] == 1
    assert s["by_category"]["XSS"] == {"positive": 1, "negative": 1}
    assert s["by_category"]["SQL_Injection"] == {"positive": 1, "negative": 1}
