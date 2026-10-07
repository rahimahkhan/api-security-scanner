"""Deduplication + endpoint grouping + scoring for the results page/exports."""
from dashboard.results_grouping import group_findings, TOP_RISKS_COUNT


def _f(id, url="https://api.example.com/users", method="GET",
       attack="SQLi", severity="High", status="Suspected", risk=50.0,
       rec="Use parameterized queries."):
    return {"id": id, "url": url, "method": method, "attack_type": attack,
            "severity": severity, "finding_status": status,
            "risk_score": risk, "recommendation": rec}


def test_dedup_merges_same_check_into_one_vuln():
    findings = [_f(i, risk=40.0 + i) for i in range(5)]
    grouped = group_findings(findings)
    assert len(grouped["groups"]) == 1
    g = grouped["groups"][0]
    assert len(g["vulns"]) == 1
    v = g["vulns"][0]
    assert v["evidence_count"] == 5
    assert v["risk_score"] == 44.0  # strongest kept
    assert sorted(v["finding_ids"]) == [0, 1, 2, 3, 4]


def test_groups_by_endpoint():
    findings = [_f(1, url="https://api.example.com/users", attack="SQLi"),
                _f(2, url="https://api.example.com/users", attack="XSS"),
                _f(3, url="https://api.example.com/orders", attack="SQLi")]
    grouped = group_findings(findings)
    assert len(grouped["groups"]) == 2
    users = [g for g in grouped["groups"] if g["path"] == "/users"][0]
    assert len(users["vulns"]) == 2


def test_query_strings_group_into_same_endpoint():
    findings = [_f(1, url="https://api.example.com/search?q=a"),
                _f(2, url="https://api.example.com/search?q=b")]
    grouped = group_findings(findings)
    assert len(grouped["groups"]) == 1
    assert grouped["groups"][0]["path"] == "/search"


def test_method_distinguishes_groups():
    findings = [_f(1, method="GET"), _f(2, method="POST")]
    grouped = group_findings(findings)
    assert len(grouped["groups"]) == 2


def test_scoring_confirmed_outranks_suspected():
    findings = [
        _f(1, url="https://api.example.com/a", severity="High",
           status="Suspected", risk=80.0),   # 7 + 1 = 8
        _f(2, url="https://api.example.com/b", severity="High",
           status="Confirmed", risk=70.0),   # 7 + 3 = 10
        _f(3, url="https://api.example.com/c", severity="Critical",
           status="Suspected", risk=60.0),   # 10 + 1 = 11
    ]
    groups = group_findings(findings)["groups"]
    assert [g["path"] for g in groups] == ["/c", "/b", "/a"]
    assert [g["score"] for g in groups] == [11, 10, 8]


def test_group_takes_highest_severity_and_status():
    findings = [_f(1, severity="Low", status="Informational"),
                _f(2, severity="Critical", status="Suspected")]
    g = group_findings(findings)["groups"][0]
    assert g["severity"] == "Critical"
    assert g["finding_status"] == "Suspected"
    assert g["score"] == 11


def test_fix_first_uses_top_recommendation():
    findings = [_f(1, rec="Use parameterized queries. Never concatenate input.")]
    g = group_findings(findings)["groups"][0]
    assert g["fix_first"] == "Use parameterized queries"


def test_empty_findings():
    grouped = group_findings([])
    assert grouped["groups"] == []
    assert grouped["summary"]["vulnerable_endpoints"] == 0


def test_summary_counts():
    findings = [_f(1, url="https://api.example.com/a", severity="Critical",
                    status="Confirmed"),
                _f(2, url="https://api.example.com/b", severity="High")]
    summary = group_findings(findings)["summary"]
    assert summary["vulnerable_endpoints"] == 2
    assert summary["critical_endpoints"] == 1
    assert summary["confirmed_endpoints"] == 1


def test_top_risks_slice_is_six():
    assert TOP_RISKS_COUNT == 6
