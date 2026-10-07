"""Group scan findings by endpoint for the results page and exports.

Raw findings are per-check (one row per SQLi/XSS/BOLA probe...), so the
same endpoint repeats many times. This module deduplicates them into
per-endpoint groups so the UI can show "Top Risks" instead of a wall of
repeated rows. Stored findings are untouched — grouping is a presentation
concern computed on demand, shared by the results page and all exports.
"""
from urllib.parse import urlsplit

# Endpoint score = severity weight + status weight, taken from the group's
# strongest single vulnerability. Confirmed findings outrank suspected ones
# at the same severity.
SEVERITY_WEIGHTS = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
STATUS_WEIGHTS = {"Confirmed": 3, "Suspected": 1, "Informational": 0}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
STATUS_ORDER = {"Confirmed": 0, "Suspected": 1, "Informational": 2}

TOP_RISKS_COUNT = 6

# The ONE scoring rule for the whole app. Results page, history, dashboard,
# compare and exports all derive their numbers from this function, so the
# counts can never disagree again.
#
# Rule:
# - A finding counts as a vulnerability when its finding_status is Confirmed
#   or Suspected. Informational findings are notes, not vulnerabilities.
# - "vulnerabilities" dedupes by (method, path, attack_type), the same key
#   the results page groups by.
# - "risk_score" is the highest risk_score across all findings (unchanged).
# - Severity follows the detector thresholds, with the standing proof cap:
#   CRITICAL requires at least one Confirmed finding.
VULN_STATUSES = frozenset({"Confirmed", "Suspected"})


def _classify_score(score: float) -> str:
    if score >= 70.0:
        return "CRITICAL"
    if score >= 40.0:
        return "HIGH"
    if score >= 15.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def summarize_findings(finding_dicts):
    """Canonical session numbers from a list of finding dicts.

    Each dict may carry: url, method, attack_type, severity, finding_status,
    risk_score. Returns {"vulnerabilities", "vulnerable_endpoints",
    "critical_endpoints", "confirmed", "suspected", "informational",
    "risk_score", "severity"}.
    """
    vulns = {}          # (method, path, attack_type) -> True
    vuln_endpoints = set()
    critical_endpoints = set()
    confirmed = suspected = informational = 0
    top_score = 0.0
    for f in finding_dicts or []:
        status = f.get("finding_status") or "Informational"
        if status == "Confirmed":
            confirmed += 1
        elif status == "Suspected":
            suspected += 1
        else:
            informational += 1
        score = float(f.get("risk_score") or 0.0)
        if score > top_score:
            top_score = score
        if status in VULN_STATUSES:
            method = (f.get("method") or "GET").upper()
            path = _split_path(f.get("url") or "")
            vulns[(method, path, f.get("attack_type") or "None")] = True
            vuln_endpoints.add((method, path))
            if (f.get("severity") or "").lower() == "critical":
                critical_endpoints.add((method, path))
    severity = _classify_score(top_score)
    if confirmed == 0 and severity == "CRITICAL":
        severity = "HIGH"
    return {
        "vulnerabilities": len(vulns),
        "vulnerable_endpoints": len(vuln_endpoints),
        "critical_endpoints": len(critical_endpoints),
        "confirmed": confirmed,
        "suspected": suspected,
        "informational": informational,
        "risk_score": round(top_score, 2),
        "severity": severity,
    }



def _split_path(url):
    """Path without query string / fragment — the grouping key for endpoints."""
    try:
        return urlsplit(url or "").path or "/"
    except Exception:
        return "/"


def _fix_first_line(group):
    top = group["vulns"][0] if group["vulns"] else None
    if top and top["recommendation"]:
        first = top["recommendation"].split(". ")[0].strip()
        return first[:157] + "..." if len(first) > 160 else first
    if top:
        return (f"Review {top['attack_type']} on {group['method']} "
                f"{group['path']} — highest risk on this endpoint.")
    return ""


def group_findings(findings):
    """Deduplicate + group finding dicts by endpoint.

    Each finding dict may carry: id, url, method, attack_type, severity,
    finding_status, risk_score, recommendation.

    Returns {"groups": [...], "summary": {...}} with groups sorted by
    score descending. Each group holds its merged vulns (one per
    attack_type, with evidence_count), its score/severity/status, and a
    one-line "fix this first" recommendation.
    """
    vulns = {}  # (method, path, attack_type) -> merged vuln
    for f in findings or []:
        url = f.get("url") or "Base URL"
        method = (f.get("method") or "GET").upper()
        path = _split_path(url)
        attack = f.get("attack_type") or "None"
        key = (method, path, attack)
        if key not in vulns:
            vulns[key] = {
                "method": method,
                "path": path,
                "url": url,
                "attack_type": attack,
                "severity": f.get("severity") or "Low",
                "finding_status": f.get("finding_status") or "Informational",
                "risk_score": float(f.get("risk_score") or 0.0),
                "recommendation": f.get("recommendation") or "",
                "evidence_count": 0,
                "finding_ids": [],
                "top_finding_id": f.get("id"),
            }
        v = vulns[key]
        v["evidence_count"] += 1
        if f.get("id") is not None:
            v["finding_ids"].append(f.get("id"))
        risk = float(f.get("risk_score") or 0.0)
        if risk > v["risk_score"]:
            v["risk_score"] = risk
            v["top_finding_id"] = f.get("id")
            if f.get("recommendation"):
                v["recommendation"] = f.get("recommendation")
        if SEVERITY_ORDER.get(f.get("severity"), 3) < SEVERITY_ORDER.get(v["severity"], 3):
            v["severity"] = f.get("severity")
        if STATUS_ORDER.get(f.get("finding_status"), 2) < STATUS_ORDER.get(v["finding_status"], 2):
            v["finding_status"] = f.get("finding_status")

    groups = {}  # (method, path) -> endpoint group
    for v in vulns.values():
        gkey = (v["method"], v["path"])
        if gkey not in groups:
            groups[gkey] = {
                "method": v["method"],
                "path": v["path"],
                "url": v["url"],
                "vulns": [],
                "score": 0.0,
                "severity": "Low",
                "finding_status": "Informational",
                "max_risk": 0.0,
            }
        g = groups[gkey]
        g["vulns"].append(v)
        score = (SEVERITY_WEIGHTS.get(v["severity"], 1)
                 + STATUS_WEIGHTS.get(v["finding_status"], 0))
        v["score"] = score
        g["score"] = max(g["score"], score)
        if SEVERITY_ORDER.get(v["severity"], 3) < SEVERITY_ORDER.get(g["severity"], 3):
            g["severity"] = v["severity"]
        if STATUS_ORDER.get(v["finding_status"], 2) < STATUS_ORDER.get(g["finding_status"], 2):
            g["finding_status"] = v["finding_status"]
        g["max_risk"] = max(g["max_risk"], v["risk_score"])

    result = list(groups.values())
    for g in result:
        g["vulns"].sort(key=lambda v: (-v["score"], -v["risk_score"]))
        g["fix_first"] = _fix_first_line(g)
    result.sort(key=lambda g: (-g["score"], -g["max_risk"], g["path"]))

    summary = {
        "endpoint_groups": len(result),
        "vulnerable_endpoints": len(result),
        "critical_endpoints": sum(1 for g in result if g["severity"] == "Critical"),
        "confirmed_endpoints": sum(1 for g in result if g["finding_status"] == "Confirmed"),
    }
    return {"groups": result, "summary": summary}
