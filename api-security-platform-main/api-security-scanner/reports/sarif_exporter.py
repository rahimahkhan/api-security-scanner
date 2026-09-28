"""SARIF 2.1.0 export for machine-readable CI security findings.

This is an independent implementation inspired by the structured reporting and
SARIF support documented by the Apache-2.0-licensed Strix project. It does not
copy Strix source code.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.logging_config import logger
from config.settings import REPORTS_DIR


_SEVERITY_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
    "info": "note",
}


def _rule_id(attack_type: str) -> str:
    normalized = "-".join((attack_type or "unknown").lower().split())
    normalized = normalized.replace("_", "-")
    return f"api-security/{normalized or 'unknown'}"


def _fingerprint(finding: Dict[str, Any]) -> str:
    identity = "|".join(
        str(finding.get(key, ""))
        for key in ("url", "method", "attack_type", "request_payload")
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def build_sarif_document(
    session_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    *,
    tool_version: str = "0.1.0",
) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        attack_type = str(finding.get("attack_type") or "Unknown")
        rule_id = _rule_id(attack_type)
        status = str(finding.get("finding_status") or "Informational")
        severity = str(finding.get("severity") or "Low")
        proof = str(finding.get("signature_triggered") or "")
        recommendation = str(finding.get("recommendation") or "")
        endpoint = str(finding.get("url") or session_data.get("target_url") or "")
        method = str(finding.get("method") or "GET").upper()

        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": attack_type,
                "shortDescription": {"text": attack_type.replace("_", " ")},
                "helpUri": "https://owasp.org/API-Security/",
                "properties": {"category": attack_type},
            },
        )

        message_parts = [f"{status} {attack_type} on {method} {endpoint}"]
        if proof:
            message_parts.append(f"Proof/evidence: {proof}")
        if recommendation:
            message_parts.append(f"Recommendation: {recommendation}")

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_LEVELS.get(severity.lower(), "warning"),
            "message": {"text": " ".join(message_parts)},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": f"{method} {endpoint}",
                            "kind": "endpoint",
                        }
                    ]
                }
            ],
            "partialFingerprints": {"apiSecurityIdentity": _fingerprint(finding)},
            "properties": {
                "finding_status": status,
                "confirmed": status.lower() == "confirmed",
                "severity": severity,
                "risk_score": finding.get("risk_score", 0.0),
                "response_status": finding.get("response_status"),
                "response_size": finding.get("response_size"),
                "response_time": finding.get("response_time"),
                "request_payload": finding.get("request_payload", ""),
            },
        }
        results.append(result)

    target = session_data.get("target_url") or ""
    run = {
        "tool": {
            "driver": {
                "name": "API Security & Anomaly Platform",
                "version": tool_version,
                "informationUri": "https://github.com/rahimahkhan/api-security-scanner",
                "rules": list(rules.values()),
            }
        },
        "automationDetails": {"id": f"api-security/session-{session_data.get('id', 'unknown')}"},
        "invocations": [
            {
                "executionSuccessful": True,
                "properties": {
                    "target_url": target,
                    "overall_risk_score": session_data.get("overall_risk_score", 0.0),
                    "overall_severity": session_data.get("overall_severity", "Low"),
                    "total_endpoints_found": session_data.get("total_endpoints_found", 0),
                    "total_vulnerabilities_found": session_data.get("total_vulnerabilities_found", 0),
                },
            }
        ],
        "results": results,
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
        "properties": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "confirmed_results": sum(
                1 for finding in findings if str(finding.get("finding_status", "")).lower() == "confirmed"
            ),
        },
    }


class SARIFReportExporter:
    """Export findings to SARIF 2.1.0 for CI and security tooling."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else Path(REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        session_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_path: Optional[str] = None,
    ) -> str:
        path = Path(output_path) if output_path else self.output_dir / f"scan_report_{session_data.get('id', 1)}.sarif"
        path.parent.mkdir(parents=True, exist_ok=True)
        document = build_sarif_document(session_data, findings)
        temporary = path.with_name(f".{path.name}.tmp")
        try:
            temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        logger.info("Exported SARIF report to: %s", path)
        return str(path)
