import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import REPORTS_DIR

class JSONReportExporter:
    """
    Exports complete scan session metadata and findings as pretty-formatted JSON.
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path(REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, session_data: Dict[str, Any], endpoints: List[Dict[str, Any]],
               findings: List[Dict[str, Any]], top_risks: List[Dict[str, Any]] = None) -> str:
        session_id = session_data.get("id", 1)
        file_path = self.output_dir / f"scan_report_{session_id}.json"

        report_payload = {
            "platform": "API Security & Anomaly Platform",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "session_summary": {
                "session_id": session_id,
                "target_url": session_data.get("target_url"),
                "scan_start_time": str(session_data.get("scan_start_time")),
                "overall_risk_score": session_data.get("overall_risk_score", 0.0),
                "overall_severity": session_data.get("overall_severity", "Low"),
                "total_endpoints_found": session_data.get("total_endpoints_found", 0),
                "total_vulnerabilities_found": session_data.get("total_vulnerabilities_found", 0)
            },
            "discovered_endpoints": endpoints,
            "top_risks": top_risks or [],
            "findings_detail": findings
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2, default=str)

        logger.info(f"Exported JSON report to: {file_path}")
        return str(file_path)


if __name__ == "__main__":
    exporter = JSONReportExporter()
    dummy_session = {"id": 99, "target_url": "http://httpbin.org", "overall_risk_score": 47.2, "overall_severity": "Medium"}
    dummy_eps = [{"url": "http://httpbin.org", "method": "GET"}]
    dummy_findings = [{"attack_type": "Security_Misconfiguration", "risk_score": 47.2}]
    json_path = exporter.export(dummy_session, dummy_eps, dummy_findings)
    print(f"\n[+] Exported JSON Report: {json_path}")
