import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import REPORTS_DIR

class HTMLReportExporter:
    """
    Generates a standalone HTML report with inline CSS styling.
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path(REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, session_data: Dict[str, Any], findings: List[Dict[str, Any]],
               top_risks: List[Dict[str, Any]] = None) -> str:
        session_id = session_data.get("id", 1)
        file_path = self.output_dir / f"scan_report_{session_id}.html"

        import html as _html

        top_risks_html = ""
        for i, g in enumerate(top_risks or [], 1):
            vulns = "".join(
                f"<li><strong>{_html.escape(str(v.get('attack_type', '')))}</strong> "
                f"<span class=\"badge {str(v.get('severity', 'low')).lower()}\">{_html.escape(str(v.get('severity', '')))}</span>"
                + (f" <em>{v.get('evidence_count', 1)} evidence samples</em>" if v.get("evidence_count", 1) > 1 else "")
                + "</li>"
                for v in g.get("vulns", []))
            top_risks_html += f"""
            <div class="card" style="margin-bottom:1rem;">
                <div><strong>{i}. {_html.escape(str(g.get('method', '')))} {_html.escape(str(g.get('path', '')))}</strong>
                <span class="badge {str(g.get('severity', 'low')).lower()}">{_html.escape(str(g.get('severity', '')))}</span>
                <span style="color:#94a3b8;font-size:0.85rem;">{_html.escape(str(g.get('finding_status', '')))} · score {round(g.get('score', 0), 1)}</span></div>
                <ul>{vulns}</ul>
                <div style="font-size:0.9rem;color:#cbd5e1;"><strong>Fix first:</strong> {_html.escape(str(g.get('fix_first', '')))}</div>
            </div>
            """
        top_risks_section = ""
        if top_risks_html:
            top_risks_section = f"<h2>Top Risks</h2>{top_risks_html}"

        findings_rows_html = ""
        for f in findings:
            ep_url = f.get("url") or (f.get("endpoint").url if f.get("endpoint") else "Base URL")
            sev_class = str(f.get("severity", "low")).lower()
            findings_rows_html += f"""
            <tr>
                <td><code>{ep_url}</code></td>
                <td>{f.get('attack_type', 'None')}</td>
                <td><span class="badge {sev_class}">{f.get('severity', 'Low')}</span></td>
                <td><strong>{f.get('risk_score', 0.0)}</strong></td>
                <td>{f.get('recommendation', 'N/A')}</td>
            </tr>
            """

        if not findings_rows_html:
            findings_rows_html = "<tr><td colspan='5' style='text-align:center;'>No vulnerabilities or anomalies flagged for this session.</td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Security Report — Session #{session_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 2rem; }}
        h1 {{ color: #38bdf8; font-size: 1.8rem; margin-top: 0; }}
        h2 {{ color: #f8fafc; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; margin-top: 1.5rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
        .card {{ background-color: #0f172a; border: 1px solid #334155; padding: 1rem; border-radius: 6px; }}
        .score {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
        .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
        .badge.low {{ background-color: #166534; color: #4ade80; }}
        .badge.medium {{ background-color: #854d0e; color: #facc15; }}
        .badge.high {{ background-color: #991b1b; color: #f87171; }}
        .badge.critical {{ background-color: #7f1d1d; color: #fca5a5; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; border-bottom: 1px solid #334155; text-align: left; }}
        th {{ background-color: #0f172a; color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
        code {{ background-color: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; color: #38bdf8; }}
        footer {{ margin-top: 2rem; font-size: 0.8rem; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>API Security & Anomaly Inspection Report</h1>
        <p>Target: <code>{session_data.get('target_url')}</code> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>

        <div class="summary-grid">
            <div class="card">
                <div>Overall Risk Score</div>
                <div class="score">{session_data.get('overall_risk_score', 0.0)} / 100</div>
            </div>
            <div class="card">
                <div>Overall Severity</div>
                <div style="margin-top:0.5rem;"><span class="badge {str(session_data.get('overall_severity', 'low')).lower()}">{session_data.get('overall_severity', 'Low')}</span></div>
            </div>
            <div class="card">
                <div>Total Endpoints</div>
                <div class="score">{session_data.get('total_endpoints_found', 0)}</div>
            </div>
            <div class="card">
                <div>Vulnerabilities</div>
                <div class="score">{session_data.get('total_vulnerabilities_found', 0)}</div>
            </div>
        </div>

        {top_risks_section}

        <h2>Appendix: All Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Endpoint</th>
                    <th>Attack Type</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows_html}
            </tbody>
        </table>

        <h2>Detection Layer Methodology</h2>
        <ul>
            <li><strong>Layer 1 (Signature Rules):</strong> Deterministic regex rules for missing security headers, stack traces, and structural attack indicators.</li>
            <li><strong>Layer 2 (ML Anomaly Isolation Forest):</strong> Unsupervised anomaly scoring trained on the defined HTTP telemetry feature schema (17 features).</li>
            <li><strong>Layer 3 (Deep Learning):</strong> Character-level LSTM payload classification + PyTorch Autoencoder reconstruction error analysis.</li>
        </ul>

        <footer>Generated by API Security Platform &copy; 2026</footer>
    </div>
</body>
</html>
"""

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Exported HTML report to: {file_path}")
        return str(file_path)


if __name__ == "__main__":
    exporter = HTMLReportExporter()
    dummy_session = {"id": 99, "target_url": "http://httpbin.org", "overall_risk_score": 47.2, "overall_severity": "Medium", "total_endpoints_found": 1, "total_vulnerabilities_found": 1}
    dummy_findings = [{"url": "http://httpbin.org", "attack_type": "Security_Misconfiguration", "severity": "Medium", "risk_score": 47.2, "recommendation": "Enforce HTTP security headers."}]
    html_path = exporter.export(dummy_session, dummy_findings)
    print(f"\n[+] Exported HTML Report: {html_path}")
