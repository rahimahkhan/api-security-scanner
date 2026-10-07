import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import REPORTS_DIR

class PDFReportGenerator:
    """
    Generates a professional PDF report using reportlab for API security scan sessions.
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path(REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, session_data: Dict[str, Any], findings: List[Dict[str, Any]],
                 top_risks: List[Dict[str, Any]] = None) -> str:
        session_id = session_data.get("id", 1)
        file_path = self.output_dir / f"scan_report_{session_id}.pdf"

        doc = SimpleDocTemplate(
            str(file_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=12
        )
        h2_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155")
        )

        story = []

        # Header Title
        story.append(Paragraph("API Security & Anomaly Inspection Report", title_style))
        story.append(Spacer(1, 10))

        # Cover Summary Table
        summary_data = [
            [Paragraph("<b>Target Base URL:</b>", body_style), Paragraph(str(session_data.get("target_url", "")), body_style)],
            [Paragraph("<b>Session ID:</b>", body_style), Paragraph(f"#{session_id}", body_style)],
            [Paragraph("<b>Scan Date:</b>", body_style), Paragraph(str(session_data.get("scan_start_time", datetime.utcnow())), body_style)],
            [Paragraph("<b>Overall Risk Score:</b>", body_style), Paragraph(f"{session_data.get('overall_risk_score', 0.0)} / 100", body_style)],
            [Paragraph("<b>Overall Severity:</b>", body_style), Paragraph(str(session_data.get("overall_severity", "Low")), body_style)],
            [Paragraph("<b>Total Endpoints Tested:</b>", body_style), Paragraph(str(session_data.get("total_endpoints_found", 0)), body_style)],
            [Paragraph("<b>Vulnerabilities Found:</b>", body_style), Paragraph(str(session_data.get("total_vulnerabilities_found", 0)), body_style)],
        ]

        summary_table = Table(summary_data, colWidths=[160, 380])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 15))

        # Executive Summary Section
        story.append(Paragraph("Executive Summary", h2_style))
        exec_summary_text = (
            f"This inspection report summarizes telemetry security findings for <b>{session_data.get('target_url')}</b>. "
            f"The scanner evaluated target endpoints across three independent detection layers: "
            f"Layer 1 (Signature Rules), Layer 2 (Isolation Forest ML Anomaly), and Layer 3 (PyTorch LSTM + Autoencoder DL). "
            f"Overall risk severity is assessed as <b>{session_data.get('overall_severity')}</b> with a composite score of <b>{session_data.get('overall_risk_score')}/100</b>."
        )
        story.append(Paragraph(exec_summary_text, body_style))
        story.append(Spacer(1, 15))

        # Top Risks (page 1) — grouped, deduplicated, highest score first
        if top_risks:
            from xml.sax.saxutils import escape as _xml_escape
            story.append(Paragraph("Top Risks", h2_style))
            for i, g in enumerate(top_risks, 1):
                vuln_names = ", ".join(
                    f"{v['attack_type']} ({v['severity']}"
                    + (f", {v['evidence_count']} samples" if v.get("evidence_count", 1) > 1 else "")
                    + ")"
                    for v in g.get("vulns", []))
                fix = g.get("fix_first") or ""
                story.append(Paragraph(
                    f"<b>{i}. {_xml_escape(str(g.get('method', '')))} "
                    f"{_xml_escape(str(g.get('path', '')))}</b> "
                    f"— {_xml_escape(str(g.get('severity', '')))} / "
                    f"{_xml_escape(str(g.get('finding_status', '')))} "
                    f"(score {round(g.get('score', 0), 1)})<br/>"
                    f"Vulnerabilities: {_xml_escape(vuln_names)}<br/>"
                    f"<i>Fix first: {_xml_escape(fix)}</i>",
                    body_style))
                story.append(Spacer(1, 8))

        # Findings Detail Table (appendix)
        story.append(Paragraph("Appendix: Full Findings Detail", h2_style))
        
        table_headers = ["Endpoint", "Attack Type", "Severity", "Score", "Recommendation"]
        table_rows = [[Paragraph(f"<b>{h}</b>", body_style) for h in table_headers]]

        for f in findings:
            ep_url = f.get("url") or (f.get("endpoint").url if f.get("endpoint") else "Base URL")
            row = [
                Paragraph(str(ep_url), body_style),
                Paragraph(str(f.get("attack_type", "None")), body_style),
                Paragraph(str(f.get("severity", "Low")), body_style),
                Paragraph(str(f.get("risk_score", 0.0)), body_style),
                Paragraph(str(f.get("recommendation", "N/A")), body_style)
            ]
            table_rows.append(row)

        if len(table_rows) == 1:
            table_rows.append([Paragraph("No vulnerabilities or anomalies flagged.", body_style)] + [Paragraph("", body_style)]*4)

        findings_table = Table(table_rows, colWidths=[120, 90, 60, 50, 220])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 15))

        # Methodology Section
        story.append(Paragraph("Detection Methodology", h2_style))
        methodology_text = (
            "1. <b>Layer 1 (Signature Engine):</b> Performs deterministic regex matching on URLs, parameters, headers, and responses.<br/>"
            "2. <b>Layer 2 (Machine Learning):</b> Analyzes the defined HTTP telemetry feature schema (17 features) using an Isolation Forest model trained on HTTP CSIC datasets.<br/>"
            "3. <b>Layer 3 (Deep Learning):</b> Combines character-level LSTM sequence classification with PyTorch Autoencoder feature reconstruction error benchmarking."
        )
        story.append(Paragraph(methodology_text, body_style))

        # Build PDF Document
        doc.build(story)
        logger.info(f"Generated PDF report at: {file_path}")
        return str(file_path)


if __name__ == "__main__":
    generator = PDFReportGenerator()
    dummy_session = {"id": 99, "target_url": "http://httpbin.org", "overall_risk_score": 47.2, "overall_severity": "Medium", "total_endpoints_found": 1, "total_vulnerabilities_found": 1}
    dummy_findings = [{"url": "http://httpbin.org", "attack_type": "Security_Misconfiguration", "severity": "Medium", "risk_score": 47.2, "recommendation": "Enforce HTTP security headers."}]
    pdf_path = generator.generate(dummy_session, dummy_findings)
    print(f"\n[+] Generated PDF Report: {pdf_path}")
