import os
import sys
import secrets
import threading
from functools import wraps
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, abort, current_app

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import (
    DASHBOARD_AUTH_ENABLED,
    DASHBOARD_ADMIN_USER,
    DASHBOARD_ADMIN_PASSWORD,
    CSRF_ENABLED,
    APP_VERSION,
)
from sqlalchemy.orm import joinedload
from database.db import (
    save_scan_session, save_endpoint, save_finding, complete_scan_session,
    fail_scan_session,
    get_all_sessions, get_session_findings, get_finding_by_id, delete_session, SessionLocal
)
from database.models import ScanSession, Finding, Endpoint
from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.signature import SignatureDetector
from detection.ml_model import MLAnomalyDetector
from detection.deep_learning import DeepLearningDetector
from detection.risk_scorer import RiskScorer
from main import run_pipeline, validate_target_url

dashboard_bp = Blueprint("dashboard", __name__)


def _scan_worker(target_url: str, session_id: int) -> None:
    """Background thread entry point: run the pipeline against the pre-created session."""
    try:
        run_pipeline(target_url, return_session_id=True, session_id=session_id)
    except Exception as exc:  # never let the thread die silently
        logger.error(f"Background scan {session_id} crashed: {exc}")
        try:
            fail_scan_session(session_id, str(exc))
        except Exception:
            pass


def _launch_background_scan(target_url: str) -> int:
    """Create the session row immediately and run the scan in a daemon thread.

    Returns the session id at once so HTTP clients never block on (or time
    out during) a long scan.
    """
    session_obj = save_scan_session(target_url=target_url, status="running")
    thread = threading.Thread(
        target=_scan_worker,
        args=(target_url, session_obj.id),
        daemon=True,
        name=f"scan-{session_obj.id}",
    )
    thread.start()
    logger.info(f"Launched background scan {session_obj.id} for {target_url}")
    return session_obj.id


def get_or_create_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def is_auth_enabled() -> bool:
    return current_app.config.get("DASHBOARD_AUTH_ENABLED", DASHBOARD_AUTH_ENABLED)


def is_csrf_enabled() -> bool:
    if current_app.config.get("TESTING") and "CSRF_ENABLED" not in current_app.config:
        return False
    return current_app.config.get("CSRF_ENABLED", CSRF_ENABLED)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_auth_enabled() and not session.get("authenticated"):
            return redirect(url_for("dashboard.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@dashboard_bp.context_processor
def inject_globals():
    return dict(
        recent_sessions=get_all_sessions()[:5],
        csrf_token=get_or_create_csrf_token,
        auth_enabled=is_auth_enabled(),
        is_authenticated=bool(session.get("authenticated")),
        app_version=APP_VERSION,
    )


@dashboard_bp.before_request
def validate_csrf():
    get_or_create_csrf_token()
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        if not request.path.startswith("/api/"):
            if is_csrf_enabled():
                submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
                expected_token = session.get("csrf_token")
                if not submitted_token or not expected_token or not secrets.compare_digest(str(submitted_token), str(expected_token)):
                    abort(400, description="CSRF token missing or invalid.")


@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("dashboard.index"))
    error = None
    next_url = request.args.get("next") or request.form.get("next") or url_for("dashboard.index")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        admin_user = current_app.config.get("DASHBOARD_ADMIN_USER", DASHBOARD_ADMIN_USER)
        admin_pass = current_app.config.get("DASHBOARD_ADMIN_PASSWORD", DASHBOARD_ADMIN_PASSWORD)
        if username == admin_user and password == admin_pass:
            session["authenticated"] = True
            session["user"] = username
            return redirect(next_url)
        error = "Invalid username or password"
    return render_template("login.html", error=error, next_url=next_url)


@dashboard_bp.route("/logout")
def logout():
    session.pop("authenticated", None)
    session.pop("user", None)
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/")
@login_required
def index():
    recent_sessions = get_all_sessions()[:5]
    return render_template("index.html", recent_sessions=recent_sessions)


@dashboard_bp.route("/scan", methods=["POST"])
@login_required
def start_scan():
    target_url = request.form.get("target_url")
    if not target_url:
        return redirect(url_for("dashboard.index"))

    valid, normalized_or_reason = validate_target_url(target_url)
    if not valid:
        return f"Invalid target URL: {normalized_or_reason}", 400

    # Scans run in the background; the results page polls until completion.
    session_id = _launch_background_scan(normalized_or_reason)
    return redirect(url_for("dashboard.results", session_id=session_id))

@dashboard_bp.route("/results/<int:session_id>")
@login_required
def results(session_id):
    db = SessionLocal()
    try:
        session_data = db.query(ScanSession).options(joinedload(ScanSession.endpoints), joinedload(ScanSession.findings)).filter(ScanSession.id == session_id).first()
        if not session_data:
            return "Session not found", 404

        findings = get_session_findings(session_id)
        
        # Categorize stats for Chart.js
        severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        attack_counts = {}

        for f in findings:
            sev = f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            att = f.attack_type
            attack_counts[att] = attack_counts.get(att, 0) + 1

        return render_template(
            "results.html",
            session_data=session_data,
            findings=findings,
            severity_counts=severity_counts,
            attack_counts=attack_counts
        )
    finally:
        db.close()

@dashboard_bp.route("/history")
@login_required
def history():
    sessions = get_all_sessions()
    return render_template("history.html", sessions=sessions)

@dashboard_bp.route("/finding/<int:finding_id>")
@login_required
def finding_detail(finding_id):
    finding = get_finding_by_id(finding_id)
    if finding:
        current_app.logger.info(
            "Finding %s scores: risk_score=%r, ml_score=%r, lstm_score=%r, autoencoder_score=%r",
            finding.id,
            finding.risk_score,
            finding.ml_score,
            finding.lstm_score,
            finding.autoencoder_score,
        )
    return render_template("report.html", finding=finding)

@dashboard_bp.route("/export/<int:session_id>")
@login_required
def export_report(session_id):
    fmt = request.args.get("format", "pdf").lower()
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if not session_obj:
            return "Session not found", 404
        
        session_data = {
            "id": session_obj.id,
            "target_url": session_obj.target_url,
            "scan_start_time": session_obj.scan_start_time,
            "overall_risk_score": session_obj.overall_risk_score,
            "overall_severity": session_obj.overall_severity,
            "total_endpoints_found": session_obj.total_endpoints_found,
            "total_vulnerabilities_found": session_obj.total_vulnerabilities_found
        }

        endpoints_list = [{"url": ep.url, "method": ep.method} for ep in session_obj.endpoints]
        findings = get_session_findings(session_id)
        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "url": f.endpoint.url if f.endpoint else session_obj.target_url,
                "method": f.endpoint.method if f.endpoint else "GET",
                "attack_type": f.attack_type,
                "finding_status": f.finding_status,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "signature_triggered": f.signature_triggered,
                "ml_score": f.ml_score,
                "lstm_score": f.lstm_score,
                "autoencoder_score": f.autoencoder_score,
                "recommendation": f.recommendation,
                "response_status": f.response_status,
                "response_size": f.response_size,
                "response_time": f.response_time
            })

        from reports.pdf_generator import PDFReportGenerator
        from reports.json_exporter import JSONReportExporter
        from reports.html_exporter import HTMLReportExporter
        from reports.sarif_exporter import SARIFReportExporter
        from flask import send_file

        if fmt == "json":
            exporter = JSONReportExporter()
            out_file = exporter.export(session_data, endpoints_list, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.json")
        elif fmt == "html":
            exporter = HTMLReportExporter()
            out_file = exporter.export(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.html")
        elif fmt == "sarif":
            exporter = SARIFReportExporter()
            out_file = exporter.export(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.sarif")
        else:
            generator = PDFReportGenerator()
            out_file = generator.generate(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.pdf")

    finally:
        db.close()

@dashboard_bp.route("/delete_scan/<int:session_id>", methods=["POST"])
@login_required
def delete_scan(session_id):
    delete_session(session_id)
    return redirect(url_for("dashboard.history"))

# ---------------------------------------------------------
# REST API Endpoints for Programmatic Client Access
# ---------------------------------------------------------

@dashboard_bp.route("/api/sessions", methods=["GET"])
def api_list_sessions():
    sessions = get_all_sessions()
    sessions_data = []
    for s in sessions:
        sessions_data.append({
            "id": s.id,
            "target_url": s.target_url,
            "scan_start_time": s.scan_start_time.isoformat() if s.scan_start_time else None,
            "scan_end_time": s.scan_end_time.isoformat() if s.scan_end_time else None,
            "overall_risk_score": s.overall_risk_score,
            "overall_severity": s.overall_severity,
            "total_endpoints_found": s.total_endpoints_found,
            "total_vulnerabilities_found": s.total_vulnerabilities_found
        })
    return jsonify({"status": "success", "sessions": sessions_data}), 200


@dashboard_bp.route("/api/sessions/<int:session_id>", methods=["GET"])
def api_get_session(session_id):
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if not session_obj:
            return jsonify({"status": "error", "message": "Session not found"}), 404

        findings = get_session_findings(session_id)
        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "url": f.endpoint.url if f.endpoint else session_obj.target_url,
                "attack_type": f.attack_type,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "finding_status": f.finding_status,
                "signature_triggered": f.signature_triggered,
                "ml_score": f.ml_score,
                "lstm_score": f.lstm_score,
                "autoencoder_score": f.autoencoder_score,
                "recommendation": f.recommendation,
                "response_status": f.response_status,
                "response_size": f.response_size,
                "response_time": f.response_time
            })

        endpoints_data = [{"url": ep.url, "method": ep.method} for ep in session_obj.endpoints]

        return jsonify({
            "status": "success",
            "session": {
                "id": session_obj.id,
                "target_url": session_obj.target_url,
                "scan_start_time": session_obj.scan_start_time.isoformat() if session_obj.scan_start_time else None,
                "scan_end_time": session_obj.scan_end_time.isoformat() if session_obj.scan_end_time else None,
                "scan_status": getattr(session_obj, "status", "complete"),
                "overall_risk_score": session_obj.overall_risk_score,
                "overall_severity": session_obj.overall_severity,
                "total_endpoints_found": session_obj.total_endpoints_found,
                "total_vulnerabilities_found": session_obj.total_vulnerabilities_found
            },
            "endpoints": endpoints_data,
            "findings": findings_data
        }), 200
    finally:
        db.close()


@dashboard_bp.route("/api/sessions/<int:session_id>", methods=["DELETE"])
def api_delete_session(session_id):
    success = delete_session(session_id)
    if success:
        return jsonify({"status": "success", "message": f"Session {session_id} deleted"}), 200
    return jsonify({"status": "error", "message": "Session not found"}), 404


@dashboard_bp.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    req_json = request.get_json(silent=True) or {}
    target_url = req_json.get("target_url") or request.form.get("target_url")
    if not target_url:
        return jsonify({"status": "error", "message": "target_url is required"}), 400

    valid, normalized_or_reason = validate_target_url(target_url)
    if not valid:
        return jsonify({"status": "error", "message": f"Invalid target_url: {normalized_or_reason}"}), 400

    # Run in the background: return 202 immediately so long scans never hit
    # HTTP timeouts. Poll GET /api/sessions/<id> (scan_status) for completion.
    session_id = _launch_background_scan(normalized_or_reason)
    return jsonify({
        "status": "accepted",
        "message": "Scan started in background; poll the session until scan_status is complete.",
        "session_id": session_id,
        "target_url": normalized_or_reason,
        "status_url": url_for("dashboard.api_get_session", session_id=session_id),
        "results_url": url_for("dashboard.results", session_id=session_id),
        "sarif_url": url_for("dashboard.export_report", session_id=session_id, format="sarif"),
    }), 202
