import os
import re
import sys
import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, abort, current_app

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import (
    DASHBOARD_AUTH_ENABLED,
    CSRF_ENABLED,
    APP_VERSION,
)
from sqlalchemy.orm import joinedload
from database.db import (
    save_scan_session, save_endpoint, save_finding, complete_scan_session,
    fail_scan_session, touch_scan_session, format_scan_eta,
    get_all_sessions, get_session_for_user, get_session_findings,
    get_finding_by_id, delete_session, SessionLocal,
    get_user_by_username, get_user_by_firebase_uid,
    get_or_create_firebase_user,
    create_reset_otp, get_latest_valid_reset_otp, increment_otp_attempts,
    mark_otp_verified, mark_otp_used, count_recent_otps,
)
from database.models import ScanSession, Finding, Endpoint
from dashboard.auth_validators import (
    validate_signup_email, password_strength_error, EMAIL_RE)
from dashboard.emailer import is_email_configured, send_otp_email
from dashboard.firebase_auth import (
    firebase_web_config, firebase_configured, verify_firebase_token,
)
from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.signature import SignatureDetector
from detection.ml_model import MLAnomalyDetector
from detection.deep_learning import DeepLearningDetector
from detection.risk_scorer import RiskScorer
from main import run_pipeline, validate_target_url

dashboard_bp = Blueprint("dashboard", __name__)

# A "running" scan whose worker heartbeat is older than this is considered
# dead (e.g. the process was restarted, killing the daemon thread) and is
# reaped as failed so the UI stops polling it forever.
STALE_SCAN_AFTER_SECONDS = 600
HEARTBEAT_INTERVAL_SECONDS = 60
# A "running" scan that made no progress for longer than this is considered
# stuck (the worker is alive — heartbeat is fresh — but wedged on one step)
# and is reaped as failed so the UI shows "Scan failed" instead of
# "Scan in progress..." forever. Must comfortably exceed the worst legitimate
# single-endpoint time (bounded by ENDPOINT_DISPATCH_TIMEOUT in main.py).
PROGRESS_STALL_AFTER_SECONDS = int(os.getenv("PROGRESS_STALL_AFTER_SECONDS", "900"))


def _scan_worker(target_url: str, session_id: int) -> None:
    """Background thread entry point: run the pipeline against the pre-created session."""
    stop_heartbeat = threading.Event()

    def _heartbeat() -> None:
        while not stop_heartbeat.wait(HEARTBEAT_INTERVAL_SECONDS):
            try:
                touch_scan_session(session_id)
            except Exception:
                pass

    hb_thread = threading.Thread(target=_heartbeat, daemon=True, name=f"heartbeat-{session_id}")
    hb_thread.start()
    try:
        run_pipeline(target_url, return_session_id=True, session_id=session_id)
    except Exception as exc:  # never let the thread die silently
        logger.error(f"Background scan {session_id} crashed: {exc}")
        try:
            fail_scan_session(session_id, str(exc))
        except Exception:
            pass
    finally:
        stop_heartbeat.set()


def _launch_background_scan(target_url: str, user_id=None) -> int:
    """Create the session row immediately and run the scan in a daemon thread.

    Returns the session id at once so HTTP clients never block on (or time
    out during) a long scan.
    """
    session_obj = save_scan_session(target_url=target_url, status="running", user_id=user_id)
    thread = threading.Thread(
        target=_scan_worker,
        args=(target_url, session_obj.id),
        daemon=True,
        name=f"scan-{session_obj.id}",
    )
    thread.start()
    logger.info(f"Launched background scan {session_obj.id} for {target_url}")
    return session_obj.id


def reap_stale_scan(db_session, session_obj) -> bool:
    """Mark a 'running' scan as failed when its worker heartbeat went stale.

    Returns True when the session was reaped. The caller owns the commit.
    """
    if session_obj is None or getattr(session_obj, "status", None) != "running":
        return False
    heartbeat = getattr(session_obj, "updated_at", None) or session_obj.scan_start_time
    if heartbeat is None:
        return False
    if datetime.utcnow() - heartbeat > timedelta(seconds=STALE_SCAN_AFTER_SECONDS):
        session_obj.status = "failed"
        session_obj.scan_end_time = datetime.utcnow()
        logger.warning(
            f"Reaped stale scan {session_obj.id}: no worker heartbeat for "
            f">{STALE_SCAN_AFTER_SECONDS}s; marked failed."
        )
        return True
    # Progress watchdog: the worker is alive (heartbeat fresh) but hasn't
    # recorded any progress for a long time — it's wedged. Fail honestly
    # instead of showing "Scan in progress..." forever.
    progress_ts = getattr(session_obj, "progress_updated_at", None)
    if progress_ts is not None:
        if datetime.utcnow() - progress_ts > timedelta(seconds=PROGRESS_STALL_AFTER_SECONDS):
            session_obj.status = "failed"
            session_obj.scan_end_time = datetime.utcnow()
            logger.warning(
                f"Reaped stuck scan {session_obj.id}: no progress for "
                f">{PROGRESS_STALL_AFTER_SECONDS}s (last: done={session_obj.progress_done}/"
                f"{session_obj.progress_total} stage={session_obj.progress_stage!r}); marked failed."
            )
            return True
    return False


def get_or_create_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def is_auth_enabled() -> bool:
    if "DASHBOARD_AUTH_ENABLED" in current_app.config:
        return bool(current_app.config["DASHBOARD_AUTH_ENABLED"])
    if current_app.config.get("TESTING"):
        # Existing tests exercise the UI without accounts; keep them green
        # unless a test opts into auth explicitly.
        return False
    return DASHBOARD_AUTH_ENABLED


def get_current_user_id():
    """Logged-in user's id, or None when auth is disabled / not logged in."""
    if not is_auth_enabled():
        return None
    return session.get("user_id")


def is_csrf_enabled() -> bool:
    if current_app.config.get("TESTING") and "CSRF_ENABLED" not in current_app.config:
        return False
    return current_app.config.get("CSRF_ENABLED", CSRF_ENABLED)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_auth_enabled() and not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Authentication required"}), 401
            return redirect(url_for("dashboard.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@dashboard_bp.context_processor
def inject_globals():
    user_id = get_current_user_id()
    if is_auth_enabled() and user_id is None:
        recent = []  # logged out: never leak other users' scans in the sidebar
    else:
        recent = get_all_sessions(user_id)[:5]
    authed = bool(session.get("user_id")) or not is_auth_enabled()
    return dict(
        recent_sessions=recent,
        csrf_token=get_or_create_csrf_token,
        auth_enabled=is_auth_enabled(),
        is_authenticated=authed,
        current_username=session.get("username"),
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


# ---------------------------------------------------------------------------
# Firebase Authentication
# ---------------------------------------------------------------------------
# Identity lives in Firebase (email/password + Google sign-in via the Firebase
# JS SDK in the browser). The browser signs in with Firebase, then POSTs the
# Firebase ID token to /api/auth/session; this backend verifies the token with
# the Admin SDK and creates the server session. Password resets are handled
# entirely by Firebase (sendPasswordResetEmail in the browser) — the reset
# email and reset page are Firebase's, so this backend needs no reset code.

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _unique_username(base: str) -> str:
    """First available username derived from base (suffixes with a number)."""
    base = re.sub(r"[^A-Za-z0-9_.-]", "", base.replace(" ", "."))[:20] or "user"
    if len(base) < 3:
        base = (base + "user")[:20]
    candidate = base
    i = 0
    while get_user_by_username(candidate):
        i += 1
        candidate = f"{base}{i}"[:32]
    return candidate


@dashboard_bp.route("/login", methods=["GET"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))
    next_url = request.args.get("next") or url_for("dashboard.index")
    if not next_url.startswith("/"):
        next_url = url_for("dashboard.index")
    return render_template("login.html", next_url=next_url,
                           firebase_config=firebase_web_config(),
                           firebase_configured=firebase_configured())


@dashboard_bp.route("/signup", methods=["GET"])
def signup():
    if not is_auth_enabled():
        return redirect(url_for("dashboard.index"))
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))
    return render_template("signup.html",
                           firebase_config=firebase_web_config(),
                           firebase_configured=firebase_configured())


@dashboard_bp.route("/forgot-password", methods=["GET"])
def forgot_password():
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))
    return render_template("forgot_password.html",
                           firebase_config=firebase_web_config(),
                           firebase_configured=firebase_configured())


@dashboard_bp.route("/api/auth/session", methods=["POST"])
def firebase_session():
    """Exchange a verified Firebase ID token for a server session.

    Body (JSON): {"idToken": "<firebase id token>", "username": "<optional>"}.
    The username is only used the first time a Firebase user signs in.
    """
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"}), 400
    data = request.get_json(silent=True) or {}
    id_token = (data.get("idToken") or "").strip()
    if not id_token:
        return jsonify({"status": "error", "message": "Missing sign-in token"}), 400
    try:
        claims = verify_firebase_token(id_token)
    except Exception as exc:
        logger.warning(f"Firebase ID token verification failed: {exc}")
        return jsonify({"status": "error", "message": "Invalid sign-in token — please sign in again"}), 401

    email = (claims.get("email") or "").strip()
    if not email:
        return jsonify({"status": "error", "message": "This sign-in has no email address"}), 400
    # Server-side enforcement of the email allow-list (the signup form also
    # checks this in JS, but the verified token email is authoritative here).
    email_error = validate_signup_email(email)
    if email_error:
        return jsonify({"status": "error", "message": email_error}), 400

    uid = claims["uid"]
    user = get_user_by_firebase_uid(uid)
    if user is None:
        username = (data.get("username") or "").strip()
        if username:
            if not USERNAME_RE.match(username):
                return jsonify({"status": "error", "message":
                                "Username must be 3-32 characters: letters, numbers, dot, dash, underscore."}), 400
            if get_user_by_username(username):
                return jsonify({"status": "error", "message": "That username is already taken."}), 400
        else:
            # Google sign-in (or any flow without a typed username): derive one.
            username = _unique_username(claims.get("name") or email.split("@")[0])
        user = get_or_create_firebase_user(
            uid, email, username,
            name=claims.get("name"), avatar_url=claims.get("picture"))
        logger.info(f"New dashboard user via Firebase: {username} ({email})")

    session["user_id"] = user.id
    session["username"] = user.username
    next_url = (data.get("next") or "").strip()
    if not next_url.startswith("/"):
        next_url = url_for("dashboard.index")
    return jsonify({"status": "ok", "redirect": next_url})


# ---------------------------------------------------------------------------
# Forgot password via emailed OTP (alternative to the Firebase reset link).
# The OTP only proves ownership of the email address; the new password is
# set through the Firebase Admin SDK. Codes are 6 digits, hashed at rest,
# 15-minute expiry, 5-attempt lockout, single-use.
# ---------------------------------------------------------------------------
OTP_EXPIRY_MINUTES = 15
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_PER_HOUR = 5

# Generic reply used everywhere in this flow so the responses never reveal
# whether an email address has an account.
_OTP_GENERIC_REPLY = ("If an account exists for that email, we've sent it a "
                      "one-time code. Check your inbox (and spam folder).")


def _hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def _normalize_otp_email(email: str) -> str:
    return (email or "").strip().lower()


def _get_firebase_user_by_email(email: str):
    """Firebase user record for the email, or None when there isn't one."""
    from firebase_admin import auth as fb_auth
    from dashboard.firebase_auth import _admin_app
    _admin_app()  # raises RuntimeError when the service account isn't set
    try:
        return fb_auth.get_user_by_email(email)
    except fb_auth.UserNotFoundError:
        return None


@dashboard_bp.route("/api/auth/otp/request", methods=["POST"])
def otp_request():
    """Email a 6-digit reset code. Body: {"email": "..."}."""
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"}), 400
    data = request.get_json(silent=True) or {}
    email = _normalize_otp_email(data.get("email"))
    email_error = validate_signup_email(email)
    if email_error:
        return jsonify({"status": "error", "message": email_error}), 400
    if not is_email_configured():
        return jsonify({"status": "error", "message":
                        "Email sending isn't set up on this server yet."}), 503

    now = datetime.utcnow()
    if count_recent_otps(email, now - timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)) > 0:
        return jsonify({"status": "error", "message":
                        "A code was just sent — please wait a minute before asking again."}), 429
    if count_recent_otps(email, now - timedelta(hours=1)) >= OTP_MAX_PER_HOUR:
        return jsonify({"status": "error", "message":
                        "Too many codes requested. Please try again later."}), 429

    try:
        fb_user = _get_firebase_user_by_email(email)
    except RuntimeError:
        logger.warning("OTP request failed: Firebase Admin SDK not configured")
        return jsonify({"status": "error", "message":
                        "Password reset isn't available right now. Please try again later."}), 503
    except Exception as exc:
        logger.warning(f"OTP request Firebase lookup failed: {exc}")
        return jsonify({"status": "error", "message":
                        "Password reset isn't available right now. Please try again later."}), 503

    if fb_user is None:
        # No account — reply generically, send nothing (anti-enumeration).
        return jsonify({"status": "ok", "message": _OTP_GENERIC_REPLY})

    otp = f"{secrets.randbelow(1000000):06d}"
    create_reset_otp(email, _hash_otp(otp),
                     now + timedelta(minutes=OTP_EXPIRY_MINUTES))
    ok, reason = send_otp_email(email, otp)
    if not ok:
        latest = get_latest_valid_reset_otp(email)
        if latest:
            mark_otp_used(latest.id)
        logger.warning(f"OTP email to {email} failed: {reason}")
        return jsonify({"status": "error", "message":
                        "We couldn't send the email right now. Please try again in a bit."}), 502
    return jsonify({"status": "ok", "message": _OTP_GENERIC_REPLY})


@dashboard_bp.route("/api/auth/otp/verify", methods=["POST"])
def otp_verify():
    """Check a 6-digit code. Body: {"email": "...", "otp": "123456"}."""
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"}), 400
    data = request.get_json(silent=True) or {}
    email = _normalize_otp_email(data.get("email"))
    otp = (data.get("otp") or "").strip()
    if not email or not otp:
        return jsonify({"status": "error", "message": "Enter the code we emailed you."}), 400

    token = get_latest_valid_reset_otp(email)
    if token is None:
        return jsonify({"status": "error", "message":
                        "That code has expired. Request a new one."}), 400
    if (token.attempts or 0) >= OTP_MAX_ATTEMPTS:
        mark_otp_used(token.id)
        return jsonify({"status": "error", "message":
                        "Too many wrong attempts. Request a new code."}), 429
    if not hmac.compare_digest(token.otp_hash, _hash_otp(otp)):
        increment_otp_attempts(token.id)
        remaining = OTP_MAX_ATTEMPTS - (token.attempts or 0) - 1
        return jsonify({"status": "error", "message":
                        f"That code isn't right. {max(remaining, 0)} attempts left."}), 401
    mark_otp_verified(token.id)
    return jsonify({"status": "ok", "message": "Code verified. Choose a new password."})


@dashboard_bp.route("/api/auth/otp/reset", methods=["POST"])
def otp_reset():
    """Set the new password after OTP verification.

    Body: {"email": "...", "otp": "123456", "new_password": "...",
           "confirm_password": "..."}. The password is set via Firebase.
    """
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"}), 400
    data = request.get_json(silent=True) or {}
    email = _normalize_otp_email(data.get("email"))
    otp = (data.get("otp") or "").strip()
    new_password = data.get("new_password") or ""
    confirm_password = data.get("confirm_password") or ""

    pw_error = password_strength_error(new_password)
    if pw_error:
        return jsonify({"status": "error", "message": pw_error}), 400
    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "The passwords don't match."}), 400
    if not email or not otp:
        return jsonify({"status": "error", "message": "Enter the code we emailed you."}), 400

    token = get_latest_valid_reset_otp(email)
    if token is None:
        return jsonify({"status": "error", "message":
                        "That code has expired. Request a new one."}), 400
    if not token.verified:
        return jsonify({"status": "error", "message":
                        "Please verify the code first."}), 400
    if not hmac.compare_digest(token.otp_hash, _hash_otp(otp)):
        increment_otp_attempts(token.id)
        return jsonify({"status": "error", "message": "That code isn't right."}), 401

    try:
        fb_user = _get_firebase_user_by_email(email)
        if fb_user is None:
            return jsonify({"status": "error", "message":
                            "That account no longer exists."}), 400
        from firebase_admin import auth as fb_auth
        fb_auth.update_user(fb_user.uid, password=new_password)
    except RuntimeError:
        logger.warning("OTP reset failed: Firebase Admin SDK not configured")
        return jsonify({"status": "error", "message":
                        "Password reset isn't available right now. Please try again later."}), 503
    except Exception as exc:
        logger.warning(f"OTP reset Firebase update failed for {email}: {exc}")
        return jsonify({"status": "error", "message":
                        "We couldn't update the password. Please try again."}), 502

    mark_otp_used(token.id)
    logger.info(f"Password reset via OTP for {email}")
    return jsonify({"status": "ok", "message":
                    "Password updated. You can log in with your new password now."})


@dashboard_bp.route("/api/auth/resolve", methods=["POST"])
def resolve_login_identifier():
    """Resolve an email-or-username login identifier to the account email.

    Firebase signs in with email+password, so a typed username has to be
    mapped to its email first. Returns {"email": ...} or an error.
    """
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"}), 400
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    if not identifier:
        return jsonify({"status": "error", "message": "Enter your email or username."}), 400
    if "@" in identifier:
        email = identifier.lower()
        if not EMAIL_RE.match(email):
            return jsonify({"status": "error", "message": "That doesn't look like an email address."}), 400
        return jsonify({"status": "ok", "email": email})
    user = get_user_by_username(identifier)
    if user is None or not user.email:
        return jsonify({"status": "error", "message":
                        "No account found for that email or username."}), 404
    return jsonify({"status": "ok", "email": user.email})


@dashboard_bp.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("authenticated", None)  # legacy key, harmless
    # The login/signup pages also sign out of the Firebase JS SDK client-side.
    return redirect(url_for("dashboard.index"))



@dashboard_bp.route("/")
@login_required
def index():
    recent_sessions = get_all_sessions(get_current_user_id())[:5]
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
    session_id = _launch_background_scan(normalized_or_reason, user_id=get_current_user_id())
    return redirect(url_for("dashboard.results", session_id=session_id))

@dashboard_bp.route("/results/<int:session_id>")
@login_required
def results(session_id):
    db = SessionLocal()
    try:
        user_id = get_current_user_id()
        query = db.query(ScanSession).options(joinedload(ScanSession.endpoints), joinedload(ScanSession.findings)).filter(ScanSession.id == session_id)
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        session_data = query.first()
        if not session_data:
            return "Session not found", 404

        # If the worker died (restart/crash), the row would sit at "running"
        # forever and the progress banner would poll forever -- reap it.
        if reap_stale_scan(db, session_data):
            db.commit()

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
            attack_counts=attack_counts,
            progress_eta=format_scan_eta(session_data),
        )
    finally:
        db.close()

@dashboard_bp.route("/history")
@login_required
def history():
    sessions = get_all_sessions(get_current_user_id())
    return render_template("history.html", sessions=sessions)

@dashboard_bp.route("/finding/<int:finding_id>")
@login_required
def finding_detail(finding_id):
    finding = get_finding_by_id(finding_id)
    user_id = get_current_user_id()
    if finding and user_id is not None and finding.session and finding.session.user_id != user_id:
        finding = None
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
        user_id = get_current_user_id()
        query = db.query(ScanSession).filter(ScanSession.id == session_id)
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        session_obj = query.first()
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
    if not get_session_for_user(session_id, get_current_user_id()):
        return "Session not found", 404
    delete_session(session_id)
    return redirect(url_for("dashboard.history"))

# ---------------------------------------------------------
# REST API Endpoints for Programmatic Client Access
# ---------------------------------------------------------

@dashboard_bp.route("/api/sessions", methods=["GET"])
@login_required
def api_list_sessions():
    sessions = get_all_sessions(get_current_user_id())
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
@login_required
def api_get_session(session_id):
    db = SessionLocal()
    try:
        user_id = get_current_user_id()
        query = db.query(ScanSession).filter(ScanSession.id == session_id)
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        session_obj = query.first()
        if not session_obj:
            return jsonify({"status": "error", "message": "Session not found"}), 404

        # Reap scans whose worker died, so API pollers see a terminal state.
        if reap_stale_scan(db, session_obj):
            db.commit()

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
                "total_vulnerabilities_found": session_obj.total_vulnerabilities_found,
                "progress_done": int(session_obj.progress_done or 0),
                "progress_total": int(session_obj.progress_total or 0),
                "progress_stage": session_obj.progress_stage or "",
                "progress_eta": format_scan_eta(session_obj)
            },
            "endpoints": endpoints_data,
            "findings": findings_data
        }), 200
    finally:
        db.close()


@dashboard_bp.route("/api/sessions/<int:session_id>", methods=["DELETE"])
@login_required
def api_delete_session(session_id):
    if not get_session_for_user(session_id, get_current_user_id()):
        return jsonify({"status": "error", "message": "Session not found"}), 404
    success = delete_session(session_id)
    if success:
        return jsonify({"status": "success", "message": f"Session {session_id} deleted"}), 200
    return jsonify({"status": "error", "message": "Session not found"}), 404


@dashboard_bp.route("/api/scan", methods=["POST"])
@login_required
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
    session_id = _launch_background_scan(normalized_or_reason, user_id=get_current_user_id())
    return jsonify({
        "status": "accepted",
        "message": "Scan started in background; poll the session until scan_status is complete.",
        "session_id": session_id,
        "target_url": normalized_or_reason,
        "status_url": url_for("dashboard.api_get_session", session_id=session_id),
        "results_url": url_for("dashboard.results", session_id=session_id),
        "sarif_url": url_for("dashboard.export_report", session_id=session_id, format="sarif"),
    }), 202
