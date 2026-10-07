import os
import json
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
from database.db import (
    save_scan_session, save_endpoint, save_finding, complete_scan_session,
    fail_scan_session, touch_scan_session, format_scan_eta,
    get_all_sessions, get_session_for_user, get_session_findings,
    get_finding_by_id, delete_session, delete_user, get_user_by_id,
    get_user_by_username, get_user_by_firebase_uid,
    get_or_create_firebase_user, update_user_name,
    create_reset_otp, get_latest_valid_reset_otp, increment_otp_attempts,
    mark_otp_verified, mark_otp_used, count_recent_otps,
)
from dashboard.auth_validators import (
    validate_signup_email, password_strength_error, EMAIL_RE)
from dashboard.emailer import is_email_configured, send_otp_email
from dashboard.firebase_auth import (
    firebase_web_config, firebase_configured, verify_firebase_token,
)
from dashboard.results_grouping import (
    group_findings, summarize_findings, VULN_STATUSES, TOP_RISKS_COUNT
)
from dashboard.vuln_guide_content import GUIDE_CHECKS, get_check
from dashboard import assistant as assistant_engine
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


def _scan_worker(target_url: str, session_id: int, extra_headers=None) -> None:
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
        run_pipeline(target_url, return_session_id=True, session_id=session_id,
                     extra_headers=extra_headers)
    except Exception as exc:  # never let the thread die silently
        logger.error(f"Background scan {session_id} crashed: {exc}")
        try:
            fail_scan_session(session_id, str(exc))
        except Exception:
            pass
    finally:
        stop_heartbeat.set()
        # A user-cancelled scan stays failed even if the worker just finished.
        if session_id in _cancelled_scans:
            try:
                fail_scan_session(session_id, "Cancelled by user")
            except Exception:
                pass


# Session ids the user asked to cancel. The worker checks this after the
# pipeline returns so a late finish can't resurrect a cancelled scan.
_cancelled_scans = set()


def _launch_background_scan(target_url: str, user_id=None, extra_headers=None) -> int:
    """Create the session row immediately and run the scan in a daemon thread.

    Returns the session id at once so HTTP clients never block on (or time
    out during) a long scan.
    """
    session_obj = save_scan_session(target_url=target_url, status="running", user_id=user_id)
    thread = threading.Thread(
        target=_scan_worker,
        args=(target_url, session_obj.id, extra_headers),
        daemon=True,
        name=f"scan-{session_obj.id}",
    )
    thread.start()
    logger.info(f"Launched background scan {session_obj.id} for {target_url}")
    return session_obj.id


def reap_stale_scan(session_obj) -> bool:
    """Mark a 'running' scan as failed when its worker heartbeat went stale.

    Backend-agnostic: persists via fail_scan_session and mirrors the change
    onto the passed object. Returns True when the session was reaped.
    """
    if session_obj is None or getattr(session_obj, "status", None) != "running":
        return False
    heartbeat = getattr(session_obj, "updated_at", None) or session_obj.scan_start_time
    if heartbeat is None:
        return False
    if datetime.utcnow() - heartbeat > timedelta(seconds=STALE_SCAN_AFTER_SECONDS):
        fail_scan_session(session_obj.id,
                          f"no worker heartbeat for >{STALE_SCAN_AFTER_SECONDS}s")
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
            fail_scan_session(session_obj.id,
                              f"no progress for >{PROGRESS_STALL_AFTER_SECONDS}s")
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
        if is_auth_enabled():
            user_id = session.get("user_id")
            if not session.get("user_id"):
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
        alert_count = 0
    else:
        recent = get_all_sessions(user_id)[:5]
        try:
            alert_count = len(_build_alerts(user_id))
        except Exception:
            alert_count = 0
    authed = bool(session.get("user_id")) or not is_auth_enabled()
    return dict(
        recent_sessions=recent,
        csrf_token=get_or_create_csrf_token,
        auth_enabled=is_auth_enabled(),
        is_authenticated=authed,
        current_username=session.get("username"),
        app_version=APP_VERSION,
        alert_count=alert_count,
    )


def _build_alerts(user_id):
    """Alert items derived from the user's recent scan sessions.

    Each alert: id, kind (badge class), label, message, when, url, action.
    Pure presentation over existing session rows — no new state.
    """
    alerts = []
    sessions = get_all_sessions(user_id)[:10]
    for s in sessions:
        when = s.scan_start_time.strftime("%Y-%m-%d %H:%M") if s.scan_start_time else ""
        target = s.target_url
        if (s.status or "complete") == "failed":
            alerts.append({
                "id": f"failed-{s.id}", "kind": "failed", "label": "Failed",
                "message": f"Scan of {target} could not reach the target.",
                "when": when, "url": url_for("dashboard.new_scan"), "action": "Try again",
            })
        elif (s.status or "complete") == "running":
            continue  # a running scan is progress, not an alert
        else:
            critical = sum(
                1 for f in get_session_findings(s.id) if f.severity == "Critical"
            )
            if critical:
                alerts.append({
                    "id": f"critical-{s.id}", "kind": "critical", "label": "Critical",
                    "message": f"Scan of {target} finished with {critical} critical finding{'s' if critical != 1 else ''}.",
                    "when": when, "url": url_for("dashboard.results", session_id=s.id), "action": "View results",
                })
            alerts.append({
                "id": f"scan-{s.id}", "kind": "scan", "label": "Scan",
                "message": f"Scan of {target} completed.",
                "when": when, "url": url_for("dashboard.results", session_id=s.id), "action": "View results",
            })
            alerts.append({
                "id": f"report-{s.id}", "kind": "report", "label": "Report",
                "message": f"Report for {target} is ready to download.",
                "when": when, "url": url_for("dashboard.reports"), "action": "Open reports",
            })
    return alerts


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
        return redirect(url_for("dashboard.dashboard"))
    next_url = request.args.get("next") or url_for("dashboard.dashboard")
    if not next_url.startswith("/"):
        next_url = url_for("dashboard.dashboard")
    return render_template("login.html", next_url=next_url,
                           firebase_config=firebase_web_config(),
                           firebase_configured=firebase_configured())


@dashboard_bp.route("/signup", methods=["GET"])
def signup():
    if not is_auth_enabled():
        return redirect(url_for("dashboard.dashboard"))
    if session.get("user_id"):
        return redirect(url_for("dashboard.dashboard"))
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
        # Optional display name from the signup form (falls back to Firebase).
        display_name = (data.get("name") or "").strip() or claims.get("name")
        user = get_or_create_firebase_user(
            uid, email, username,
            name=display_name, avatar_url=claims.get("picture"))
        logger.info(f"New dashboard user via Firebase: {username} ({email})")

    session["user_id"] = user.id
    session["username"] = user.username
    next_url = (data.get("next") or "").strip()
    if not next_url.startswith("/"):
        next_url = url_for("dashboard.dashboard")
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
def index():
    # Public front door: visitors see the landing page; signed-in users
    # go straight to their dashboard.
    if session.get("user_id"):
        return redirect(url_for("dashboard.dashboard"))
    return render_template("landing.html", active_page="landing")


@dashboard_bp.route("/new-scan")
@login_required
def new_scan():
    return _render_new_scan()


def _render_new_scan():
    """Shared renderer for / and /new-scan."""
    user_id = get_current_user_id()
    running_scan = None
    for s in get_all_sessions(user_id):
        if (s.status or "complete") == "running":
            running_scan = s
            break
    return render_template("new_scan.html", running_scan=running_scan)


def _auth_headers_from_form():
    """Translate the New Scan auth fields into probe headers (or None).

    Returns None when auth type is "none"/empty so the pipeline behaves
    exactly as before.
    """
    auth_type = (request.form.get("auth_type") or "none").strip().lower()
    auth_value = (request.form.get("auth_value") or "").strip()
    if auth_type in ("", "none") or not auth_value:
        return None
    if auth_type == "bearer":
        return {"Authorization": f"Bearer {auth_value}"}
    if auth_type == "api_key":
        return {"X-API-Key": auth_value}
    if auth_type == "cookie":
        return {"Cookie": auth_value}
    return None


@dashboard_bp.route("/scan", methods=["POST"])
@login_required
def start_scan():
    target_url = request.form.get("target_url")
    if not target_url:
        return redirect(url_for("dashboard.new_scan"))

    valid, normalized_or_reason = validate_target_url(target_url)
    if not valid:
        return f"Invalid target URL: {normalized_or_reason}", 400

    # The wireframe requires the authorization checkbox; the API contract
    # (and older form posts) never had it, so the server stays lenient and
    # the checkbox is enforced in the browser.
    extra_headers = _auth_headers_from_form()

    # Scans run in the background; the results page polls until completion.
    # extra_headers is only passed when set, so the monkeypatched launcher in
    # older tests (target_url, user_id=None) keeps working unchanged.
    launch_kwargs = {}
    if extra_headers:
        launch_kwargs["extra_headers"] = extra_headers
    session_id = _launch_background_scan(normalized_or_reason, user_id=get_current_user_id(), **launch_kwargs)
    return redirect(url_for("dashboard.results", session_id=session_id))


@dashboard_bp.route("/scan/<session_id>/cancel", methods=["POST"])
@login_required
def cancel_scan(session_id):
    """Cancel a running scan: mark it failed so polling stops.

    The worker checks the cancelled set when the pipeline returns, so a
    late finish can't resurrect the session back to "complete".
    """
    if not get_session_for_user(session_id, get_current_user_id()):
        return "Session not found", 404
    _cancelled_scans.add(session_id)
    fail_scan_session(session_id, "Cancelled by user")
    return redirect(url_for("dashboard.results", session_id=session_id))

@dashboard_bp.route("/results/<session_id>")
@login_required
def results(session_id):
    user_id = get_current_user_id()
    session_data = get_session_for_user(session_id, user_id)
    if not session_data:
        return "Session not found", 404

    # If the worker died (restart/crash), the row would sit at "running"
    # forever and the progress banner would poll forever -- reap it.
    reap_stale_scan(session_data)

    findings = get_session_findings(session_id)

    # Group findings by endpoint for the Top Risks view (deduped,
    # scored, sorted). Raw findings stay untouched for charts/detail.
    finding_dicts = [{
        "id": f.id,
        "url": f.endpoint.url if f.endpoint else session_data.target_url,
        "method": f.endpoint.method if f.endpoint else "GET",
        "attack_type": f.attack_type,
        "severity": f.severity,
        "finding_status": f.finding_status,
        "risk_score": f.risk_score,
        "recommendation": f.recommendation,
    } for f in findings]
    grouped = group_findings(finding_dicts)
    endpoint_groups = grouped["groups"]
    # The single scoring rule: header numbers always match history/dashboard.
    scan_summary = summarize_findings(finding_dicts)
    total_endpoints = len(session_data.endpoints or [])
    passed_count = max(0, total_endpoints - len(endpoint_groups))

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
        endpoint_groups=endpoint_groups,
        top_risks=endpoint_groups[:TOP_RISKS_COUNT],
        group_summary=grouped["summary"],
        scan_summary=scan_summary,
        total_endpoints=total_endpoints,
        passed_count=passed_count,
    )

@dashboard_bp.route("/history")
@login_required
def history():
    user_id = get_current_user_id()
    sessions = get_all_sessions(user_id)
    q = (request.args.get("q") or "").strip().lower()
    severity = (request.args.get("severity") or "").strip()
    date = (request.args.get("date") or "").strip()
    if q:
        sessions = [s for s in sessions
                    if q in (s.target_url or "").lower() or q in str(s.id)]
    if severity:
        sessions = [s for s in sessions if (s.overall_severity or "") == severity]
    if date in ("today", "week", "month"):
        days = {"today": 1, "week": 7, "month": 30}[date]
        cutoff = datetime.utcnow() - timedelta(days=days)
        sessions = [s for s in sessions
                    if s.scan_start_time and s.scan_start_time >= cutoff]
    rows = []
    for s in sessions:
        rows.append({
            "session": s,
            "summary": summarize_findings(
                _finding_dicts(get_session_findings(s.id), s.target_url)),
        })
    return render_template("history.html", rows=rows,
                           q=request.args.get("q") or "",
                           severity=severity, date=date)

@dashboard_bp.route("/finding/<finding_id>")
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

@dashboard_bp.route("/export/<session_id>")
@login_required
def export_report(session_id):
    fmt = request.args.get("format", "pdf").lower()
    user_id = get_current_user_id()
    session_obj = get_session_for_user(session_id, user_id)
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
    from dashboard.results_grouping import group_findings, TOP_RISKS_COUNT

    grouped = group_findings(findings_data)
    top_risks = grouped["groups"][:TOP_RISKS_COUNT]
    # Order findings by their endpoint group's score so top risks come
    # first in every export (SARIF keeps the flat finding list).
    group_rank = {}
    for rank, g in enumerate(grouped["groups"]):
        for v in g["vulns"]:
            for fid in v["finding_ids"]:
                group_rank[fid] = rank
    findings_data.sort(key=lambda f: (group_rank.get(f["id"], 10**9), -(f["risk_score"] or 0)))

    if fmt == "json":
        exporter = JSONReportExporter()
        out_file = exporter.export(session_data, endpoints_list, findings_data,
                                   top_risks=top_risks)
        return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.json")
    elif fmt == "html":
        exporter = HTMLReportExporter()
        out_file = exporter.export(session_data, findings_data, top_risks=top_risks)
        return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.html")
    elif fmt == "sarif":
        exporter = SARIFReportExporter()
        out_file = exporter.export(session_data, findings_data)
        return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.sarif")
    else:
        generator = PDFReportGenerator()
        out_file = generator.generate(session_data, findings_data, top_risks=top_risks)
        return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.pdf")


@dashboard_bp.route("/delete_scan/<session_id>", methods=["POST"])
@login_required
def delete_scan(session_id):
    if not get_session_for_user(session_id, get_current_user_id()):
        return "Session not found", 404
    delete_session(session_id)
    return redirect(url_for("dashboard.history"))

# ---------------------------------------------------------
# New UI pages (wireframes): dashboard, targets, reports, alerts,
# settings, vulnerability guide, AI assistant, public pages.
# All read existing session rows; none change the scan pipeline.
# ---------------------------------------------------------

def _finding_dicts(findings, fallback_url=""):
    return [{
        "id": f.id,
        "url": f.endpoint.url if f.endpoint else fallback_url,
        "method": f.endpoint.method if f.endpoint else "GET",
        "attack_type": f.attack_type,
        "severity": f.severity,
        "finding_status": f.finding_status,
        "risk_score": f.risk_score,
        "recommendation": f.recommendation,
    } for f in findings]


def _current_user():
    return get_user_by_id(get_current_user_id())


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    user_id = get_current_user_id()
    sessions = get_all_sessions(user_id)

    scans_run = len(sessions)
    scored = [s for s in sessions if s.overall_risk_score is not None]
    avg_score = round(sum(s.overall_risk_score for s in scored) / len(scored), 1) if scored else 0
    last = sessions[0].scan_start_time if sessions and sessions[0].scan_start_time else None

    recent_ids = [s.id for s in sessions[:10]]
    recent_findings = []
    for _sid in recent_ids:
        recent_findings.extend(get_session_findings(_sid))
    critical_findings = sum(
        1 for f in recent_findings
        if f.severity == "Critical" and (f.finding_status or "Informational") in VULN_STATUSES)
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for f in recent_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    trend = [s for s in sessions[:10] if s.scan_start_time][::-1]
    risk_over_time = {
        "labels": [s.scan_start_time.strftime("%m-%d") for s in trend],
        "scores": [round(s.overall_risk_score or 0, 1) for s in trend],
    }

    top_endpoints = []
    for s in sessions[:5]:
        top_endpoints.extend(_finding_dicts(get_session_findings(s.id), s.target_url))
    top_endpoints = group_findings(top_endpoints)["groups"][:5]

    return render_template(
        "dashboard.html",
        stats={
            "scans_run": scans_run,
            "critical_findings": critical_findings,
            "avg_score": avg_score,
            "last_scan": last.strftime("%Y-%m-%d") if last else None,
        },
        severity_counts=severity_counts,
        risk_over_time=risk_over_time,
        top_endpoints=top_endpoints,
    )


@dashboard_bp.route("/compare")
@login_required
def compare():
    user_id = get_current_user_id()
    ids = []
    for raw in request.args.getlist("ids"):
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                ids.append(int(part))
    compared = []
    for sid in ids[:4]:
        s = get_session_for_user(sid, user_id)
        if not s:
            continue
        findings = get_session_findings(sid)
        fd = _finding_dicts(findings, s.target_url)
        compared.append({
            "session": s,
            "summary": summarize_findings(fd),
            "critical": sum(1 for f in fd if f["severity"] == "Critical" and f["finding_status"] in VULN_STATUSES),
            "high": sum(1 for f in fd if f["severity"] == "High" and f["finding_status"] in VULN_STATUSES),
        })
    return render_template("compare.html", compared=compared)


@dashboard_bp.route("/targets")
@login_required
def targets():
    user_id = get_current_user_id()
    q = (request.args.get("q") or "").strip().lower()
    grouped = {}
    for s in get_all_sessions(user_id):
        key = (s.target_url or "").strip()
        if not key:
            continue
        g = grouped.setdefault(key, {"target_url": key, "scans_run": 0,
                                     "last_scan": None, "latest_score": 0,
                                     "severity": "Low", "latest_session_id": None})
        g["scans_run"] += 1
        if g["last_scan"] is None or (s.scan_start_time and s.scan_start_time > g["last_scan"]):
            g["last_scan"] = s.scan_start_time
            g["latest_score"] = s.overall_risk_score or 0
            g["severity"] = s.overall_severity or "Low"
            g["latest_session_id"] = s.id
    rows = sorted(grouped.values(), key=lambda r: r["last_scan"] or datetime.min, reverse=True)
    if q:
        rows = [r for r in rows if q in r["target_url"].lower()]
    return render_template("targets.html", targets=rows, q=request.args.get("q") or "")


@dashboard_bp.route("/reports")
@login_required
def reports():
    user_id = get_current_user_id()
    sessions = [s for s in get_all_sessions(user_id)
                if (s.status or "complete") == "complete"]
    q = (request.args.get("q") or "").strip().lower()
    date = (request.args.get("date") or "").strip()
    if q:
        sessions = [s for s in sessions if q in (s.target_url or "").lower()]
    if date in ("today", "week", "month"):
        days = {"today": 1, "week": 7, "month": 30}[date]
        cutoff = datetime.utcnow() - timedelta(days=days)
        sessions = [s for s in sessions
                    if s.scan_start_time and s.scan_start_time >= cutoff]
    return render_template("reports.html", sessions=sessions,
                           q=request.args.get("q") or "", date=date)


@dashboard_bp.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", alerts=_build_alerts(get_current_user_id()))


@dashboard_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    notice = None
    if request.method == "POST" and request.form.get("form") == "account":
        name = (request.form.get("name") or "").strip()
        if update_user_name(get_current_user_id(), name):
            notice = "Account name saved."
        else:
            notice = "Could not save — please try again."
    return render_template("settings.html", user=_current_user(), notice=notice,
                           ai_live=(assistant_engine.engine_mode() == "live"),
                           ai_error=assistant_engine.last_llm_error())


@dashboard_bp.route("/settings/export")
@login_required
def export_my_data():
    """Download everything about the user's account as JSON (privacy)."""
    user = _current_user()
    sessions = get_all_sessions(get_current_user_id())
    data = {
        "user": {
            "username": user.username if user else None,
            "email": user.email if user else None,
            "name": user.name if user else None,
        },
        "sessions": [{
            "id": s.id,
            "target_url": s.target_url,
            "status": s.status,
            "scan_start_time": s.scan_start_time.isoformat() if s.scan_start_time else None,
            "scan_end_time": s.scan_end_time.isoformat() if s.scan_end_time else None,
            "overall_risk_score": s.overall_risk_score,
            "overall_severity": s.overall_severity,
            "total_endpoints_found": s.total_endpoints_found,
            "total_vulnerabilities_found": s.total_vulnerabilities_found,
        } for s in sessions],
    }
    return jsonify(data), 200, {
        "Content-Disposition": "attachment; filename=xploiter-my-data.json"}


@dashboard_bp.route("/settings/delete-scans", methods=["POST"])
@login_required
def delete_my_scans():
    for s in get_all_sessions(get_current_user_id()):
        delete_session(s.id)
    return redirect(url_for("dashboard.settings"))


@dashboard_bp.route("/settings/delete-account", methods=["POST"])
@login_required
def delete_my_account():
    user_id = get_current_user_id()
    delete_user(user_id)
    session.clear()
    return redirect(url_for("dashboard.landing"))


@dashboard_bp.route("/vuln-guide")
@login_required
def vuln_guide():
    q = (request.args.get("q") or "").strip().lower()
    checks = [c for c in GUIDE_CHECKS
              if not q or q in c["title"].lower() or q in c["what"].lower()]
    slug = request.args.get("check") or ""
    active = get_check(slug) if slug else (checks[0] if checks else GUIDE_CHECKS[0])
    return render_template("vuln_guide.html", checks=checks, active=active,
                           q=request.args.get("q") or "")


@dashboard_bp.route("/ai-assistant")
@login_required
def ai_assistant():
    return render_template("ai_assistant.html",
                           prefill=(request.args.get("q") or "").strip() or None,
                           ai_mode=assistant_engine.engine_mode(),
                           show_ai_fab=False)


def _assistant_scan_context(user_id):
    """Short, honest summary of the latest completed scan (or None)."""
    sessions = [s for s in get_all_sessions(user_id)
                if (s.status or "complete") == "complete"]
    if not sessions:
        return None
    s = sessions[0]
    findings = get_session_findings(s.id)
    types = sorted({f.attack_type for f in findings})
    return (
        f"Latest scan: session {s.id}, target {s.target_url}, "
        f"score {s.overall_risk_score}/100 ({s.overall_severity}), "
        f"{s.total_vulnerabilities_found} findings across "
        f"{s.total_endpoints_found} endpoints. "
        f"Finding types: {', '.join(types) if types else 'none'}."
    )


@dashboard_bp.route("/api/assistant/ask", methods=["POST"])
@login_required
def assistant_ask():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"status": "error", "message": "Ask a question first."}), 400
    language = (data.get("language") or "auto").strip().lower()
    if language not in ("auto", "en", "ur", "ar", "es"):
        language = "auto"
    scan_context = None
    if (data.get("context") or "latest") == "latest":
        scan_context = _assistant_scan_context(get_current_user_id())
    answer_html, actions = assistant_engine.answer(question, language, scan_context)
    return jsonify({"status": "ok", "answer_html": answer_html, "actions": actions})


# ---------------------------------------------------------
# Public pages (no login required)
# ---------------------------------------------------------

@dashboard_bp.route("/landing")
def landing():
    return render_template("landing.html", active_page="landing")


@dashboard_bp.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html", active_page="how_it_works")


@dashboard_bp.route("/docs")
def docs():
    return render_template("docs.html", active_page="docs")


@dashboard_bp.route("/pricing")
def pricing():
    return render_template("pricing.html", active_page="pricing")


@dashboard_bp.route("/about")
def about():
    return render_template("about.html", active_page="about")


@dashboard_bp.route("/contact")
def contact():
    return render_template("contact.html", active_page="contact")


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


@dashboard_bp.route("/api/sessions/<session_id>", methods=["GET"])
@login_required
def api_get_session(session_id):
    user_id = get_current_user_id()
    session_obj = get_session_for_user(session_id, user_id)
    if not session_obj:
        return jsonify({"status": "error", "message": "Session not found"}), 404

    # Reap scans whose worker died, so API pollers see a terminal state.
    reap_stale_scan(session_obj)

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


@dashboard_bp.route("/api/sessions/<session_id>", methods=["DELETE"])
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
