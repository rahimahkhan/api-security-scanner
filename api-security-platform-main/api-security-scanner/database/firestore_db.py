"""Google Cloud Firestore backend (NoSQL) for Xploiter.

Exposes the SAME function names as database/sql_db.py, so every
`from database.db import ...` keeps working unchanged when
DB_BACKEND=firestore. Selected by database/db.py.

Design notes:
- Document IDs are Firestore auto-IDs (strings), not integers.
- No JOINs in Firestore: each finding stores its endpoint's url/method
  (denormalized at write time), and session lookups attach `.endpoints`.
- Only single-field equality queries are used (no composite indexes
  needed); filtering/sorting happens in Python. The app's scale
  (dozens of sessions per user) makes this fast and free-tier friendly.
- Auth reuses the Firebase Admin app initialised from
  FIREBASE_SERVICE_ACCOUNT_JSON (dashboard/firebase_auth.py) — no
  GOOGLE_APPLICATION_CREDENTIALS file needed.
"""
from datetime import datetime
from types import SimpleNamespace
from typing import List, Optional

from config.logging_config import logger

_client = None


def _fs():
    """Lazily return the Firestore client (singleton)."""
    global _client
    if _client is None:
        from dashboard.firebase_auth import _admin_app
        _admin_app()  # raises a clear error if the service account is missing
        from firebase_admin import firestore
        _client = firestore.client()
    return _client


def _now():
    return datetime.utcnow()


def _doc_to_ns(doc, extra=None):
    """Firestore document -> SimpleNamespace with .id attribute."""
    data = doc.to_dict() or {}
    data.pop("id", None)
    ns = SimpleNamespace(id=doc.id, **data)
    if extra:
        for k, v in extra.items():
            setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

def init_db():
    """Verify Firestore connectivity (collections are created on first write)."""
    db = _fs()
    list(db.collection("users").limit(1).stream())  # 1 read; fails fast on bad creds
    logger.info("Firestore backend ready.")


# ---------------------------------------------------------------------------
# Scan sessions
# ---------------------------------------------------------------------------

_SESSION_DEFAULTS = {
    "total_endpoints_found": 0,
    "total_vulnerabilities_found": 0,
    "overall_risk_score": 0.0,
    "overall_severity": "Low",
    "status": "running",
    "scan_end_time": None,
    "progress_done": 0,
    "progress_total": 0,
    "progress_stage": "",
    "progress_updated_at": None,
    "user_id": None,
}


def save_scan_session(
    target_url: str,
    total_endpoints: int = 0,
    total_vulnerabilities: int = 0,
    overall_risk_score: float = 0.0,
    overall_severity: str = "Low",
    status: str = "running",
    user_id=None,
):
    db = _fs()
    data = dict(_SESSION_DEFAULTS)
    data.update({
        "target_url": target_url,
        "scan_start_time": _now(),
        "total_endpoints_found": total_endpoints,
        "total_vulnerabilities_found": total_vulnerabilities,
        "overall_risk_score": overall_risk_score,
        "overall_severity": overall_severity,
        "status": status,
        "updated_at": _now(),
        "user_id": user_id,
    })
    _, ref = db.collection("scan_sessions").add(data)
    return _doc_to_ns(ref.get())


def _get_session_doc(session_id):
    return _fs().collection("scan_sessions").document(str(session_id)).get()


def touch_scan_session(session_id) -> None:
    """Heartbeat: mark a running scan as alive (stale-scan reaper input)."""
    _fs().collection("scan_sessions").document(str(session_id)).update(
        {"updated_at": _now()})


def update_scan_progress(session_id, done=None, total=None, stage=None) -> None:
    """Record scan progress for the live 'time left' banner."""
    updates = {"updated_at": _now(), "progress_updated_at": _now()}
    if done is not None:
        updates["progress_done"] = max(0, int(done))
    if total is not None:
        updates["progress_total"] = max(0, int(total))
    if stage is not None:
        updates["progress_stage"] = str(stage)[:80]
    _fs().collection("scan_sessions").document(str(session_id)).update(updates)


def format_scan_eta(scan) -> str:
    """Human-friendly remaining-time estimate, e.g. 'about 2 minutes left'."""
    try:
        done = int(scan.progress_done or 0)
        total = int(scan.progress_total or 0)
        if total <= 0 or done <= 0:
            return ""
        start = scan.scan_start_time
        if not start:
            return ""
        if getattr(start, "tzinfo", None) is not None:
            start = start.replace(tzinfo=None)
        elapsed = (_now() - start).total_seconds()
        if elapsed <= 0:
            return ""
        remaining = elapsed / done * (total - done)
        if remaining < 15:
            return "less than 15 seconds left"
        if remaining < 90:
            return f"about {int(round(remaining / 5) * 5)} seconds left"
        minutes = remaining / 60
        if minutes < 90:
            return f"about {int(round(minutes))} minute{'s' if int(round(minutes)) != 1 else ''} left"
        return f"about {int(round(minutes / 5) * 5)} minutes left"
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def _user_ns(doc):
    return _doc_to_ns(doc)


def get_user_by_firebase_uid(firebase_uid: str):
    docs = list(_fs().collection("users").where("firebase_uid", "==", firebase_uid).limit(1).stream())
    return _user_ns(docs[0]) if docs else None


def get_or_create_firebase_user(firebase_uid: str, email, username: str,
                                name=None, avatar_url=None):
    """Find the local user for a Firebase UID, creating it on first sign-in."""
    existing = get_user_by_firebase_uid(firebase_uid)
    if existing:
        return existing
    data = {
        "firebase_uid": firebase_uid,
        "username": username,
        "email": email,
        "email_lower": (email or "").strip().lower() or None,
        "name": name,
        "avatar_url": avatar_url,
        "created_at": _now(),
    }
    _, ref = _fs().collection("users").add(data)
    return _doc_to_ns(ref.get())


def get_user_by_username(username: str):
    docs = list(_fs().collection("users").where("username", "==", username).limit(1).stream())
    return _user_ns(docs[0]) if docs else None


def get_user_by_email(email: str):
    """Case-insensitive email lookup (emails are matched ignoring case)."""
    key = (email or "").strip().lower()
    if not key:
        return None
    docs = list(_fs().collection("users").where("email_lower", "==", key).limit(1).stream())
    return _user_ns(docs[0]) if docs else None


def get_user_by_id(user_id):
    doc = _fs().collection("users").document(str(user_id)).get()
    return _user_ns(doc) if doc.exists else None


def update_user_name(user_id, name) -> bool:
    doc_ref = _fs().collection("users").document(str(user_id))
    if not doc_ref.get().exists:
        return False
    doc_ref.update({"name": (name or "").strip() or None})
    return True


# ---------------------------------------------------------------------------
# Endpoints & findings
# ---------------------------------------------------------------------------

def save_endpoint(session_id, url: str, method: str = "GET"):
    _, ref = _fs().collection("endpoints").add({
        "session_id": str(session_id),
        "url": url,
        "method": (method or "GET").upper(),
        "created_at": _now(),
    })
    return _doc_to_ns(ref.get())


def get_session_endpoints(session_id) -> list:
    docs = _fs().collection("endpoints").where("session_id", "==", str(session_id)).stream()
    return [_doc_to_ns(d) for d in docs]


def save_finding(
    session_id,
    endpoint_id,
    attack_type: str,
    severity: str,
    risk_score: float,
    finding_status: str = "Informational",
    signature_triggered: str = "",
    ml_score: float = 0.0,
    lstm_score: float = 0.0,
    autoencoder_score: float = 0.0,
    recommendation: str = "",
    request_payload: str = "",
    response_status: int = 200,
    response_size: int = 0,
    response_time: float = 0.0,
):
    db = _fs()
    # Denormalize the endpoint's url/method onto the finding (no JOINs in Firestore).
    ep_url, ep_method = None, "GET"
    if endpoint_id:
        ep_doc = db.collection("endpoints").document(str(endpoint_id)).get()
        if ep_doc.exists:
            ep_data = ep_doc.to_dict() or {}
            ep_url = ep_data.get("url")
            ep_method = ep_data.get("method") or "GET"
    _, ref = db.collection("findings").add({
        "session_id": str(session_id),
        "endpoint_id": str(endpoint_id) if endpoint_id else None,
        "endpoint_url": ep_url,
        "endpoint_method": ep_method,
        "attack_type": attack_type,
        "finding_status": finding_status,
        "severity": severity,
        "risk_score": float(risk_score or 0.0),
        "signature_triggered": signature_triggered,
        "ml_score": float(ml_score or 0.0),
        "lstm_score": float(lstm_score or 0.0),
        "autoencoder_score": float(autoencoder_score or 0.0),
        "recommendation": recommendation,
        "request_payload": request_payload,
        "response_status": response_status,
        "response_size": response_size,
        "response_time": response_time,
        "created_at": _now(),
    })
    return _doc_to_ns(ref.get())


def _finding_ns(doc, session_url=None):
    ns = _doc_to_ns(doc)
    ns.endpoint = SimpleNamespace(
        url=getattr(ns, "endpoint_url", None) or session_url,
        method=getattr(ns, "endpoint_method", None) or "GET",
    )
    return ns


def get_session_findings(session_id) -> List:
    docs = _fs().collection("findings").where("session_id", "==", str(session_id)).stream()
    out = []
    for d in docs:
        ns = _finding_ns(d)
        if (ns.risk_score or 0) > 0:
            out.append(ns)
    return out


def get_finding_by_id(finding_id):
    doc = _fs().collection("findings").document(str(finding_id)).get()
    if not doc.exists:
        return None
    ns = _finding_ns(doc)
    sid = getattr(ns, "session_id", None)
    ns.session = _doc_to_ns(_get_session_doc(sid)) if sid else None
    return ns


def complete_scan_session(session_id, overall_risk_score: float,
                          overall_severity: str, total_vulnerabilities: int):
    doc_ref = _fs().collection("scan_sessions").document(str(session_id))
    if not doc_ref.get().exists:
        return None
    doc_ref.update({
        "overall_risk_score": overall_risk_score,
        "overall_severity": overall_severity,
        "total_vulnerabilities_found": total_vulnerabilities,
        "scan_end_time": _now(),
        "status": "complete",
    })
    return _doc_to_ns(doc_ref.get())


def fail_scan_session(session_id, error: str = ""):
    """Mark a background scan as failed so the UI stops polling it."""
    doc_ref = _fs().collection("scan_sessions").document(str(session_id))
    if not doc_ref.get().exists:
        return None
    if error:
        logger.error(f"Scan session {session_id} failed: {error}")
    doc_ref.update({"status": "failed", "scan_end_time": _now()})
    return _doc_to_ns(doc_ref.get())


def get_all_sessions(user_id=None) -> List:
    """List scan sessions, newest first (per-user isolation when given)."""
    db = _fs()
    if user_id is not None:
        docs = db.collection("scan_sessions").where("user_id", "==", str(user_id)).stream()
    else:
        docs = db.collection("scan_sessions").stream()
    sessions = [_doc_to_ns(d) for d in docs]
    sessions.sort(key=lambda s: getattr(s, "scan_start_time", None) or datetime.min, reverse=True)
    return sessions


def get_session_for_user(session_id, user_id):
    """Fetch one session only if it belongs to the given user (else None)."""
    doc = _get_session_doc(session_id)
    if not doc.exists:
        return None
    ns = _doc_to_ns(doc)
    if user_id is not None and str(getattr(ns, "user_id", None)) != str(user_id):
        return None
    ns.endpoints = get_session_endpoints(session_id)
    return ns


def delete_session(session_id) -> bool:
    db = _fs()
    sid = str(session_id)
    if not db.collection("scan_sessions").document(sid).get().exists:
        return False
    batch = db.batch()
    count = 0

    def _flush(b):
        b.commit()

    for coll in ("findings", "endpoints"):
        for d in db.collection(coll).where("session_id", "==", sid).stream():
            batch.delete(d.reference)
            count += 1
            if count % 400 == 0:
                _flush(batch)
                batch = db.batch()
    _flush(batch)
    db.collection("scan_sessions").document(sid).delete()
    return True


def set_session_total_endpoints(session_id, count) -> None:
    """Update a session's discovered-endpoint count (scan reuse path)."""
    _fs().collection("scan_sessions").document(str(session_id)).update(
        {"total_endpoints_found": int(count), "updated_at": _now()})


def delete_user(user_id) -> bool:
    """Delete a user and all their sessions (findings/endpoints cascade)."""
    db = _fs()
    for d in db.collection("scan_sessions").where("user_id", "==", str(user_id)).stream():
        delete_session(d.id)
    user_ref = db.collection("users").document(str(user_id))
    if not user_ref.get().exists:
        return False
    user_ref.delete()
    return True
