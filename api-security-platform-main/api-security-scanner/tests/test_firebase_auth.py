"""Firebase Authentication: session exchange, validation, per-user isolation,
and the stale-scan reaper (adapted from the old password-auth tests)."""
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from dashboard.app import create_app
from database.db import (
    SessionLocal, save_scan_session, delete_session,
    get_user_by_username, get_user_by_firebase_uid,
    get_or_create_firebase_user,
)
from database.models import User


def _unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def authed_app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    yield app


def _claims(uid="uid-123", email="someone@gmail.com", name="Some One"):
    return {"uid": uid, "email": email, "name": name}


def _start_session(client, uid="uid-123", email="someone@gmail.com",
                   username="testuser", name="Some One", next_url="/"):
    """POST /api/auth/session with a mocked verified Firebase token."""
    with patch("dashboard.routes.verify_firebase_token",
               return_value=_claims(uid, email, name)):
        return client.post("/api/auth/session",
                           json={"idToken": "fake-id-token",
                                 "username": username, "next": next_url})


def _cleanup_user(user):
    if user is None:
        return
    db = SessionLocal()
    try:
        db_user = db.query(User).filter(User.id == user.id).first()
        if db_user:
            for s in list(db_user.sessions):
                db.delete(s)
            db.delete(db_user)
            db.commit()
    finally:
        db.close()


@pytest.fixture()
def user_a(authed_app):
    client = authed_app.test_client()
    username, uid = _unique("alice"), f"fb-{uuid.uuid4().hex[:8]}"
    r = _start_session(client, uid=uid, email=f"{username}@gmail.com",
                       username=username)
    assert r.status_code == 200, r.data[:200]
    user = get_user_by_firebase_uid(uid)
    yield client, user
    _cleanup_user(user)


@pytest.fixture()
def user_b(authed_app):
    client = authed_app.test_client()
    username, uid = _unique("bob"), f"fb-{uuid.uuid4().hex[:8]}"
    r = _start_session(client, uid=uid, email=f"{username}@gmail.com",
                       username=username)
    assert r.status_code == 200, r.data[:200]
    user = get_user_by_firebase_uid(uid)
    yield client, user
    _cleanup_user(user)


# --- session exchange ---------------------------------------------------------

def test_session_exchange_creates_user_and_logs_in(authed_app):
    client = authed_app.test_client()
    username, uid = _unique("fbsignup"), f"fb-{uuid.uuid4().hex[:8]}"
    email = f"{username}@gmail.com"
    try:
        assert get_user_by_firebase_uid(uid) is None
        r = _start_session(client, uid=uid, email=email, username=username)
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"
        user = get_user_by_firebase_uid(uid)
        assert user is not None and user.username == username
        assert user.email == email
        # server session is set: landing stays public, dashboard loads
        r = client.get("/")
        assert r.status_code == 200
        assert client.get("/dashboard").status_code == 200
    finally:
        _cleanup_user(get_user_by_firebase_uid(uid))


def test_session_exchange_existing_user_no_duplicate(authed_app):
    client = authed_app.test_client()
    username, uid = _unique("fbagain"), f"fb-{uuid.uuid4().hex[:8]}"
    try:
        assert _start_session(client, uid=uid, username=username).status_code == 200
        first_id = get_user_by_firebase_uid(uid).id
        # second sign-in with the same Firebase uid reuses the row
        other = authed_app.test_client()
        assert _start_session(other, uid=uid, username="different-name").status_code == 200
        assert get_user_by_firebase_uid(uid).id == first_id
        assert get_user_by_username("different-name") is None
    finally:
        _cleanup_user(get_user_by_firebase_uid(uid))


def test_session_exchange_invalid_token_401(authed_app):
    client = authed_app.test_client()
    with patch("dashboard.routes.verify_firebase_token",
               side_effect=Exception("bad token")):
        r = client.post("/api/auth/session", json={"idToken": "bogus"})
    assert r.status_code == 401
    assert r.get_json()["status"] == "error"


def test_session_exchange_missing_token_400(authed_app):
    client = authed_app.test_client()
    r = client.post("/api/auth/session", json={})
    assert r.status_code == 400


def test_session_exchange_rejects_bad_username(authed_app):
    client = authed_app.test_client()
    r = _start_session(client, uid=f"fb-{uuid.uuid4().hex[:8]}", username="ab")
    assert r.status_code == 400
    assert b"3-32 characters" in r.data


def test_session_exchange_rejects_taken_username(authed_app, user_a):
    _, existing = user_a
    client = authed_app.test_client()
    r = _start_session(client, uid=f"fb-{uuid.uuid4().hex[:8]}",
                       username=existing.username)
    assert r.status_code == 400
    assert b"already taken" in r.data


def test_session_exchange_rejects_disallowed_email(authed_app):
    # Server-side email allow-list: the verified token email is authoritative.
    client = authed_app.test_client()
    r = _start_session(client, uid=f"fb-{uuid.uuid4().hex[:8]}",
                       email="someone@yahoo.com")
    assert r.status_code == 400
    assert b"gmail.com or @email.com" in r.data


def test_session_exchange_derives_username_when_missing(authed_app):
    # Google sign-in flow: no typed username -> derived from the Firebase name.
    client = authed_app.test_client()
    uid = f"fb-{uuid.uuid4().hex[:8]}"
    try:
        with patch("dashboard.routes.verify_firebase_token",
                   return_value=_claims(uid, "newperson@gmail.com", "New Person")):
            r = client.post("/api/auth/session",
                            json={"idToken": "fake", "username": ""})
        assert r.status_code == 200
        user = get_user_by_firebase_uid(uid)
        assert user is not None and user.username.startswith("New.Person")
    finally:
        _cleanup_user(get_user_by_firebase_uid(uid))


def test_session_exchange_auth_disabled(authed_app):
    authed_app.config["DASHBOARD_AUTH_ENABLED"] = False
    try:
        client = authed_app.test_client()
        r = _start_session(client)
        assert r.status_code == 400
    finally:
        authed_app.config["DASHBOARD_AUTH_ENABLED"] = True


def test_login_page_renders_with_firebase_config(authed_app):
    client = authed_app.test_client()
    r = client.get("/login")
    assert r.status_code == 200
    assert b"firebase" in r.data.lower() or b"Continue with Google" in r.data


def test_forgot_password_page_renders(authed_app, monkeypatch):
    for var, val in [("FIREBASE_API_KEY", "key"), ("FIREBASE_AUTH_DOMAIN", "x.firebaseapp.com"),
                     ("FIREBASE_PROJECT_ID", "x"), ("FIREBASE_APP_ID", "1:2:3")]:
        monkeypatch.setenv(var, val)
    client = authed_app.test_client()
    r = client.get("/forgot-password")
    assert r.status_code == 200
    assert b"Send reset link" in r.data
    assert b"sendPasswordResetEmail" in r.data


def test_auth_pages_show_setup_message_without_config(authed_app, monkeypatch):
    for var in ["FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN",
                "FIREBASE_PROJECT_ID", "FIREBASE_APP_ID"]:
        monkeypatch.delenv(var, raising=False)
    client = authed_app.test_client()
    assert b"isn't set up" in client.get("/login").data
    assert b"isn't set up" in client.get("/signup").data
    assert b"isn't set up" in client.get("/forgot-password").data


# --- session behavior (adapted) ------------------------------------------------

def test_unauthenticated_redirects(authed_app):
    client = authed_app.test_client()
    r = client.get("/")
    assert r.status_code == 200  # public landing page for visitors
    assert b"Find API vulnerabilities before attackers do" in r.data
    # Login is optional: pages are public...
    r = client.get("/history")
    assert r.status_code == 200
    r = client.get("/api/sessions")
    assert r.status_code == 200
    assert r.get_json()["sessions"] == []
    # ...but other users' data stays hidden and destructive/settings
    # pages still require login.
    r = client.get("/settings")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_logout(authed_app, user_a):
    client, _ = user_a
    r = client.get("/")
    assert r.status_code == 200
    client.get("/logout")
    r = client.get("/")
    assert r.status_code == 200  # back to the public landing page


def test_scan_isolation_between_users(authed_app, user_a, user_b):
    client_a, user_a_obj = user_a
    client_b, _ = user_b
    sess = save_scan_session(target_url="http://example.test/a", status="complete",
                             user_id=user_a_obj.id)
    try:
        assert b"example.test/a" not in client_b.get("/history").data
        assert b"example.test/a" in client_a.get("/history").data
        assert client_b.get(f"/results/{sess.id}").status_code == 404
        assert client_b.get(f"/api/sessions/{sess.id}").status_code == 404
        assert client_b.delete(f"/api/sessions/{sess.id}").status_code == 404
        assert client_a.get(f"/results/{sess.id}").status_code == 200
        assert client_a.get(f"/api/sessions/{sess.id}").status_code == 200
        api_list = client_a.get("/api/sessions").get_json()["sessions"]
        assert any(s["id"] == sess.id for s in api_list)
        api_list_b = client_b.get("/api/sessions").get_json()["sessions"]
        assert not any(s["id"] == sess.id for s in api_list_b)
    finally:
        delete_session(sess.id)


def test_login_page_sidebar_leaks_nothing(authed_app, user_a):
    _, user_a_obj = user_a
    sess = save_scan_session(target_url="http://example.test/secret", status="complete",
                             user_id=user_a_obj.id)
    try:
        anon = authed_app.test_client()
        page = anon.get("/login").data
        assert b"example.test/secret" not in page
    finally:
        delete_session(sess.id)


def test_stale_running_scan_is_reaped(authed_app, user_a):
    client, user = user_a
    sess = save_scan_session(target_url="http://example.test/stale", status="running",
                             user_id=user.id)
    try:
        db = SessionLocal()
        try:
            obj = db.query(type(sess)).filter(type(sess).id == sess.id).first()
            obj.updated_at = datetime.utcnow() - timedelta(hours=1)
            db.commit()
        finally:
            db.close()
        r = client.get(f"/results/{sess.id}")
        assert r.status_code == 200
        assert b"Scan failed" in r.data
        assert b"Scan in progress" not in r.data
        api = client.get(f"/api/sessions/{sess.id}").get_json()
        assert api["session"]["scan_status"] == "failed"
    finally:
        delete_session(sess.id)


def test_fresh_running_scan_is_not_reaped(authed_app, user_a):
    client, user = user_a
    sess = save_scan_session(target_url="http://example.test/fresh", status="running",
                             user_id=user.id)
    try:
        r = client.get(f"/results/{sess.id}")
        assert r.status_code == 200
        assert b"Scan in progress" in r.data
        api = client.get(f"/api/sessions/{sess.id}").get_json()
        assert api["session"]["scan_status"] == "running"
    finally:
        delete_session(sess.id)


def test_get_or_create_firebase_user_helper(authed_app):
    uid = f"fb-{uuid.uuid4().hex[:8]}"
    try:
        u1 = get_or_create_firebase_user(uid, "helper@gmail.com", _unique("fbhelp"))
        u2 = get_or_create_firebase_user(uid, "helper@gmail.com", "other-name")
        assert u1.id == u2.id  # same Firebase uid -> same row
        assert get_user_by_firebase_uid(uid).username == u1.username
    finally:
        _cleanup_user(get_user_by_firebase_uid(uid))


def test_admin_sdk_really_initializes(monkeypatch):
    """Regression test: _admin_app() must actually call initialize_app().

    A name-shadowing bug once made the cache variable share the function's
    name (``_admin_app``), so the function returned itself immediately and the
    Admin SDK was never initialized — live, every login failed with
    "The default Firebase app does not exist". All route tests mock
    verify_firebase_token, so only this test exercises the real init path.
    """
    import json

    import firebase_admin
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from dashboard import firebase_auth

    # Throwaway RSA key: only needs to parse, never used against Google.
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    fake_sa = {
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "key1",
        "private_key": pem,
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "client_id": "1",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    monkeypatch.setenv("FIREBASE_SERVICE_ACCOUNT_JSON", json.dumps(fake_sa))
    firebase_auth.reset_admin_app_cache()
    app = None
    try:
        app = firebase_auth._admin_app()
        assert firebase_admin.get_app() is app  # SDK really initialized
        assert firebase_auth._admin_app() is app  # singleton cached
    finally:
        firebase_auth.reset_admin_app_cache()
        if app is not None:
            try:
                firebase_admin.delete_app(app)
            except Exception:
                pass


def test_admin_sdk_missing_key_raises(monkeypatch):
    """Without the service-account env var, init must fail loudly."""
    from dashboard import firebase_auth

    monkeypatch.delenv("FIREBASE_SERVICE_ACCOUNT_JSON", raising=False)
    firebase_auth.reset_admin_app_cache()
    try:
        with pytest.raises(RuntimeError, match="not set"):
            firebase_auth._admin_app()
    finally:
        firebase_auth.reset_admin_app_cache()


# --- email-or-username login identifier resolution ---------------------------

def test_resolve_email_passthrough(authed_app):
    client = authed_app.test_client()
    r = client.post("/api/auth/resolve",
                    json={"identifier": "Someone@Gmail.com"})
    assert r.status_code == 200
    assert r.get_json()["email"] == "someone@gmail.com"


def test_resolve_username_to_email(authed_app):
    client = authed_app.test_client()
    username, uid = _unique("carol"), f"fb-{uuid.uuid4().hex[:8]}"
    email = f"{username}@gmail.com"
    try:
        get_or_create_firebase_user(uid, email, username)
        r = client.post("/api/auth/resolve", json={"identifier": username})
        assert r.status_code == 200
        assert r.get_json()["email"] == email
    finally:
        _cleanup_user(get_user_by_firebase_uid(uid))


def test_resolve_unknown_username_404(authed_app):
    client = authed_app.test_client()
    r = client.post("/api/auth/resolve",
                    json={"identifier": "no_such_user_xyz"})
    assert r.status_code == 404


def test_resolve_bad_input(authed_app):
    client = authed_app.test_client()
    r = client.post("/api/auth/resolve", json={"identifier": ""})
    assert r.status_code == 400
    r = client.post("/api/auth/resolve", json={"identifier": "bad@x"})
    assert r.status_code == 400
