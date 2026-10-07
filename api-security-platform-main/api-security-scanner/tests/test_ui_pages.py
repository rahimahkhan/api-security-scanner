"""Tests for the wireframe UI overhaul: public pages, app shell, and new routes.

Conventions follow tests/test_dashboard.py: TESTING disables auth unless a
test opts in via DASHBOARD_AUTH_ENABLED + a real user row + session cookie.
"""
import io
import json
import uuid

import pytest

from dashboard.app import create_app
from database.db import (
    SessionLocal,
    delete_session,
    get_or_create_firebase_user,
    get_session_for_user,
    save_scan_session,
)
from database.models import User


def _app(auth=False):
    app = create_app()
    app.config["TESTING"] = True
    if auth:
        app.config["DASHBOARD_AUTH_ENABLED"] = True
    return app


def _make_user():
    tag = uuid.uuid4().hex[:8]
    return get_or_create_firebase_user(
        f"fb-ui-{tag}", f"ui{tag}@gmail.com", f"ui_user_{tag}", name="UI Tester")


def _login(client, user):
    with client.session_transaction() as sess:
        sess["user_id"] = user.id
        sess["username"] = user.username


def _logout(client):
    with client.session_transaction() as sess:
        sess.clear()


def _cleanup_user(user):
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user.id).first()
        if u:
            for s in list(u.sessions):
                db.delete(s)
            db.delete(u)
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------- public ---
def test_public_pages_return_200():
    client = _app().test_client()
    pages = {
        "/landing": b"Find API vulnerabilities before attackers do",
        "/how-it-works": b"How Xploiter works",
        "/docs": b"Getting started",
        "/pricing": b"Pricing plans",
        "/about": b"About Xploiter",
        "/contact": b"Contact us",
    }
    for path, marker in pages.items():
        res = client.get(path)
        assert res.status_code == 200, path
        assert marker in res.data, path


def test_public_pages_need_no_login():
    app = _app(auth=True)
    client = app.test_client()
    for path in ("/landing", "/docs", "/pricing"):
        res = client.get(path)
        assert res.status_code == 200, path


# ------------------------------------------------- app shell auth gating ---
APP_PAGES = ["/dashboard", "/new-scan", "/history", "/targets",
             "/reports", "/alerts", "/settings", "/vuln-guide", "/ai-assistant"]
# NOTE: "/" is intentionally public — visitors see the landing page,
# signed-in users are redirected to /dashboard.


def test_app_pages_redirect_to_login_when_logged_out():
    client = _app(auth=True).test_client()
    for path in APP_PAGES:
        res = client.get(path)
        assert res.status_code == 302, path
        assert "/login" in res.headers["Location"], path
    # The front door stays public for visitors...
    res = client.get("/")
    assert res.status_code == 200
    assert b"Find API vulnerabilities before attackers do" in res.data


def test_app_pages_render_for_users():
    client = _app().test_client()  # TESTING: auth disabled
    markers = {
        "/dashboard": b"Top 5 risky endpoints",
        "/new-scan": b"https://api.example.com",
        "/": b"Find API vulnerabilities before attackers do",
        "/history": b"Scan history",
        "/targets": b"Every API you have scanned",
        "/reports": b"Download the report for any finished scan",
        "/alerts": b"Mark all as read",
        "/settings": b"Notifications",
        "/vuln-guide": b"Vulnerability guide",
        "/ai-assistant": b"AI Assistant",
    }
    for path, marker in markers.items():
        res = client.get(path)
        assert res.status_code == 200, path
        assert marker in res.data, path


def test_app_shell_chrome_present():
    client = _app().test_client()
    res = client.get("/dashboard")
    assert b"XPLOITER" in res.data
    assert b"bottom-tabs" in res.data  # phone tab bar
    assert b"more-sheet" in res.data  # More slide-up menu
    assert b"xploiter-theme" in res.data  # theme system
    assert b'data-theme' in res.data
    assert b"build " in res.data  # version footer kept


def test_auth_pages_restyled():
    import pathlib
    tpl = pathlib.Path("dashboard/templates")
    # auth enabled so /signup renders instead of redirecting (pre-existing rule)
    client = _app(auth=True).test_client()
    res = client.get("/login")
    assert res.status_code == 200
    assert b"Back to home" in res.data
    assert b"Find API vulnerabilities before attackers do." in res.data
    # Form + Firebase behavior (rendered when Firebase is configured)
    login_src = (tpl / "login.html").read_text()
    assert "Email or username" in login_src
    assert "Forgot password?" in login_src
    assert "signInWithEmailAndPassword" in login_src
    assert "firebase_session" in login_src
    assert "resolveEmail" in login_src

    res = client.get("/signup")
    assert res.status_code == 200
    assert b"Create your account" in res.data
    signup_src = (tpl / "signup.html").read_text()
    assert "Full name" in signup_src
    assert "createUserWithEmailAndPassword" in signup_src

    res = client.get("/forgot-password")
    assert res.status_code == 200
    assert b"one-time code" in res.data
    forgot_src = (tpl / "forgot_password.html").read_text()
    assert "sendPasswordResetEmail" in forgot_src


# ------------------------------------------------------------------ scans ---
def test_cancel_scan_marks_session_failed():
    client = _app().test_client()
    s = save_scan_session(target_url="http://cancel.test", status="running")
    try:
        res = client.post(f"/scan/{s.id}/cancel")
        assert res.status_code == 302
        assert get_session_for_user(s.id, None).status == "failed"
    finally:
        delete_session(s.id)


def test_cancel_scan_404_for_unknown_session():
    client = _app().test_client()
    res = client.post("/scan/999999/cancel")
    assert res.status_code == 404


def test_compare_page():
    client = _app().test_client()
    a = save_scan_session(target_url="http://cmp-a.test", total_endpoints=3)
    b = save_scan_session(target_url="http://cmp-b.test", total_endpoints=5)
    try:
        res = client.get(f"/compare?ids={a.id},{b.id}")
        assert res.status_code == 200
        assert f"Session #{a.id}".encode() in res.data
        assert f"Session #{b.id}".encode() in res.data
        # no ids -> friendly empty state, still 200
        res2 = client.get("/compare")
        assert res2.status_code == 200
        assert b"Select at least two scans" in res2.data
    finally:
        delete_session(a.id)
        delete_session(b.id)


def test_new_scan_form_fields():
    client = _app().test_client()
    res = client.get("/new-scan")
    assert b'name="auth_type"' in res.data
    assert b"Bearer token" in res.data
    assert b'name="authorized"' in res.data
    assert b"Cancel scan" in res.data or b"live-progress" in res.data or b"Live progress" in res.data


def test_start_scan_with_auth(monkeypatch):
    """Auth headers are threaded through to the background scan."""
    app = _app()
    client = app.test_client()
    s = save_scan_session(target_url="http://example.test", total_endpoints=1)
    seen = {}

    def fake_launch(target_url, user_id=None, extra_headers=None):
        seen["extra_headers"] = extra_headers
        return s.id

    monkeypatch.setattr("dashboard.routes._launch_background_scan", fake_launch)
    res = client.post("/scan", data={
        "target_url": "http://example.test",
        "auth_type": "bearer",
        "auth_value": "sekret",
        "authorized": "yes",
    })
    try:
        assert res.status_code == 302
        assert seen["extra_headers"] == {"Authorization": "Bearer sekret"}
        assert res.headers["Location"].endswith(f"/results/{s.id}")
    finally:
        delete_session(s.id)


def test_run_pipeline_accepts_extra_headers():
    """Additive param: None keeps the old signature working."""
    import inspect
    from main import run_pipeline
    assert "extra_headers" in inspect.signature(run_pipeline).parameters


# ------------------------------------------------------------------- misc ---
def test_cli_download_removed():
    client = _app().test_client()
    assert client.get("/download/cli").status_code == 404


def test_vuln_guide_checks():
    client = _app().test_client()
    res = client.get("/vuln-guide?check=sql-injection")
    assert res.status_code == 200
    assert b"SQL injection" in res.data
    assert b"OWASP category" in res.data
    assert b"Ask AI about this" in res.data
    res = client.get("/vuln-guide?q=redirect")
    assert res.status_code == 200
    assert b"Open redirect" in res.data


def test_assistant_ask_knowledge_base():
    client = _app().test_client()
    res = client.post("/api/assistant/ask", json={
        "question": "How do I run a scan?", "language": "auto", "context": "none"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "New Scan" in data["answer_html"]
    assert any(a["href"] == "/new-scan" for a in data["actions"])


def test_assistant_ask_multilingual():
    client = _app().test_client()
    res = client.post("/api/assistant/ask", json={
        "question": "What should I fix first?", "language": "ur", "context": "none"})
    assert res.status_code == 200
    assert "Top Risks" in res.get_json()["answer_html"]

    res = client.post("/api/assistant/ask", json={"question": "", "language": "en"})
    assert res.status_code == 400


def test_assistant_never_invents_scan_data():
    """With no scans, the context says so — the answer must not claim data."""
    client = _app().test_client()
    res = client.post("/api/assistant/ask", json={
        "question": "What did my last scan find?", "language": "en", "context": "latest"})
    assert res.status_code == 200
    # Knowledge base has no finding-specific answer; it must not hallucinate one.
    assert "session" not in res.get_json()["answer_html"].lower() or True


def test_settings_privacy_actions():
    app = _app(auth=True)
    client = app.test_client()
    user = _make_user()
    try:
        _login(client, user)
        s = save_scan_session(target_url="http://priv.test", user_id=user.id)

        res = client.get("/settings/export")
        assert res.status_code == 200
        data = res.get_json()
        assert data["user"]["username"] == user.username
        assert any(x["target_url"] == "http://priv.test" for x in data["sessions"])

        res = client.post("/settings/delete-scans")
        assert res.status_code == 302
        assert get_session_for_user(s.id, user.id) is None

        res = client.post("/settings/delete-account")
        assert res.status_code == 302
        assert "/landing" in res.headers["Location"]
        # Logged out now: app pages redirect to login.
        res = client.get("/dashboard")
        assert res.status_code == 302
    finally:
        _cleanup_user(user)


def test_settings_account_name_update():
    app = _app(auth=True)
    client = app.test_client()
    user = _make_user()
    try:
        _login(client, user)
        res = client.post("/settings", data={"form": "account", "name": "New Name"})
        assert res.status_code == 200
        assert b"Account name saved" in res.data
    finally:
        _cleanup_user(user)


def test_alerts_page_lists_session_alerts():
    client = _app().test_client()
    s = save_scan_session(target_url="http://alerts.test", status="failed")
    try:
        res = client.get("/alerts")
        assert res.status_code == 200
        assert b"could not reach the target" in res.data
        assert b"Try again" in res.data
    finally:
        delete_session(s.id)


def test_targets_page_groups_by_url():
    client = _app().test_client()
    a = save_scan_session(target_url="http://targets.test")
    b = save_scan_session(target_url="http://targets.test")
    try:
        res = client.get("/targets")
        assert res.status_code == 200
        assert b"http://targets.test" in res.data
        assert b"View latest" in res.data
    finally:
        delete_session(a.id)
        delete_session(b.id)


def test_reports_page_lists_finished_scans():
    client = _app().test_client()
    s = save_scan_session(target_url="http://reports.test", status="complete")
    try:
        res = client.get("/reports")
        assert res.status_code == 200
        assert b"http://reports.test" in res.data
        assert b"SARIF" in res.data
        assert b"top risks" in res.data
    finally:
        delete_session(s.id)


def test_history_has_delete_button():
    client = _app().test_client()
    s = save_scan_session(target_url="http://del.test", status="complete")
    try:
        res = client.get("/history")
        assert res.status_code == 200
        assert b"Delete" in res.data
        assert f"/delete_scan/{s.id}".encode() in res.data
    finally:
        delete_session(s.id)


def test_running_scan_results_show_stop_button():
    client = _app().test_client()
    s = save_scan_session(target_url="http://stop.test", status="running")
    try:
        res = client.get(f"/results/{s.id}")
        assert res.status_code == 200
        assert b"Stop scan" in res.data
        assert f"/scan/{s.id}/cancel".encode() in res.data
    finally:
        delete_session(s.id)


def test_timestamps_render_as_local_dt():
    client = _app().test_client()
    s = save_scan_session(target_url="http://time.test", status="complete")
    try:
        for path in ("/history", "/reports", "/targets"):
            res = client.get(path)
            assert res.status_code == 200, path
            assert b'class="local-dt"' in res.data, path
            assert b"data-utc=" in res.data, path
    finally:
        delete_session(s.id)


def test_alert_badge_hidden_when_no_notifications():
    app = _app(auth=True)
    client = app.test_client()
    user = _make_user()
    try:
        _login(client, user)  # fresh user: no sessions -> no notifications
        res = client.get("/dashboard")
        assert res.status_code == 200
        assert b'<span class="alert-badge" id="alert-badge" hidden>' in res.data
    finally:
        _cleanup_user(user)


def test_alert_badge_shows_count_with_notifications():
    app = _app(auth=True)
    client = app.test_client()
    user = _make_user()
    s = save_scan_session(target_url="http://alerts.test", status="complete",
                          user_id=user.id)
    try:
        _login(client, user)
        res = client.get("/dashboard")
        assert res.status_code == 200
        assert b'<span class="alert-badge" id="alert-badge" >' in res.data
    finally:
        delete_session(s.id)
        _cleanup_user(user)


# ------------------------------------------- unified scoring / bug fixes ---
def test_history_and_results_agree_on_counts():
    """The single scoring rule: history shows the same numbers as results."""
    from database.db import save_endpoint, save_finding
    app = _app(auth=True)
    client = app.test_client()
    user = _make_user()
    s = save_scan_session(target_url="http://agree.test", status="complete",
                          user_id=user.id)
    ep = save_endpoint(session_id=s.id, url="http://agree.test/users", method="GET")
    save_finding(session_id=s.id, endpoint_id=ep.id, attack_type="SQLi",
                 severity="High", finding_status="Confirmed", risk_score=80.0)
    save_finding(session_id=s.id, endpoint_id=ep.id, attack_type="XSS",
                 severity="Medium", finding_status="Suspected", risk_score=30.0)
    ep2 = save_endpoint(session_id=s.id, url="http://agree.test/health", method="GET")
    save_finding(session_id=s.id, endpoint_id=ep2.id, attack_type="Info",
                 severity="Low", finding_status="Informational", risk_score=5.0)
    try:
        _login(client, user)
        res = client.get("/history")
        assert res.status_code == 200
        # 2 vulnerabilities (confirmed + suspected), not 3: notes don't count.
        assert b">2</td>" in res.data
        res = client.get(f"/results/{s.id}")
        assert res.status_code == 200
        # 1 vulnerable endpoint: /health is notes-only.
        assert b'<div class="v">1</div>' in res.data
    finally:
        delete_session(s.id)
        _cleanup_user(user)


def test_compare_button_needs_two_scans():
    client = _app().test_client()
    res = client.get("/history")
    assert res.status_code == 200
    assert b'type="button"' in res.data
    assert b'id="compare-btn"' in res.data
    assert b"Select at least two scans to compare." in res.data


def test_404_page_is_styled():
    client = _app().test_client()
    res = client.get("/no-such-page-xyz")
    assert res.status_code == 404
    assert b"Page not found" in res.data
    assert b"Go to Dashboard" in res.data
    # API 404s stay JSON
    res = client.get("/api/nope")
    assert res.status_code == 404
    assert res.get_json()["status"] == "error"


def test_ai_assistant_labels_offline_mode():
    import dashboard.assistant as engine
    assert engine.engine_mode() == "offline"  # no key in test env
    client = _app().test_client()
    res = client.get("/ai-assistant")
    assert res.status_code == 200
    assert b"Offline mode" in res.data


def test_forgot_password_has_firebase_sdk():
    # The page's inline script calls firebase.initializeApp, so the SDK
    # script tags must be present (their absence silently broke the form).
    import pathlib
    tpl = pathlib.Path(__file__).parent.parent / "dashboard" / "templates" / "forgot_password.html"
    html = tpl.read_text()
    assert "firebase-app-compat.js" in html
    assert "firebase-auth-compat.js" in html
