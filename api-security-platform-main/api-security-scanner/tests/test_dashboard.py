import pytest
from dashboard.app import create_app
from database.db import save_scan_session

def test_dashboard_routes():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response_index = client.get("/")
    assert response_index.status_code == 200
    assert b"Find API vulnerabilities before attackers do" in response_index.data

    response_new_scan = client.get("/new-scan")
    assert response_new_scan.status_code == 200
    assert b"New scan" in response_new_scan.data

    response_history = client.get("/history")
    assert response_history.status_code == 200
    assert b"Scan history" in response_history.data

def test_dashboard_complete_pipeline_ui():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/new-scan")
    assert response.status_code == 200
    assert b"New scan" in response.data
    assert b"https://api.example.com" in response.data
    assert b"complete pipeline" in response.data
    assert b"Export SARIF" not in response.data
    assert b"module_sqli" not in response.data


def test_dashboard_api_routes():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    # List sessions API
    res = client.get("/api/sessions")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["status"] == "success"
    assert isinstance(json_data["sessions"], list)

    # API Scan error on missing target_url
    bad_scan = client.post("/api/scan", json={})
    assert bad_scan.status_code == 400


def test_dashboard_api_scan_uses_shared_pipeline_and_returns_sarif_url(monkeypatch):
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    session = save_scan_session(target_url="http://example.test", total_endpoints=1)
    calls = []

    def fake_launch(target_url, user_id=None):
        calls.append(target_url)
        return session.id

    monkeypatch.setattr("dashboard.routes._launch_background_scan", fake_launch)
    response = client.post("/api/scan", json={"target_url": "http://example.test"})
    assert response.status_code == 202
    payload = response.get_json()
    assert payload["status"] == "accepted"
    assert calls == ["http://example.test"]
    assert payload["session_id"] == session.id
    assert payload["results_url"].endswith(f"/results/{session.id}")
    assert payload["sarif_url"].endswith(f"/export/{session.id}?format=sarif")


def test_dashboard_api_scan_rejects_invalid_target_url():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.post("/api/scan", json={"target_url": "<script>alert(1)</script>"})
    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_dashboard_form_scan_uses_shared_pipeline(monkeypatch):
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    session = save_scan_session(target_url="http://example.test", total_endpoints=1)
    calls = []

    def fake_launch(target_url, user_id=None):
        calls.append(target_url)
        return session.id

    monkeypatch.setattr("dashboard.routes._launch_background_scan", fake_launch)
    response = client.post("/scan", data={"target_url": "http://example.test"})
    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/results/{session.id}")
    assert calls == ["http://example.test"]


def test_dashboard_form_scan_rejects_invalid_target_url():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.post("/scan", data={"target_url": "; cat /etc/passwd"})
    assert response.status_code == 400


def test_dashboard_csrf_enforcement():
    app = create_app()
    app.config["TESTING"] = True
    app.config["CSRF_ENABLED"] = True
    client = app.test_client()

    # Form post without CSRF token should fail with 400
    res_bad = client.post("/scan", data={"target_url": "http://example.test"})
    assert res_bad.status_code == 400

    # Get index page to establish session and obtain csrf token
    res_get = client.get("/")
    assert res_get.status_code == 200
    with client.session_transaction() as sess:
        token = sess.get("csrf_token")
    assert token is not None

    # Form post with valid CSRF token passes validation
    res_good = client.post("/scan", data={"target_url": "http://example.test", "csrf_token": token})
    # Will attempt to scan or redirect
    assert res_good.status_code in (302, 500)


def test_dashboard_auth_workflow():
    """Firebase session exchange -> protected pages -> logout round-trip."""
    from unittest.mock import patch
    from database.db import get_user_by_firebase_uid, SessionLocal
    from database.models import User
    app = create_app()
    app.config["TESTING"] = True
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    client = app.test_client()
    import uuid as _uuid
    username = f"authwf_user_{_uuid.uuid4().hex[:8]}"
    uid = f"fb-{_uuid.uuid4().hex[:8]}"
    claims = {"uid": uid, "email": f"{username}@gmail.com", "name": "Auth Wf"}

    # Unauthenticated visitors see the public landing page at /
    res = client.get("/")
    assert res.status_code == 200
    assert b"Find API vulnerabilities before attackers do" in res.data

    # Session exchange (mocked Firebase token) logs the user in
    with patch("dashboard.routes.verify_firebase_token", return_value=claims):
        res_session = client.post("/api/auth/session", json={
            "idToken": "fake", "username": username})
    assert res_session.status_code == 200
    assert res_session.get_json()["status"] == "ok"
    res_auth = client.get("/")
    assert res_auth.status_code == 302
    assert "/dashboard" in res_auth.headers["Location"]

    # Logout clears authentication
    res_logout = client.get("/logout")
    assert res_logout.status_code == 302
    res_after = client.get("/")
    assert res_after.status_code == 200
    assert b"Find API vulnerabilities before attackers do" in res_after.data

    # cleanup
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.firebase_uid == uid).first()
        if u:
            for s in list(u.sessions):
                db.delete(s)
            db.delete(u)
            db.commit()
    finally:
        db.close()
    assert get_user_by_firebase_uid(uid) is None

