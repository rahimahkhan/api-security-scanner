"""Built-in demo login (development period): one click, no credentials.

The login page must show the "Try the demo account" button with zero
environment setup, POST /api/auth/demo must open a real session for the
shared demo account, and XPLOITER_DEMO_LOGIN=0 must turn it all off.
"""
from dashboard.app import create_app


def _client():
    app = create_app()
    app.config["TESTING"] = True
    # Production runs with auth enabled; tests must opt in explicitly
    # (is_auth_enabled() defaults to off under TESTING).
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    return app.test_client()


def test_login_page_shows_demo_button_without_any_setup():
    client = _client()
    res = client.get("/login")
    assert res.status_code == 200
    assert b'id="demo-btn"' in res.data
    assert b"Try the demo account" in res.data


def test_demo_signin_opens_a_working_session():
    client = _client()
    res = client.post("/api/auth/demo", json={})
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"
    # /account requires login: a 200 here proves the session was opened.
    account = client.get("/account")
    assert account.status_code == 200
    assert b"demo" in account.data.lower()


def test_demo_signin_is_idempotent():
    first = _client()
    second = _client()
    assert first.post("/api/auth/demo", json={}).status_code == 200
    assert second.post("/api/auth/demo", json={}).status_code == 200
    assert first.get("/account").status_code == 200
    assert second.get("/account").status_code == 200


def test_demo_login_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("XPLOITER_DEMO_LOGIN", "0")
    client = _client()
    res = client.post("/api/auth/demo", json={})
    assert res.status_code == 404
    page = client.get("/login")
    assert b'id="demo-btn"' not in page.data
