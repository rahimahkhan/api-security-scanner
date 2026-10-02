"""Email login/signup and Sign-in-with-Google (OAuth 2.0)."""
import uuid
from unittest.mock import patch, MagicMock

import pytest

import dashboard.routes as routes
from dashboard.app import create_app
from database.db import (
    SessionLocal, create_user, get_user_by_username, get_user_by_email,
)
from database.models import User
from werkzeug.security import generate_password_hash


def _unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def authed_app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    yield app


@pytest.fixture()
def oauth_on(monkeypatch):
    monkeypatch.setattr(routes, "GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(routes, "GOOGLE_CLIENT_SECRET", "test-client-secret")


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


# --- email on password signup -------------------------------------------------

def test_signup_with_email_then_login_with_email(authed_app):
    client = authed_app.test_client()
    name = _unique("emailuser")
    email = f"{name}@example.com"
    try:
        r = client.post("/signup", data={
            "username": name, "email": email,
            "password": "password123", "confirm_password": "password123",
        })
        assert r.status_code == 302
        assert get_user_by_email(email).username == name
        client.get("/logout")
        # login via email address
        r = client.post("/login", data={"identifier": email, "password": "password123"})
        assert r.status_code == 302
        assert client.get("/").status_code == 200
        # email matching is case-insensitive
        client.get("/logout")
        r = client.post("/login", data={"identifier": email.upper(), "password": "password123"})
        assert r.status_code == 302
    finally:
        _cleanup_user(get_user_by_username(name))


def test_signup_rejects_bad_and_duplicate_email(authed_app):
    client = authed_app.test_client()
    name = _unique("badmail")
    try:
        r = client.post("/signup", data={
            "username": name, "email": "not-an-email",
            "password": "password123", "confirm_password": "password123",
        })
        assert r.status_code == 200 and b"valid email" in r.data
        # a good signup, then a second user reusing the email
        email = f"{name}@example.com"
        assert client.post("/signup", data={
            "username": name, "email": email,
            "password": "password123", "confirm_password": "password123",
        }).status_code == 302
        client.get("/logout")
        r = client.post("/signup", data={
            "username": _unique("other"), "email": email,
            "password": "password123", "confirm_password": "password123",
        })
        assert r.status_code == 200 and b"already exists" in r.data
    finally:
        _cleanup_user(get_user_by_username(name))


# --- Google button visibility --------------------------------------------------

def test_google_button_hidden_without_config(authed_app):
    client = authed_app.test_client()
    assert b"Continue with Google" not in client.get("/login").data
    assert b"Sign up with Google" not in client.get("/signup").data
    # /auth/google without config just bounces to login
    r = client.get("/auth/google")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_google_button_shown_with_config(authed_app, oauth_on):
    client = authed_app.test_client()
    assert b"Continue with Google" in client.get("/login").data
    assert b"Sign up with Google" in client.get("/signup").data
    r = client.get("/auth/google")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert "accounts.google.com" in loc and "code" in loc and "state=" in loc


# --- Google callback -----------------------------------------------------------

def _mock_google(monkeypatch, profile):
    token = MagicMock()
    token.json.return_value = {"access_token": "tok123"}
    token.raise_for_status.return_value = None
    info = MagicMock()
    info.json.return_value = profile
    info.raise_for_status.return_value = None
    monkeypatch.setattr(routes.requests, "post", MagicMock(return_value=token))
    monkeypatch.setattr(routes.requests, "get", MagicMock(return_value=info))


def _begin_oauth(client):
    with client.session_transaction() as sess:
        sess["google_oauth_state"] = "test-state-123"


def test_google_callback_creates_and_logs_in(authed_app, oauth_on, monkeypatch):
    client = authed_app.test_client()
    _mock_google(monkeypatch, {
        "sub": "google-sub-1", "email": "guser1@example.com",
        "email_verified": True, "name": "G User", "picture": "http://x/pic.png",
    })
    _begin_oauth(client)
    try:
        r = client.get("/auth/google/callback?code=authcode&state=test-state-123")
        assert r.status_code == 302 and r.headers["Location"].endswith("/")
        user = get_user_by_email("guser1@example.com")
        assert user is not None and user.google_id == "google-sub-1"
        assert client.get("/").status_code == 200
    finally:
        _cleanup_user(get_user_by_email("guser1@example.com"))


def test_google_callback_links_existing_email_account(authed_app, oauth_on, monkeypatch):
    client = authed_app.test_client()
    name = _unique("linkme")
    email = f"{name}@example.com"
    user = create_user(name, generate_password_hash("password123"), email=email)
    try:
        _mock_google(monkeypatch, {
            "sub": "google-sub-2", "email": email,
            "email_verified": True, "name": "Link Me",
        })
        _begin_oauth(client)
        r = client.get("/auth/google/callback?code=authcode&state=test-state-123")
        assert r.status_code == 302
        linked = get_user_by_username(name)
        assert linked.google_id == "google-sub-2"
        # password login still works after linking
        client.get("/logout")
        r = client.post("/login", data={"identifier": name, "password": "password123"})
        assert r.status_code == 302
    finally:
        _cleanup_user(get_user_by_username(name))


def test_google_callback_rejects_bad_state(authed_app, oauth_on, monkeypatch):
    client = authed_app.test_client()
    _mock_google(monkeypatch, {"sub": "x", "email": "x@example.com", "email_verified": True})
    with client.session_transaction() as sess:
        sess["google_oauth_state"] = "real-state"
    r = client.get("/auth/google/callback?code=authcode&state=wrong-state")
    assert r.status_code == 200 and b"Invalid OAuth state" in r.data
    assert get_user_by_email("x@example.com") is None


def test_google_callback_rejects_unverified_email(authed_app, oauth_on, monkeypatch):
    client = authed_app.test_client()
    _mock_google(monkeypatch, {
        "sub": "google-sub-3", "email": "unverified@example.com", "email_verified": False,
    })
    _begin_oauth(client)
    r = client.get("/auth/google/callback?code=authcode&state=test-state-123")
    assert r.status_code == 200 and b"not verified" in r.data
    assert get_user_by_email("unverified@example.com") is None


def test_username_suggestion_is_unique_and_valid(authed_app):
    name = _unique("taken")
    user = create_user(name, generate_password_hash("password123"))
    try:
        # same base name -> suffixed; weird chars stripped; short names padded
        assert routes._suggest_username(f"{name}@example.com", name) != name
        assert routes.USERNAME_RE.match(routes._suggest_username("a@b.co", "a b"))
        assert routes.USERNAME_RE.match(routes._suggest_username("x@y.zz", "***"))
    finally:
        _cleanup_user(user)
