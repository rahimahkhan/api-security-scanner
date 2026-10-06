"""Forgot-password via emailed OTP (alongside the Firebase reset link).

Covers: request (validation, allow-list, cooldown, hourly cap, generic
reply for unknown emails, SMTP failure), verify (correct/wrong/lockout/
expiry), reset (password policy, match, verified-only, single-use, and the
Firebase Admin password update).
"""
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dashboard.app import create_app
from dashboard.routes import _hash_otp
from database.db import (
    SessionLocal, create_reset_otp, get_latest_valid_reset_otp,
    count_recent_otps,
)
from database.models import PasswordResetOTP


def _unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def authed_app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    yield app


@pytest.fixture()
def otp_email():
    email = f"{_unique('otpuser')}@gmail.com"
    yield email
    db = SessionLocal()
    try:
        db.query(PasswordResetOTP).filter(
            PasswordResetOTP.email == email).delete()
        db.commit()
    finally:
        db.close()


def _make_otp(email, otp="123456", minutes=15):
    return create_reset_otp(email, _hash_otp(otp),
                            datetime.utcnow() + timedelta(minutes=minutes))


def _fb_user(email="someone@gmail.com"):
    return SimpleNamespace(uid="fb-test-uid", email=email)


@pytest.fixture()
def smtp_env(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "test@gmail.com")
    monkeypatch.setenv("SMTP_PASSWORD", "fake-app-password")


# --- request -------------------------------------------------------------

def test_otp_request_sends_code(authed_app, otp_email, smtp_env):
    client = authed_app.test_client()
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=_fb_user(otp_email)), \
         patch("dashboard.routes.send_otp_email",
               return_value=(True, "sent")) as sender:
        r = client.post("/api/auth/otp/request", json={"email": otp_email})
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"
    sender.assert_called_once()
    assert sender.call_args[0][0] == otp_email
    code_sent = sender.call_args[0][1]
    assert len(code_sent) == 6 and code_sent.isdigit()
    # Stored hashed, never plaintext.
    row = get_latest_valid_reset_otp(otp_email)
    assert row is not None
    assert row.otp_hash == _hash_otp(code_sent)
    assert row.otp_hash != code_sent


def test_otp_request_rejects_bad_email(authed_app):
    client = authed_app.test_client()
    r = client.post("/api/auth/otp/request", json={"email": "not-an-email"})
    assert r.status_code == 400
    r = client.post("/api/auth/otp/request", json={"email": "x@yahoo.com"})
    assert r.status_code == 400  # allow-list: gmail/email only


def test_otp_request_unknown_email_replies_generically(authed_app, otp_email, smtp_env):
    client = authed_app.test_client()
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=None), \
         patch("dashboard.routes.send_otp_email") as sender:
        r = client.post("/api/auth/otp/request", json={"email": otp_email})
    assert r.status_code == 200
    assert "one-time code" in r.get_json()["message"]
    sender.assert_not_called()
    assert get_latest_valid_reset_otp(otp_email) is None


def test_otp_request_email_not_configured(authed_app, otp_email, monkeypatch):
    client = authed_app.test_client()
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    r = client.post("/api/auth/otp/request", json={"email": otp_email})
    assert r.status_code == 503


def test_otp_request_send_failure(authed_app, otp_email, smtp_env):
    client = authed_app.test_client()
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=_fb_user(otp_email)), \
         patch("dashboard.routes.send_otp_email",
               return_value=(False, "send_failed")):
        r = client.post("/api/auth/otp/request", json={"email": otp_email})
    assert r.status_code == 502
    assert "couldn't send" in r.get_json()["message"]
    # Failed send must not leave a usable code behind.
    assert get_latest_valid_reset_otp(otp_email) is None


def test_otp_request_cooldown(authed_app, otp_email, smtp_env):
    client = authed_app.test_client()
    _make_otp(otp_email)
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=_fb_user(otp_email)), \
         patch("dashboard.routes.send_otp_email",
               return_value=(True, "sent")) as sender:
        r = client.post("/api/auth/otp/request", json={"email": otp_email})
    assert r.status_code == 429
    sender.assert_not_called()


def test_otp_request_hourly_cap(authed_app, otp_email, smtp_env):
    client = authed_app.test_client()
    db = SessionLocal()
    try:
        for _ in range(5):
            db.add(PasswordResetOTP(
                email=otp_email, otp_hash=_hash_otp("000000"),
                expires_at=datetime.utcnow() + timedelta(minutes=15),
                used=True,
                created_at=datetime.utcnow() - timedelta(minutes=2)))
        db.commit()
    finally:
        db.close()
    # 5 within the hour (but older than the 60s resend cooldown) -> capped.
    assert count_recent_otps(otp_email,
                             datetime.utcnow() - timedelta(hours=1)) == 5
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=_fb_user(otp_email)), \
         patch("dashboard.routes.send_otp_email",
               return_value=(True, "sent")) as sender:
        r = client.post("/api/auth/otp/request", json={"email": otp_email})
    assert r.status_code == 429
    sender.assert_not_called()


# --- verify --------------------------------------------------------------

def test_otp_verify_ok(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456")
    r = client.post("/api/auth/otp/verify",
                    json={"email": otp_email, "otp": "123456"})
    assert r.status_code == 200
    assert get_latest_valid_reset_otp(otp_email).verified is True


def test_otp_verify_wrong_code(authed_app, otp_email):
    client = authed_app.test_client()
    token = _make_otp(otp_email, otp="123456")
    r = client.post("/api/auth/otp/verify",
                    json={"email": otp_email, "otp": "000000"})
    assert r.status_code == 401
    assert "attempts left" in r.get_json()["message"]
    db = SessionLocal()
    try:
        row = db.query(PasswordResetOTP).filter(
            PasswordResetOTP.id == token.id).first()
        assert row.attempts == 1
        assert row.verified is False
    finally:
        db.close()


def test_otp_verify_lockout_after_five(authed_app, otp_email):
    client = authed_app.test_client()
    token = _make_otp(otp_email, otp="123456")
    for _ in range(5):
        r = client.post("/api/auth/otp/verify",
                        json={"email": otp_email, "otp": "000000"})
        assert r.status_code == 401
    r = client.post("/api/auth/otp/verify",
                    json={"email": otp_email, "otp": "123456"})
    assert r.status_code == 429  # locked out even with the right code
    assert get_latest_valid_reset_otp(otp_email) is None


def test_otp_verify_expired(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456", minutes=-1)
    r = client.post("/api/auth/otp/verify",
                    json={"email": otp_email, "otp": "123456"})
    assert r.status_code == 400
    assert "expired" in r.get_json()["message"]


# --- reset ---------------------------------------------------------------

def test_otp_reset_full_flow(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456")
    r = client.post("/api/auth/otp/verify",
                    json={"email": otp_email, "otp": "123456"})
    assert r.status_code == 200
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=_fb_user(otp_email)), \
         patch("firebase_admin.auth.update_user") as updater:
        r = client.post("/api/auth/otp/reset", json={
            "email": otp_email, "otp": "123456",
            "new_password": "NewPass123!", "confirm_password": "NewPass123!"})
    assert r.status_code == 200
    updater.assert_called_once_with("fb-test-uid", password="NewPass123!")
    # Single-use: the code is dead afterwards.
    assert get_latest_valid_reset_otp(otp_email) is None


def test_otp_reset_requires_verification(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456")
    r = client.post("/api/auth/otp/reset", json={
        "email": otp_email, "otp": "123456",
        "new_password": "NewPass123!", "confirm_password": "NewPass123!"})
    assert r.status_code == 400
    assert "verify" in r.get_json()["message"]


def test_otp_reset_weak_password(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456")
    client.post("/api/auth/otp/verify",
                json={"email": otp_email, "otp": "123456"})
    r = client.post("/api/auth/otp/reset", json={
        "email": otp_email, "otp": "123456",
        "new_password": "weak", "confirm_password": "weak"})
    assert r.status_code == 400
    assert "8 characters" in r.get_json()["message"]


def test_otp_reset_mismatched_passwords(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456")
    client.post("/api/auth/otp/verify",
                json={"email": otp_email, "otp": "123456"})
    r = client.post("/api/auth/otp/reset", json={
        "email": otp_email, "otp": "123456",
        "new_password": "NewPass123!", "confirm_password": "Other123!"})
    assert r.status_code == 400
    assert "don't match" in r.get_json()["message"]


def test_otp_reset_rejects_wrong_code_despite_verified(authed_app, otp_email):
    client = authed_app.test_client()
    _make_otp(otp_email, otp="123456")
    client.post("/api/auth/otp/verify",
                json={"email": otp_email, "otp": "123456"})
    with patch("dashboard.routes._get_firebase_user_by_email",
               return_value=_fb_user(otp_email)), \
         patch("firebase_admin.auth.update_user") as updater:
        r = client.post("/api/auth/otp/reset", json={
            "email": otp_email, "otp": "999999",
            "new_password": "NewPass123!", "confirm_password": "NewPass123!"})
    assert r.status_code == 401
    updater.assert_not_called()


# --- emailer: SendGrid HTTPS path ------------------------------------------

def test_sendgrid_used_when_api_key_set(monkeypatch):
    from dashboard import emailer

    monkeypatch.setenv("SENDGRID_API_KEY", "SG.fake-key")
    monkeypatch.setenv("SENDGRID_FROM_EMAIL", "sender@gmail.com")
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    assert emailer.is_email_configured()

    sent = {}

    class FakeResp:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=30):
        sent["url"] = req.full_url
        sent["auth"] = req.get_header("Authorization")
        body = __import__("json").loads(req.data.decode())
        sent["to"] = body["personalizations"][0]["to"][0]["email"]
        sent["from"] = body["from"]["email"]
        return FakeResp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    ok, reason = emailer.send_otp_email("user@gmail.com", "123456")
    assert ok and reason == "sent"
    assert sent["url"] == "https://api.sendgrid.com/v3/mail/send"
    assert sent["auth"] == "Bearer SG.fake-key"
    assert sent["to"] == "user@gmail.com"
    assert sent["from"] == "sender@gmail.com"


def test_sendgrid_http_error(monkeypatch):
    import urllib.error
    from dashboard import emailer

    monkeypatch.setenv("SENDGRID_API_KEY", "SG.fake-key")
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)

    def fake_urlopen(req, timeout=30):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized",
                                     {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    ok, reason = emailer.send_otp_email("user@gmail.com", "123456")
    assert not ok and reason == "sendgrid_401"


def test_smtp_fallback_without_sendgrid_key(monkeypatch):
    from dashboard import emailer

    monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
    monkeypatch.setenv("SMTP_USERNAME", "u@gmail.com")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    assert emailer.is_email_configured()

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            pass

        def login(self, u, p):
            pass

        def sendmail(self, *a):
            pass

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    ok, reason = emailer.send_otp_email("user@gmail.com", "123456")
    assert ok and reason == "sent"


def test_email_not_configured_without_any_key(monkeypatch):
    from dashboard import emailer

    monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    assert not emailer.is_email_configured()
    ok, reason = emailer.send_otp_email("user@gmail.com", "123456")
    assert not ok and reason == "email_not_configured"
