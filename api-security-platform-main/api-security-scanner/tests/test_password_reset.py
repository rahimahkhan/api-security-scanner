"""Tests for the password policy, email allow-list, and forgot-password OTP flow."""
import re
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from werkzeug.security import generate_password_hash, check_password_hash

from dashboard.app import create_app
from dashboard.auth_validators import password_strength_error, validate_signup_email
from database.db import (
    create_user, get_user_by_username, get_user_by_email, set_user_password,
    create_password_reset_token, get_latest_valid_reset_token,
    increment_reset_attempts, mark_reset_token_used,
)


@pytest.fixture()
def authed_app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    yield app


_unique_n = [0]


def _unique(prefix="u"):
    _unique_n[0] += 1
    return f"{prefix}{_unique_n[0]}"


def _cleanup_user(user):
    if user is None:
        return
    from database.db import SessionLocal
    from database.models import User, PasswordResetToken
    db = SessionLocal()
    try:
        # SQLite doesn't enforce ON DELETE CASCADE, so remove tokens explicitly.
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id).delete()
        db.query(User).filter(User.id == user.id).delete()
        db.commit()
    finally:
        db.close()


STRONG = "TestPass123!"


# --- password policy (unit) ---------------------------------------------------

@pytest.mark.parametrize("pw, ok", [
    ("TestPass123!", True),
    ("sh1A!", False),              # too short
    ("testpass123!", False),      # no capital
    ("TestPass!!!", False),       # no number
    ("TestPass123", False),       # no special char
    ("TESTPASS123!", True),       # all-caps still has a capital
    ("t3stP@ss", True),           # exactly 8, meets all classes
])
def test_password_strength_unit(pw, ok):
    assert (password_strength_error(pw) is None) == ok


# --- email policy (unit) ------------------------------------------------------

@pytest.mark.parametrize("email, ok", [
    ("someone@gmail.com", True),
    ("someone@email.com", True),
    ("Some.One@Gmail.Com", True),   # case-insensitive domain
    ("someone@yahoo.com", False),   # domain not allowed
    ("someone@outlook.com", False),
    ("not-an-email", False),
    ("xyz@gmail.com", False),        # junk local part
    ("abc@gmail.com", False),
    ("ab@gmail.com", False),         # too short
    ("", True),                      # optional field
])
def test_email_policy_unit(email, ok):
    assert (validate_signup_email(email) is None) == ok


# --- signup enforcement -------------------------------------------------------

def _signup(client, username, password=STRONG, email=""):
    data = {"username": username, "password": password,
            "confirm_password": password}
    if email:
        data["email"] = email
    return client.post("/signup", data=data, follow_redirects=False)


def test_signup_rejects_weak_passwords(authed_app):
    client = authed_app.test_client()
    for bad, needle in [
        ("testpass123!", b"capital letter"),
        ("TestPass!!!", b"number"),
        ("TestPass123", b"special character"),
    ]:
        r = _signup(client, _unique("weak"), password=bad)
        assert r.status_code == 200 and needle in r.data
    _cleanup_user(get_user_by_username("weak1"))


def test_signup_rejects_bad_emails(authed_app):
    client = authed_app.test_client()
    r = _signup(client, _unique("mail"), email="someone@yahoo.com")
    assert r.status_code == 200 and b"@gmail.com or @email.com" in r.data
    r = _signup(client, _unique("mail"), email="xyz@gmail.com")
    assert r.status_code == 200 and b"too short" in r.data


def test_signup_accepts_good_email(authed_app):
    client = authed_app.test_client()
    name = _unique("goodmail")
    email = f"{name}@gmail.com"
    try:
        r = _signup(client, name, email=email)
        assert r.status_code == 302
        assert get_user_by_email(email).username == name
    finally:
        _cleanup_user(get_user_by_username(name))


# --- forgot-password OTP flow -------------------------------------------------

def _make_user_with_email():
    name = _unique("otpuser")
    email = f"{name}@gmail.com"
    user = create_user(name, generate_password_hash(STRONG), email=email)
    return user, email, name


def _csrf(client, path):
    r = client.get(path)
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.get_data(as_text=True))
    assert m, f"no csrf on {path}"
    return m.group(1)


def test_forgot_password_unknown_email_says_nothing(authed_app):
    client = authed_app.test_client()
    with patch("dashboard.routes.send_otp_email") as send:
        r = client.post("/forgot-password", data={
            "csrf_token": _csrf(client, "/forgot-password"),
            "email": "nobody-here-xyz@gmail.com",
        })
        assert r.status_code == 200
        # generic message, no leak
        assert b"If an account exists" in r.data
        send.assert_not_called()


def test_forgot_password_sends_otp_to_known_email(authed_app):
    user, email, name = _make_user_with_email()
    client = authed_app.test_client()
    try:
        with patch("dashboard.routes.is_email_configured", return_value=True), \
             patch("dashboard.routes.send_otp_email",
                   return_value=(True, "sent")) as send:
            r = client.post("/forgot-password", data={
                "csrf_token": _csrf(client, "/forgot-password"),
                "email": email,
            })
            assert r.status_code == 200 and b"If an account exists" in r.data
            send.assert_called_once()
            to_addr, otp = send.call_args[0]
            assert to_addr == email and re.fullmatch(r"\d{6}", otp)
            token = get_latest_valid_reset_token(user.id)
            assert token is not None
            assert check_password_hash(token.otp_hash, otp)  # hash, not plaintext
    finally:
        _cleanup_user(user)


def test_forgot_password_without_smtp_config(authed_app, monkeypatch):
    user, email, name = _make_user_with_email()
    client = authed_app.test_client()
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    try:
        r = client.post("/forgot-password", data={
            "csrf_token": _csrf(client, "/forgot-password"),
            "email": email,
        })
        assert r.status_code == 200 and b"set up on this server" in r.data
        assert get_latest_valid_reset_token(user.id) is None
    finally:
        _cleanup_user(user)


def _request_otp(client, email):
    """Drive the forgot-password form with a mocked mailer; return the OTP."""
    with patch("dashboard.routes.is_email_configured", return_value=True), \
         patch("dashboard.routes.send_otp_email",
               return_value=(True, "sent")) as send:
        client.post("/forgot-password", data={
            "csrf_token": _csrf(client, "/forgot-password"),
            "email": email,
        })
        return send.call_args[0][1]


def _reset(client, email, otp, password=STRONG):
    return client.post("/reset-password", data={
        "csrf_token": _csrf(client, "/reset-password"),
        "email": email, "otp": otp,
        "password": password, "confirm_password": password,
    })


def test_reset_password_happy_path(authed_app):
    user, email, name = _make_user_with_email()
    client = authed_app.test_client()
    try:
        otp = _request_otp(client, email)
        r = _reset(client, email, otp, password="NewPass456@")
        assert r.status_code == 200 and b"has been changed" in r.data
        # new password works, old one doesn't
        client.get("/logout")
        r = client.post("/login", data={"identifier": name, "password": "NewPass456@"})
        assert r.status_code == 302
        # OTP is single-use
        client.get("/logout")
        r = _reset(client, email, otp, password="Another1@x")
        assert r.status_code == 200 and b"invalid or has expired" in r.data
    finally:
        _cleanup_user(user)


def test_reset_password_wrong_otp_and_lockout(authed_app):
    user, email, name = _make_user_with_email()
    client = authed_app.test_client()
    try:
        _request_otp(client, email)
        for _ in range(5):
            r = _reset(client, email, "000000")
            assert r.status_code == 200 and b"incorrect" in r.data
        # 6th attempt: locked
        r = _reset(client, email, "000000")
        assert r.status_code == 200 and b"locked" in r.data
        assert get_latest_valid_reset_token(user.id) is None
    finally:
        _cleanup_user(user)


def test_reset_password_expired_otp(authed_app):
    user, email, name = _make_user_with_email()
    try:
        create_password_reset_token(
            user.id, generate_password_hash("123456"),
            datetime.utcnow() - timedelta(minutes=1))
        assert get_latest_valid_reset_token(user.id) is None
    finally:
        _cleanup_user(user)


def test_reset_password_rejects_weak_new_password(authed_app):
    user, email, name = _make_user_with_email()
    client = authed_app.test_client()
    try:
        otp = _request_otp(client, email)
        r = _reset(client, email, otp, password="weakpass1")
        assert r.status_code == 200 and b"capital letter" in r.data
        # old password still works
        client.get("/logout")
        r = client.post("/login", data={"identifier": name, "password": STRONG})
        assert r.status_code == 302
    finally:
        _cleanup_user(user)


def test_reset_password_unknown_email_no_leak(authed_app):
    client = authed_app.test_client()
    r = _reset(client, "ghost-xyz@gmail.com", "123456")
    assert r.status_code == 200 and b"invalid or has expired" in r.data


def test_set_user_password_db_helper(authed_app):
    user, _, name = _make_user_with_email()
    try:
        set_user_password(user.id, generate_password_hash("BrandNew1@"))
        assert check_password_hash(
            get_user_by_username(name).password_hash, "BrandNew1@")
    finally:
        _cleanup_user(user)


def test_increment_and_mark_token_helpers(authed_app):
    user, _, _ = _make_user_with_email()
    try:
        token = create_password_reset_token(
            user.id, generate_password_hash("123456"),
            datetime.utcnow() + timedelta(minutes=15))
        increment_reset_attempts(token.id)
        got = get_latest_valid_reset_token(user.id)
        assert got.attempts == 1
        mark_reset_token_used(token.id)
        assert get_latest_valid_reset_token(user.id) is None
    finally:
        _cleanup_user(user)
