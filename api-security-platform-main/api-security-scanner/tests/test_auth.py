"""Auth (signup/login), per-user scan isolation, and the stale-scan reaper."""
import uuid
from datetime import datetime, timedelta

import pytest

from dashboard.app import create_app
from database.db import (
    SessionLocal, save_scan_session, delete_session,
    create_user, get_user_by_username,
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


def _signup(client, username, password="TestPass123!"):
    return client.post("/signup", data={
        "username": username,
        "password": password,
        "confirm_password": password,
    }, follow_redirects=False)


@pytest.fixture()
def user_a(authed_app):
    client = authed_app.test_client()
    username = _unique("alice")
    resp = _signup(client, username)
    assert resp.status_code == 302, resp.data[:200]
    user = get_user_by_username(username)
    yield client, user
    _cleanup_user(user)


@pytest.fixture()
def user_b(authed_app):
    client = authed_app.test_client()
    username = _unique("bob")
    resp = _signup(client, username)
    assert resp.status_code == 302
    user = get_user_by_username(username)
    yield client, user
    _cleanup_user(user)


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


def test_signup_logs_in_and_shows_username(authed_app, user_a):
    client, user = user_a
    resp = client.get("/")
    assert resp.status_code == 200
    assert user.username.encode() in resp.data


def test_signup_validation(authed_app):
    client = authed_app.test_client()
    # bad username
    r = _signup(client, "ab")
    assert r.status_code == 200 and b"Username must be" in r.data
    # short password
    r = _signup(client, _unique("u"), password="short")
    assert r.status_code == 200 and b"at least 8 characters" in r.data
    # mismatched confirmation
    r = client.post("/signup", data={"username": _unique("u"), "password": "TestPass123!",
                                     "confirm_password": "different"})
    assert r.status_code == 200 and b"do not match" in r.data
    # duplicate username (fresh client, not logged in)
    name = _unique("dupe")
    assert _signup(client, name).status_code == 302
    try:
        r = _signup(authed_app.test_client(), name)
        assert r.status_code == 200 and b"already taken" in r.data
    finally:
        _cleanup_user(get_user_by_username(name))


def test_login_wrong_password(authed_app):
    client = authed_app.test_client()
    name = _unique("carol")
    assert _signup(client, name).status_code == 302
    try:
        client.get("/logout")
        r = client.post("/login", data={"identifier": name, "password": "wrongpass1"})
        assert r.status_code == 200 and b"Invalid username/email or password" in r.data
        # correct password works
        r = client.post("/login", data={"identifier": name, "password": "TestPass123!"})
        assert r.status_code == 302
    finally:
        _cleanup_user(get_user_by_username(name))


def test_unauthenticated_redirects(authed_app):
    client = authed_app.test_client()
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    r = client.get("/history")
    assert r.status_code == 302
    r = client.get("/api/sessions")
    assert r.status_code == 401
    assert r.get_json()["status"] == "error"


def test_logout(authed_app, user_a):
    client, _ = user_a
    assert client.get("/").status_code == 200
    client.get("/logout")
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_scan_isolation_between_users(authed_app, user_a, user_b):
    client_a, user_a_obj = user_a
    client_b, _ = user_b
    sess = save_scan_session(target_url="http://example.test/a", status="complete",
                             user_id=user_a_obj.id)
    try:
        # owner sees it everywhere
        assert b"example.test/a" not in client_b.get("/history").data
        assert b"example.test/a" in client_a.get("/history").data
        r = client_b.get(f"/results/{sess.id}")
        assert r.status_code == 404
        r = client_b.get(f"/api/sessions/{sess.id}")
        assert r.status_code == 404
        r = client_b.delete(f"/api/sessions/{sess.id}")
        assert r.status_code == 404
        # owner still sees it
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
        # age the heartbeat beyond the stale threshold
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


def test_heartbeat_touch_updates_timestamp(authed_app, user_a):
    from database.db import touch_scan_session
    _, user = user_a
    sess = save_scan_session(target_url="http://example.test/hb", status="running",
                             user_id=user.id)
    try:
        db = SessionLocal()
        try:
            obj = db.query(type(sess)).filter(type(sess).id == sess.id).first()
            obj.updated_at = datetime.utcnow() - timedelta(minutes=30)
            db.commit()
            before = obj.updated_at
        finally:
            db.close()
        touch_scan_session(sess.id)
        db = SessionLocal()
        try:
            obj = db.query(type(sess)).filter(type(sess).id == sess.id).first()
            assert obj.updated_at > before
        finally:
            db.close()
    finally:
        delete_session(sess.id)
