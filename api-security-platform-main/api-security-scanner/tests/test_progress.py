"""Live scan progress + 'time left' ETA for the results page banner."""
import uuid
from datetime import datetime, timedelta

import pytest

from dashboard.app import create_app
from database.db import (
    SessionLocal, save_scan_session, delete_session, update_scan_progress,
    format_scan_eta,
)
from database.models import ScanSession


def _unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def authed_app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["DASHBOARD_AUTH_ENABLED"] = True
    yield app


def _signup(client, username):
    """Create a Firebase-backed user via the session endpoint (mocked token)."""
    from unittest.mock import patch
    uid = f"fb-{uuid.uuid4().hex[:8]}"
    claims = {"uid": uid, "email": f"{username}@gmail.com", "name": username}
    with patch("dashboard.routes.verify_firebase_token", return_value=claims):
        return client.post("/api/auth/session", json={
            "idToken": "fake-id-token", "username": username})


@pytest.fixture()
def user_client(authed_app):
    client = authed_app.test_client()
    username = _unique("prog")
    assert _signup(client, username).status_code == 200
    from database.db import get_user_by_username
    from database.models import User
    user = get_user_by_username(username)
    created = []
    yield client, user, created
    db = SessionLocal()
    try:
        for sid in created:
            s = db.query(ScanSession).filter(ScanSession.id == sid).first()
            if s:
                db.delete(s)
        db_user = db.query(User).filter(User.id == user.id).first()
        if db_user:
            db.delete(db_user)
        db.commit()
    finally:
        db.close()


def _get_session_row(session_id):
    db = SessionLocal()
    try:
        s = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        db.expunge(s)
        return s
    finally:
        db.close()


def test_update_scan_progress_full_and_partial(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)

    update_scan_progress(s.id, done=3, total=10, stage="Testing endpoints")
    row = _get_session_row(s.id)
    assert row.progress_done == 3
    assert row.progress_total == 10
    assert row.progress_stage == "Testing endpoints"

    # Partial update only bumps the counter.
    update_scan_progress(s.id, done=7)
    row = _get_session_row(s.id)
    assert row.progress_done == 7
    assert row.progress_total == 10
    assert row.progress_stage == "Testing endpoints"


def test_format_scan_eta_seconds(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)
    # 40s elapsed, 1 of 2 done -> ~40s left.
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == s.id).first()
        row.scan_start_time = datetime.utcnow() - timedelta(seconds=40)
        row.progress_done = 1
        row.progress_total = 2
        db.commit()
    finally:
        db.close()
    row = _get_session_row(s.id)
    eta = format_scan_eta(row)
    assert "seconds left" in eta, eta


def test_format_scan_eta_minutes(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)
    # 60s elapsed, 1 of 4 done -> ~180s left -> minutes wording.
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == s.id).first()
        row.scan_start_time = datetime.utcnow() - timedelta(seconds=60)
        row.progress_done = 1
        row.progress_total = 4
        db.commit()
    finally:
        db.close()
    row = _get_session_row(s.id)
    eta = format_scan_eta(row)
    assert "minute" in eta and "left" in eta, eta


def test_format_scan_eta_almost_done(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == s.id).first()
        row.scan_start_time = datetime.utcnow() - timedelta(seconds=30)
        row.progress_done = 9
        row.progress_total = 10
        db.commit()
    finally:
        db.close()
    row = _get_session_row(s.id)
    assert format_scan_eta(row) == "less than 15 seconds left"


def test_format_scan_eta_empty_when_no_progress(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)
    row = _get_session_row(s.id)
    assert format_scan_eta(row) == ""


def test_api_session_exposes_progress_fields(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)
    update_scan_progress(s.id, done=2, total=8, stage="Testing endpoints")
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == s.id).first()
        row.scan_start_time = datetime.utcnow() - timedelta(seconds=20)
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/api/sessions/{s.id}")
    assert resp.status_code == 200
    sess = resp.get_json()["session"]
    assert sess["progress_done"] == 2
    assert sess["progress_total"] == 8
    assert sess["progress_stage"] == "Testing endpoints"
    assert sess["progress_eta"].endswith("left"), sess["progress_eta"]


def test_results_page_renders_live_banner(user_client):
    client, user, created = user_client
    s = save_scan_session(target_url="http://example.com", user_id=user.id)
    created.append(s.id)
    update_scan_progress(s.id, done=2, total=8, stage="Testing endpoints")
    db = SessionLocal()
    try:
        row = db.query(ScanSession).filter(ScanSession.id == s.id).first()
        row.scan_start_time = datetime.utcnow() - timedelta(seconds=20)
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/results/{s.id}")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Scan in progress" in html
    assert "endpoint 2 of 8" in html
    assert "left" in html
    assert 'id="scan-progress-fill"' in html
