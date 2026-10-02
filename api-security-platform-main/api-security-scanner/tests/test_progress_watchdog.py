"""Progress watchdog: a 'running' scan whose worker is alive but stuck
(no progress for a long time) must be reaped as failed instead of showing
"Scan in progress..." forever. Plus the bounded-dispatch helper."""
import time
from datetime import datetime, timedelta

import pytest

import dashboard.routes as routes
from dashboard.app import create_app
from database.db import SessionLocal, save_scan_session, delete_session
from database.models import ScanSession
from main import _dispatch_bounded


@pytest.fixture()
def authed_app():
    app = create_app()
    app.config["TESTING"] = True
    # The watchdog/reaper logic doesn't depend on auth; keep the pages public
    # here so the tests don't need user fixtures.
    app.config["DASHBOARD_AUTH_ENABLED"] = False
    yield app


def _make_running(target="http://example.test/watchdog"):
    return save_scan_session(target_url=target, status="running")


def _set_times(sess_id, updated_at=None, progress_updated_at=None):
    db = SessionLocal()
    try:
        obj = db.query(ScanSession).filter(ScanSession.id == sess_id).first()
        if updated_at is not None:
            obj.updated_at = updated_at
        if progress_updated_at is not None:
            obj.progress_updated_at = progress_updated_at
        db.commit()
    finally:
        db.close()


def test_stuck_scan_reaped_when_no_progress(authed_app, monkeypatch):
    """Heartbeat fresh (worker alive) but no progress for a long time -> failed."""
    monkeypatch.setattr(routes, "PROGRESS_STALL_AFTER_SECONDS", 60)
    client = authed_app.test_client()
    sess = _make_running()
    try:
        now = datetime.utcnow()
        _set_times(sess.id, updated_at=now, progress_updated_at=now - timedelta(minutes=5))
        r = client.get(f"/results/{sess.id}")
        assert r.status_code == 200
        assert b"Scan failed" in r.data
        assert b"Scan in progress" not in r.data
    finally:
        delete_session(sess.id)


def test_progressing_scan_not_reaped(authed_app, monkeypatch):
    """Fresh heartbeat AND fresh progress -> stays running."""
    monkeypatch.setattr(routes, "PROGRESS_STALL_AFTER_SECONDS", 60)
    client = authed_app.test_client()
    sess = _make_running()
    try:
        now = datetime.utcnow()
        _set_times(sess.id, updated_at=now, progress_updated_at=now - timedelta(seconds=30))
        r = client.get(f"/results/{sess.id}")
        assert r.status_code == 200
        assert b"Scan in progress" in r.data
    finally:
        delete_session(sess.id)


def test_reaper_ignores_null_progress_timestamp(authed_app, monkeypatch):
    """Pre-migration rows (progress_updated_at NULL) fall back to heartbeat rule."""
    monkeypatch.setattr(routes, "PROGRESS_STALL_AFTER_SECONDS", 60)
    client = authed_app.test_client()
    sess = _make_running()
    try:
        db = SessionLocal()
        try:
            obj = db.query(ScanSession).filter(ScanSession.id == sess.id).first()
            obj.updated_at = datetime.utcnow()
            obj.progress_updated_at = None
            db.commit()
        finally:
            db.close()
        r = client.get(f"/results/{sess.id}")
        assert b"Scan in progress" in r.data
    finally:
        delete_session(sess.id)


def test_update_progress_refreshes_watchdog_timestamp(authed_app):
    from database.db import update_scan_progress
    sess = _make_running()
    try:
        old = datetime.utcnow() - timedelta(hours=2)
        _set_times(sess.id, progress_updated_at=old)
        update_scan_progress(sess.id, done=3)
        db = SessionLocal()
        try:
            obj = db.query(ScanSession).filter(ScanSession.id == sess.id).first()
            assert obj.progress_updated_at > old
            assert obj.progress_done == 3
        finally:
            db.close()
    finally:
        delete_session(sess.id)


# --- _dispatch_bounded ---------------------------------------------------------

def test_dispatch_bounded_returns_in_order():
    out = _dispatch_bounded(lambda x: x * 2, ["a", "b", "c"], max_workers=2, timeout=10)
    assert out == ["aa", "bb", "cc"]


def test_dispatch_bounded_drops_hung_probe():
    def dispatch(item):
        if item == "hang":
            time.sleep(30)
        return item.upper()

    start = time.time()
    out = _dispatch_bounded(dispatch, ["a", "hang", "b"], max_workers=3, timeout=2)
    elapsed = time.time() - start
    assert elapsed < 15, f"took too long: {elapsed:.1f}s"
    assert out == ["A", "B"]  # original order, hung probe dropped


def test_dispatch_bounded_propagates_finished_errors():
    def boom(item):
        raise ValueError("probe exploded")

    with pytest.raises(ValueError):
        _dispatch_bounded(boom, ["a"], max_workers=1, timeout=10)


def test_dispatch_bounded_empty():
    assert _dispatch_bounded(lambda x: x, [], max_workers=2, timeout=5) == []
