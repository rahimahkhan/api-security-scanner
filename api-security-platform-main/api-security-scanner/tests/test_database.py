import pytest
from database.db import init_db, save_scan_session, save_endpoint, save_finding, get_session_findings, delete_session, get_session_for_user

def test_database_crud_operations():
    init_db()
    
    session_obj = save_scan_session("http://test-api.org", total_endpoints=2, overall_risk_score=45.0, overall_severity="Medium")
    assert session_obj.id is not None
    
    endpoint_obj = save_endpoint(session_obj.id, "http://test-api.org/v1/auth", "POST")
    assert endpoint_obj.id is not None
    
    finding_obj = save_finding(
        session_id=session_obj.id,
        endpoint_id=endpoint_obj.id,
        attack_type="Broken_Auth",
        severity="Medium",
        risk_score=45.0,
        recommendation="Use JWT validation."
    )
    assert finding_obj.id is not None
    
    findings_list = get_session_findings(session_obj.id)
    assert len(findings_list) == 1
    assert findings_list[0].attack_type == "Broken_Auth"
    
    deleted = delete_session(session_obj.id)
    assert deleted is True


def test_guest_cannot_fetch_another_users_session():
    """S1 regression: a logged-out guest (user_id=None) must NOT see a
    session owned by a logged-in user."""
    init_db()
    owned = save_scan_session("http://owned.example/api", user_id=4242)
    try:
        assert get_session_for_user(owned.id, None) is None
        # The owner can still see their own session.
        assert get_session_for_user(owned.id, 4242) is not None
        # Another logged-in user cannot.
        assert get_session_for_user(owned.id, 9999) is None
    finally:
        delete_session(owned.id)


def test_guest_can_fetch_guest_owned_session():
    """Guest-started scans (user_id NULL) remain visible to guests."""
    init_db()
    guest = save_scan_session("http://guest.example/api")
    try:
        got = get_session_for_user(guest.id, None)
        assert got is not None
        assert got.id == guest.id
        # A logged-in user must not see the guest's scan.
        assert get_session_for_user(guest.id, 4242) is None
    finally:
        delete_session(guest.id)
