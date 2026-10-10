import pytest
from detection.signature import SignatureDetector

def test_signature_sqli_detection():
    detector = SignatureDetector()
    
    # Confirmed SQLi Error Response
    sample_confirmed = {
        "url": "http://localhost:5000/api/users?id=1",
        "payload": "1' OR 1=1 --",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"error\":\"SQLAlchemyError: syntax error at or near OR\"}"
    }
    res_conf = detector.analyze(sample_confirmed)
    assert res_conf["matched"] is True
    assert res_conf["attack_type"] == "SQL_Injection"
    assert res_conf["finding_status"] == "Confirmed"
    assert res_conf["confidence"] == "High"
    assert res_conf["points"] == 40

    # Unconfirmed / Suspected SQLi Parameter Match
    sample_unconfirmed = {
        "url": "http://localhost:5000/api/users?id=1",
        "payload": "1' OR 1=1 --",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"status\":\"ok\"}"
    }
    res_unconf = detector.analyze(sample_unconfirmed)
    assert res_unconf["matched"] is True
    assert res_unconf["attack_type"] == "SQL_Injection"
    assert res_unconf["finding_status"] == "Suspected"
    assert res_unconf["confidence"] == "Low"
    assert res_unconf["points"] == 10

def test_signature_xss_detection():
    detector = SignatureDetector()

    # Confirmed Reflected XSS Response
    sample_reflected = {
        "url": "http://localhost:5000/search",
        "payload": "<script>alert(1)</script>",
        "status_code": 200,
        "response_size": 250,
        "response_headers": {"Content-Type": "text/html"},
        "response_body": "<html><body>Search result: <script>alert(1)</script></body></html>"
    }
    res_refl = detector.analyze(sample_reflected)
    assert res_refl["matched"] is True
    assert res_refl["attack_type"] == "XSS"
    assert res_refl["finding_status"] == "Confirmed"
    assert res_refl["confidence"] == "High"
    assert res_refl["points"] == 40

def test_waf_status_code_filter():
    detector = SignatureDetector()
    # NOTE: (202, 0) was removed from this list: a 202 Accepted with an empty
    # body is a legitimate async response, not a WAF block.
    for waf_status, waf_size in [(403, 0), (429, 0), (502, 0), (503, 0)]:
        sample_waf = {
            "url": "http://localhost:5000/search",
            "payload": "<script>alert(1)</script>",
            "status_code": waf_status,
            "response_size": waf_size,
            "response_headers": {},
            "response_body": ""
        }
        result = detector.analyze(sample_waf)
        assert result["matched"] is False
        assert result["has_proof"] is False
        assert result["finding_status"] == "BLOCKED_OR_NOT_FOUND"
        assert result["points"] == 0

def test_network_dropped_circuit_breaker():
    detector = SignatureDetector()
    sample_zero = {
        "url": "http://localhost:5000/search",
        "payload": "<script>alert(1)</script>",
        "status_code": 0,
        "response_size": 0,
        "response_headers": {},
        "response_body": ""
    }
    result = detector.analyze(sample_zero)
    assert result["matched"] is False
    assert result["has_proof"] is False
    assert result["finding_status"] == "UNREACHABLE / NETWORK_DROPPED"
    assert result["points"] == 0

def test_404_response_filter():
    detector = SignatureDetector()
    sample_404 = {
        "url": "http://localhost:5000/nonexistent",
        "payload": "' OR 1=1 --",
        "status_code": 404,
        "response_size": 21145,
        "response_headers": {},
        "response_body": "Not found"
    }
    result = detector.analyze(sample_404)
    assert result["matched"] is False
    assert result["has_proof"] is False
    assert result["finding_status"] == "BLOCKED_OR_NOT_FOUND"
    assert result["points"] == 0

def test_bola_verification_rules():
    detector = SignatureDetector()
    
    # 404 response on numeric ID URL should NOT produce BOLA finding
    sample_404 = {
        "url": "http://localhost:5000/users/9999",
        "payload": "",
        "status_code": 404,
        "response_size": 20,
        "response_headers": {},
        "response_body": "Not found"
    }
    res_404 = detector.analyze(sample_404)
    assert res_404["attack_type"] != "BOLA_IDOR"

    # Confirmed BOLA: cross-identity mutation + verified canary (victim login
    # with the changed password succeeded). Without the canary it is only
    # Suspected — a 2xx alone is not proof the mutation happened.
    sample_bola_confirmed = {
        "url": "http://localhost:5000/users/2",
        "payload": "",
        "status_code": 200,
        "response_size": 150,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"id\":2, \"username\":\"alice\", \"email\":\"alice@example.com\", \"role\":\"admin\"}",
        "request_headers": {"Authorization": "Bearer attacker-token"},
        "cross_identity_probe": True,
        "canary_verified": True
    }
    res_bola = detector.analyze(sample_bola_confirmed)
    assert res_bola["matched"] is True
    assert res_bola["attack_type"] == "BOLA_IDOR"
    assert res_bola["finding_status"] == "Confirmed"
    assert res_bola["points"] == 45

    sample_bola_unverified = dict(sample_bola_confirmed, canary_verified=False)
    res_unverified = detector.analyze(sample_bola_unverified)
    assert res_unverified["finding_status"] == "Suspected"
    assert res_unverified["has_proof"] is False

    unauthenticated_bola = dict(sample_bola_confirmed, request_headers={}, cross_identity_probe=False)
    res_unauthenticated = detector.analyze(unauthenticated_bola)
    assert res_unauthenticated["attack_type"] == "BOLA_IDOR"
    assert res_unauthenticated["finding_status"] == "Confirmed"
    assert res_unauthenticated["points"] == 40

    mass_assignment = detector.analyze(
        {
            "url": "http://localhost:5000/users/v1/canary_delete_qc",
            "payload": "",
            "status_code": 204,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
            "request_headers": {"Authorization": "Bearer mass-assign-token"},
            "mass_assignment_probe": True,
            "privilege_verified": True,
        }
    )
    assert mass_assignment["attack_type"] == "Mass_Assignment"
    assert mass_assignment["finding_status"] == "Confirmed"
    assert mass_assignment["points"] == 45

    # Without the privilege canary the same probe is only Suspected.
    mass_assignment_unverified = detector.analyze(
        {
            "url": "http://localhost:5000/users/v1/canary_delete_qc",
            "payload": "",
            "status_code": 204,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
            "request_headers": {"Authorization": "Bearer mass-assign-token"},
            "mass_assignment_probe": True,
        }
    )
    assert mass_assignment_unverified["attack_type"] == "Mass_Assignment"
    assert mass_assignment_unverified["finding_status"] == "Suspected"
    assert mass_assignment_unverified["has_proof"] is False

def test_signature_missing_headers():
    detector = SignatureDetector()
    sample = {
        "url": "http://localhost:5000/api/normal",
        "payload": "normal_string",
        "status_code": 200,
        "response_size": 100,
        "response_headers": {"Server": "Werkzeug"},
        "response_body": "{\"status\":\"ok\"}"
    }
    result = detector.analyze(sample)
    assert result["matched"] is True
    assert result["attack_type"] == "Security_Misconfiguration"
    assert len(result["missing_headers"]) > 0

