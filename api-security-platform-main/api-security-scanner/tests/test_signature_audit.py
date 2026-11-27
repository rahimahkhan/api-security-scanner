"""Audit tests for Layer 1 (signature / verification).

Each test states the CORRECT behaviour, from the 2026-11-27 Layer 1 audit
(Manus). The seven defect tests were marked xfail while the defects were
open; the fixes landed in detection/signature.py (AUDIT-1..6) and the marks
were removed — all nine tests must pass.

Run:  pytest tests/test_signature_audit.py -q
"""
import logging
import pytest
from detection.signature import SignatureDetector

logging.disable(logging.CRITICAL)
HTML = {"content-type": "text/html"}
JSON = {"content-type": "application/json"}


@pytest.fixture(scope="module")
def det():
    return SignatureDetector()


def _base(url, body, status=200, headers=None):
    return dict(url=url, status_code=status, response_size=len(body),
                response_body=body, response_time=0.1, response_headers=headers or {})


def test_lfi_signature_in_baseline_is_not_proof(det):
    page = "<html>Example: root:x:0:0:root:/root:/bin/bash</html>"
    probe = dict(url="http://t/doc?page=../../etc/passwd", payload="../../etc/passwd",
                 attack_category="Local_File_Inclusion", status_code=200,
                 response_size=len(page), response_headers=HTML, response_body=page)
    assert det.analyze(probe, _base("http://t/doc?page=intro", page))["finding_status"] != "Confirmed"


def test_sqli_error_text_in_baseline_is_not_proof(det):
    page = "<html>Tutorial: You have an error in your SQL syntax near ...</html>"
    probe = dict(url="http://t/blog?q='", payload="'", attack_category="SQL_Injection",
                 status_code=200, response_size=len(page), response_headers=HTML, response_body=page)
    assert det.analyze(probe, _base("http://t/blog?q=a", page))["finding_status"] != "Confirmed"


def test_open_redirect_to_unrelated_sso_host_is_not_proof(det):
    loc = {"Location": "https://sso.company.com/auth"}
    probe = dict(url="http://t/login?next=https://evil.example", payload="https://evil.example",
                 attack_category="Open_Redirect", status_code=302, response_size=0,
                 response_headers=loc, response_body="")
    assert det.analyze(probe, _base("http://t/login?next=/home", "", 302, loc))["finding_status"] != "Confirmed"


def test_auth_weakness_public_endpoint_is_not_proof(det):
    body = '{"books":[]}'
    probe = dict(url="http://t/books/v1", payload="Bearer null", attack_category="Auth_Weakness",
                 status_code=200, response_size=len(body), response_headers=JSON,
                 response_body=body, request_headers={})
    assert det.analyze(probe, _base("http://t/books/v1", body))["finding_status"] != "Confirmed"


def test_xxe_plain_xml_with_localhost_is_not_proof(det):
    xml = '<?xml version="1.0"?><status><host>localhost</host></status>'
    probe = dict(url="http://t/x", payload='<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
                 attack_category="XXE", status_code=200, response_size=len(xml),
                 response_headers={"content-type": "application/xml"}, response_body=xml)
    assert det.analyze(probe, _base("http://t/x", xml))["finding_status"] != "Confirmed"


def test_bola_public_profile_without_auth_is_not_confirmed(det):
    body = '{"username":"bob","email":"b@x.com"}'
    probe = dict(url="http://t/users/5", payload="", status_code=200, response_size=len(body),
                 response_headers=JSON, response_body=body, request_headers={})
    assert det.analyze(probe, _base("http://t/users/5", body))["finding_status"] != "Confirmed"


def test_sqli_generic_500_differential_is_at_least_suspected(det):
    body = '{"detail":"The server encountered an internal error","status":500}'
    probe = dict(url="http://t/users/v1/name1'", payload="'", attack_category="SQL_Injection",
                 status_code=500, response_size=len(body), response_headers=JSON, response_body=body)
    r = det.analyze(probe, _base("http://t/users/v1/name1", '{"username":"name1"}'))
    assert r["finding_status"] in ("Suspected", "Confirmed")


# ---- sanity: things that must keep working -------------------------------
def test_real_lfi_is_confirmed(det):
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    probe = dict(url="http://t/fi?page=../../../../etc/passwd", payload="../../../../etc/passwd",
                 attack_category="Local_File_Inclusion", status_code=200, response_size=len(body),
                 response_headers=HTML, response_body=body)
    assert det.analyze(probe, _base("http://t/fi?page=a", "hello"))["finding_status"] == "Confirmed"


def test_real_reflected_xss_is_confirmed(det):
    p = "<script>alert(1)</script>"
    body = f"<html>Hello {p}</html>"
    probe = dict(url="http://t/x?name=" + p, payload=p, attack_category="XSS", status_code=200,
                 response_size=len(body), response_headers=HTML, response_body=body)
    assert det.analyze(probe, _base("http://t/x?name=a", "<html>Hello a</html>"))["finding_status"] == "Confirmed"


def test_passive_exposure_confirms_even_with_identical_baseline(det):
    """Regression (found 2026-11-27 on VAmPI _debug): passive exposure is a
    property of the response, not of the probe. Plaintext credentials in
    the body must Confirm even when the baseline shows the same body —
    AUDIT-1's baseline exclusion applies to injection proof only."""
    body = '{"users": [{"username": "alice", "password": "secret123"}]}'
    probe = dict(url="http://t/users/v1/_debug", payload="", status_code=200,
                 response_size=len(body), response_headers=JSON, response_body=body)
    r = det.analyze(probe, _base("http://t/users/v1/_debug", body))
    assert r["attack_type"] == "Sensitive_Data_Exposure"
    assert r["finding_status"] == "Confirmed"
    assert r["points"] == 35
