"""Unit tests for the BOLA gate verification (main._identity_api_verified).

The gate arms the VAmPI identity/BOLA probes when discovery surfaces
/users/v1/* paths -- but discovery wordlist-guesses those paths, and soft-404
sites answer 200 to everything. _identity_api_verified requires one real
registration attempt to return a 2xx JSON response before the probes fire.
"""
import pytest

from main import _identity_api_verified


def _resp(status_code, body="", content_type=""):
    return {
        "status_code": status_code,
        "response_body": body,
        "response_headers": {"content-type": content_type} if content_type else {},
    }


def test_real_vampi_register_verified():
    # 201 + JSON content type: a working identity API arms the probes.
    assert _identity_api_verified(
        _resp(201, '{"message": "user created"}', "application/json")
    ) is True


def test_200_json_body_without_json_content_type_verified():
    # Some frameworks omit the JSON content type; a parseable JSON dict body
    # is still proof of an API.
    assert _identity_api_verified(
        _resp(200, '{"auth_token": "abc"}', "text/plain")
    ) is True


def test_soft404_html_body_rejected():
    # whoer.net-style: 200 with an HTML page (soft-404 / bot wall).
    assert _identity_api_verified(
        _resp(200, "<html><body>...</body></html>", "text/html")
    ) is False


def test_empty_body_rejected():
    assert _identity_api_verified(_resp(200, "", "text/html")) is False


def test_non_2xx_rejected():
    assert _identity_api_verified(
        _resp(404, '{"error": "not found"}', "application/json")
    ) is False
    assert _identity_api_verified(
        _resp(500, "internal error", "text/plain")
    ) is False
    assert _identity_api_verified(
        _resp(403, "<html>blocked</html>", "text/html")
    ) is False


def test_json_content_type_alone_is_enough():
    # A 2xx with a JSON content type proves an API even if the body shape is
    # unexpected (e.g. a JSON array).
    assert _identity_api_verified(
        _resp(200, '["a", "b"]', "application/json")
    ) is True


def test_malformed_and_missing_inputs_rejected():
    assert _identity_api_verified(None) is False
    assert _identity_api_verified({}) is False
    assert _identity_api_verified({"status_code": "200"}) is False
    assert _identity_api_verified({"status_code": 200}) is False  # no body/headers
