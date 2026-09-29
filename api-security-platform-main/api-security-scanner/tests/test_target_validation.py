"""Unit tests for target URL validation (main.validate_target_url)."""
import pytest

from main import validate_target_url


@pytest.mark.parametrize("url", [
    "https://xploiter.onrender.com",
    "http://localhost:5000/api",
    "https://example.com:8443/a/b?x=1&y=2",
    "https://192.168.1.1/",
    "http://10.0.0.5:8080/v1/users",
    "  https://example.com/  ",  # surrounding whitespace is stripped
])
def test_valid_target_urls_accepted(url):
    ok, normalized = validate_target_url(url)
    assert ok is True, f"{url!r} rejected: {normalized}"
    assert normalized == url.strip()


@pytest.mark.parametrize("url,reason_part", [
    ("<script>alert('xss')</script>", "illegal characters"),
    ("; cat /etc/passwd", "illegal characters"),
    ("'", "illegal characters"),
    ("ftp://example.com", "http:// or https://"),
    ("example.com", "http:// or https://"),
    ("", "empty"),
    ("https://", "host name"),
    ("http://256.300.1.1/", "IPv4"),
    ("http:///no-host", "host name"),
    (None, "must be a string"),
    (123, "must be a string"),
])
def test_invalid_target_urls_rejected(url, reason_part):
    ok, reason = validate_target_url(url)
    assert ok is False, f"{url!r} should have been rejected"
    assert reason_part in reason
