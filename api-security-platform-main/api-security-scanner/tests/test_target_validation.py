"""Unit tests for target URL validation (main.validate_target_url)."""
import pytest
from unittest.mock import patch

from main import validate_target_url


@pytest.mark.parametrize("url", [
    "https://xploiter.onrender.com",
    "https://example.com:8443/a/b?x=1&y=2",
    "  https://example.com/  ",  # surrounding whitespace is stripped
])
def test_valid_target_urls_accepted(url):
    # DNS is mocked: the sandbox's fake DNS resolves everything to a
    # non-routable range, so pin resolution to a public IP here.
    with patch("core.target_validation._host_resolves_to_public_ip", return_value=True):
        ok, normalized = validate_target_url(url)
    assert ok is True, f"{url!r} rejected: {normalized}"
    assert normalized == url.strip()


@pytest.mark.parametrize("url", [
    "http://localhost:5000/api",
    "http://127.0.0.1:8000/",
    "https://192.168.1.1/",
    "http://10.0.0.5:8080/v1/users",
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata (SSRF)
])
def test_private_target_urls_rejected_ssrf(url, monkeypatch):
    # Remove the conftest flow-test override so the real guard is exercised.
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    ok, reason = validate_target_url(url)
    assert ok is False
    assert "private or internal" in reason


def test_private_target_allowed_with_env_override(monkeypatch):
    # Local lab testing escape hatch: ALLOW_PRIVATE_SCAN_TARGETS=1 permits
    # private targets (never set on the deployed service).
    monkeypatch.setenv("ALLOW_PRIVATE_SCAN_TARGETS", "1")
    ok, _ = validate_target_url("http://localhost:5000/api")
    assert ok is True


def test_hostname_resolving_to_private_ip_rejected(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    with patch("core.target_validation._host_resolves_to_public_ip", return_value=False):
        ok, reason = validate_target_url("https://evil.example/")
    assert ok is False
    assert "private or internal" in reason


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
