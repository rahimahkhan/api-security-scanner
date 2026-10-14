import pytest
from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser

def test_discovery_normalization():
    discoverer = EndpointDiscovery("http://example.com")
    assert discoverer.normalize_url("/api/v1/users") == "http://example.com/api/v1/users"
    assert discoverer.is_same_domain("http://example.com/test") is True

def test_request_engine_structure():
    engine = RequestEngine()
    # Test method dictionary structuring without external network call
    res = {
        "method": "POST",
        "url": "http://example.com/api",
        "payload": "sample_data",
        "status_code": 200,
        "response_body": "{\"status\":\"ok\",\"token\":\"abc123secret\"}",
        "response_time": 0.05,
        "response_size": 32,
        "request_headers": {"Authorization": "Bearer key"}
    }
    assert res["status_code"] == 200

def test_response_parser_features():
    from ml_pipeline.feature_extractor import FEATURE_KEYS
    parser = ResponseParser()
    baseline = {
        "method": "POST",
        "url": "http://example.com/api/v1/users?id=10",
        "payload": "",
        "status_code": 200,
        "response_size": 256,
        "response_time": 0.1,
        "response_body": '{"status": "ok"}',
        "response_headers": {"Content-Type": "application/json"},
        "request_headers": {"Authorization": "Bearer secret"}
    }
    probe = dict(baseline, payload="user_payload!",
                 response_body='{"token": "secret_token"}', response_size=32)
    extracted = parser.extract_features(probe, baseline)

    assert extracted["encoded_method"] == 2  # POST (minor request context)
    assert extracted["status_class"] == 2
    assert extracted["body_diff_ratio"] > 0.0  # body changed vs baseline
    assert extracted["payload_reflected"] == 0
    assert len(extracted["feature_vector"]) == len(FEATURE_KEYS)
    assert "token" in extracted["sensitive_fields_leaked"]


# --- Discovery + request-engine fixes (2026-10-11 audit) ---

def test_base_url_with_query_string_keeps_clean_join_base():
    # A query string in the scan target must not corrupt joined paths
    # (".../search?q=x/api"); the original URL is preserved as the crawl seed.
    d = EndpointDiscovery("http://example.com/search?q=x", timeout=1)
    assert d.seed_url == "http://example.com/search?q=x"
    assert d.base_url == "http://example.com/search"
    assert f"{d.base_url}/api" == "http://example.com/search/api"


def test_js_api_paths_extracted_from_inline_script():
    from bs4 import BeautifulSoup
    d = EndpointDiscovery("http://example.test", timeout=1)
    html = (
        "<html><body><script>"
        'fetch("/api/v1/orders").then(r => r.json());'
        "axios.get('/api/v1/users/me');"
        'var asset = "/static/app.js";'
        "</script></body></html>"
    )
    soup = BeautifulSoup(html, "html.parser")
    d._extract_js_api_paths(soup, "http://example.test/", client=None)
    urls = {ep["url"] for ep in d.discovered_endpoints}
    assert "http://example.test/api/v1/orders" in urls
    assert "http://example.test/api/v1/users/me" in urls
    assert not any(u.endswith(".js") for u in urls)
    assert all(ep["method"] == "GET" for ep in d.discovered_endpoints)


def test_post_fallback_keeps_live_post_only_path():
    import httpx
    class _Resp:
        def __init__(self, status):
            self.status_code = status
    class _Client:
        def __init__(self, status):
            self._status = status
        def post(self, url, json=None):
            return _Resp(self._status)
        def get(self, url):
            raise httpx.RequestError("unreachable")
    assert EndpointDiscovery._probe_post_fallback(_Client(200), "http://example.test/submit") is True
    assert EndpointDiscovery._probe_post_fallback(_Client(400), "http://example.test/submit") is True
    assert EndpointDiscovery._probe_post_fallback(_Client(404), "http://example.test/submit") is False
    assert EndpointDiscovery._probe_post_fallback(_Client(405), "http://example.test/submit") is False


def test_fallback_query_params_prefers_existing_param():
    from core.request_engine import _fallback_query_params
    # Prefer a parameter the target URL already uses...
    assert _fallback_query_params("http://example.test/search?query=hello", "PAY") == {"query": "PAY"}
    # ...otherwise fall back to the first common name, always a single param.
    assert _fallback_query_params("http://example.test/", "PAY") == {"q": "PAY"}
    assert len(_fallback_query_params("http://example.test/?a=1&b=2", "PAY")) == 1


def test_read_capped_truncates_large_body():
    from core.request_engine import _read_capped, MAX_RESPONSE_BODY_BYTES
    class _Resp:
        def iter_bytes(self, chunk_size=None):
            for _ in range(40):  # ~2.5 MiB
                yield b"x" * 65536
    body, truncated = _read_capped(_Resp())
    assert truncated is True
    assert len(body) == MAX_RESPONSE_BODY_BYTES


def test_read_capped_keeps_small_body():
    from core.request_engine import _read_capped
    class _Resp:
        def iter_bytes(self, chunk_size=None):
            yield b"hello"
    body, truncated = _read_capped(_Resp())
    assert (body, truncated) == (b"hello", False)


def test_async_timeout_maps_to_408(monkeypatch):
    import asyncio
    import httpx
    import core.request_engine as re_mod
    class _Boom:
        def __aenter__(self):
            raise httpx.TimeoutException("timed out")
        def __aexit__(self, *exc):
            return False
    class _FakeClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *exc):
            return False
        def stream(self, **kwargs):
            return _Boom()
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: _FakeClient())
    res = asyncio.run(RequestEngine(timeout=1).send_request_async("GET", "http://example.test/"))
    assert res["status_code"] == 408
    assert "Timeout" in res["error"]


# --- Redirect SSRF guard (S4 fix) ---

def _fake_redirect_client(responses):
    """Fake httpx client: serves canned (status, location, url) responses in order."""
    import httpx
    class _Resp:
        def __init__(self, status, location, url):
            self.status_code = status
            self.headers = {"content-type": "text/html"}
            if location:
                self.headers["location"] = location
            self.url = url
        def iter_bytes(self, chunk_size=None):
            yield b"ok"
        async def aiter_bytes(self, chunk_size=None):
            yield b"ok"
    class _CM:
        def __init__(self, resp):
            self._resp = resp
        def __enter__(self):
            return self._resp
        def __exit__(self, *exc):
            return False
        async def __aenter__(self):
            return self._resp
        async def __aexit__(self, *exc):
            return False
    class _FakeClient:
        def __init__(self):
            self.fetched = []
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        async def __aenter__(self):
            return self
        async def __aexit__(self, *exc):
            return False
        def stream(self, **kwargs):
            url = str(kwargs.get("url"))
            self.fetched.append(url)
            status, location, _ = responses[min(len(self.fetched) - 1, len(responses) - 1)]
            return _CM(_Resp(status, location, url))
    return _FakeClient()



def _pin_ssrf_guard(monkeypatch, is_public):
    """Pin the SSRF host check in BOTH namespaces the engine consults.

    request_engine imports _host_resolves_to_public_ip by name (first-hop
    check); the redirect-hop path goes through core.target_validation, which
    resolves the same name at call time. Both must be pinned because this
    sandbox's fake DNS resolves every hostname to a private range.
    """
    import core.request_engine as re_mod
    import core.target_validation as tv_mod
    monkeypatch.setattr(re_mod, "_host_resolves_to_public_ip", is_public)
    monkeypatch.setattr(tv_mod, "_host_resolves_to_public_ip", is_public)


def test_redirect_to_private_ip_is_not_fetched(monkeypatch):
    import core.request_engine as re_mod
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    # Sandbox DNS resolves every hostname to a private range; pin the guard so
    # only the redirect target counts as private for this test.
    _pin_ssrf_guard(monkeypatch, lambda host: host != "169.254.169.254")
    client = _fake_redirect_client([(301, "http://169.254.169.254/latest/meta-data/", None)])
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: client)
    res = RequestEngine(timeout=1).send_request("GET", "http://example.test/start")
    assert len(client.fetched) == 1, f"private redirect hop was fetched: {client.fetched}"
    assert res["status_code"] == 0
    assert res["error"] is not None and "BlockedRedirect" in res["error"]
    assert "private" in res["error"].lower()


def test_redirect_to_public_host_is_followed(monkeypatch):
    import core.request_engine as re_mod
    _pin_ssrf_guard(monkeypatch, lambda host: True)
    client = _fake_redirect_client([
        (301, "http://example.test/other", None),
        (200, None, None),
    ])
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: client)
    res = RequestEngine(timeout=1).send_request("GET", "http://example.test/start")
    assert res["status_code"] == 200
    assert res["error"] is None
    assert len(client.fetched) == 2
    assert client.fetched[1] == "http://example.test/other"
    assert res["url"] == "http://example.test/other"


def test_follow_redirects_false_returns_raw_3xx(monkeypatch):
    import core.request_engine as re_mod
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    _pin_ssrf_guard(monkeypatch, lambda host: host != "169.254.169.254")
    client = _fake_redirect_client([(301, "http://169.254.169.254/x", None)])
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: client)
    # The Open_Redirect probe relies on this: no following, raw 3xx visible.
    res = RequestEngine(timeout=1).send_request(
        "GET", "http://example.test/r", follow_redirects=False)
    assert res["status_code"] == 301
    assert res["error"] is None
    assert len(client.fetched) == 1


def test_redirect_hop_cap_blocks_loop(monkeypatch):
    import core.request_engine as re_mod
    from core.request_engine import MAX_REDIRECT_HOPS
    _pin_ssrf_guard(monkeypatch, lambda host: True)
    client = _fake_redirect_client([(301, "http://example.test/loop", None)])
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: client)
    res = RequestEngine(timeout=1).send_request("GET", "http://example.test/loop")
    assert res["status_code"] == 0
    assert res["error"] is not None and "too many redirects" in res["error"].lower()
    assert len(client.fetched) == MAX_REDIRECT_HOPS + 1


def test_redirect_to_non_http_scheme_blocked(monkeypatch):
    import core.request_engine as re_mod
    _pin_ssrf_guard(monkeypatch, lambda host: True)
    client = _fake_redirect_client([(302, "ftp://example.test/x", None)])
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: client)
    res = RequestEngine(timeout=1).send_request("GET", "http://example.test/start")
    assert res["status_code"] == 0
    assert res["error"] is not None and "http" in res["error"].lower()
    assert len(client.fetched) == 1


def test_validate_redirect_target_unit(monkeypatch):
    from core.target_validation import validate_redirect_target
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    _pin_ssrf_guard(monkeypatch, lambda host: host == "example.test")
    ok, target, reason = validate_redirect_target("http://example.test/a", "/other")
    assert ok is True and target == "http://example.test/other" and reason == ""
    ok, _, reason = validate_redirect_target("http://example.test/a", "http://169.254.169.254/x")
    assert ok is False and "private" in reason
    ok, _, reason = validate_redirect_target("http://example.test/a", "ftp://example.test/x")
    assert ok is False and "http" in reason  # shared module: "must start with http:// or https://"


def test_async_redirect_to_private_ip_is_not_fetched(monkeypatch):
    import asyncio
    import core.request_engine as re_mod
    monkeypatch.delenv("ALLOW_PRIVATE_SCAN_TARGETS", raising=False)
    _pin_ssrf_guard(monkeypatch, lambda host: host != "169.254.169.254")
    client = _fake_redirect_client([(301, "http://169.254.169.254/x", None)])
    monkeypatch.setattr(re_mod, "_build_client", lambda cls, **kw: client)
    res = asyncio.run(RequestEngine(timeout=1).send_request_async("GET", "http://example.test/start"))
    assert len(client.fetched) == 1
    assert res["status_code"] == 0
    assert res["error"] is not None and "BlockedRedirect" in res["error"]
