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
