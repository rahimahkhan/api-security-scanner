import json
import re
import time
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qsl
import httpx
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from core.http_client import build_client as _build_client, client_kwargs

# Maximum response body handed to detectors. Probe responses are streamed and
# truncated past this point so a huge body (e.g. an LFI probe hitting a large
# file) cannot OOM the scan worker. Telemetry carries truncated=True when cut.
MAX_RESPONSE_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB

_CHARSET_RE = re.compile(r"charset\s*=\s*([\w\-]+)", re.IGNORECASE)

# Ordered fallback parameter names for GET/DELETE probes when the endpoint has
# no known fields. Only the first applicable name is ever used: one request
# per probe, never one per candidate.
_COMMON_PARAM_NAMES = ("q", "query", "search", "id", "keyword")


def _decode_body(raw: bytes, content_type: str) -> str:
    """Decode response bytes, preferring the declared charset; never raise."""
    match = _CHARSET_RE.search(content_type or "")
    encoding = match.group(1) if match else "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except (LookupError, ValueError):
        return raw.decode("utf-8", errors="replace")


def _read_capped(response) -> Tuple[bytes, bool]:
    """Read at most MAX_RESPONSE_BODY_BYTES from a streamed httpx response.

    Returns (body_bytes, truncated).
    """
    chunks = []
    kept = 0
    truncated = False
    for chunk in response.iter_bytes(chunk_size=65536):
        if not chunk:
            continue
        room = MAX_RESPONSE_BODY_BYTES - kept
        if room <= 0:
            truncated = True
            break
        if len(chunk) > room:
            chunks.append(chunk[:room])
            kept += room
            truncated = True
            break
        chunks.append(chunk)
        kept += len(chunk)
    return b"".join(chunks), truncated


async def _aread_capped(response) -> Tuple[bytes, bool]:
    """Async variant of _read_capped."""
    chunks = []
    kept = 0
    truncated = False
    async for chunk in response.aiter_bytes(chunk_size=65536):
        if not chunk:
            continue
        room = MAX_RESPONSE_BODY_BYTES - kept
        if room <= 0:
            truncated = True
            break
        if len(chunk) > room:
            chunks.append(chunk[:room])
            kept += room
            truncated = True
            break
        chunks.append(chunk)
        kept += len(chunk)
    return b"".join(chunks), truncated


def _wire_size(response, bytes_read: int) -> int:
    """Best-effort on-wire response size for differential size comparisons."""
    try:
        declared = response.headers.get("content-length")
        if declared is not None and int(declared) >= 0:
            return int(declared)
    except (TypeError, ValueError):
        pass
    return bytes_read


def _fallback_query_params(url: str, payload: str) -> Dict[str, str]:
    """Choose one query parameter to carry a GET/DELETE probe payload.

    Prefers a parameter name the target URL already uses (more likely to reach
    application logic than an invented name); otherwise falls back to the first
    common search-style name. Always a single parameter: one request per probe.
    """
    try:
        existing = [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if name]
    except Exception:
        existing = []
    name = existing[0] if existing else _COMMON_PARAM_NAMES[0]
    return {name: payload}


# --- Redirect SSRF guard (S4 fix) -------------------------------------------
# Redirects are followed manually (never by httpx itself) so that EVERY hop is
# validated through the single shared SSRF policy in core/target_validation
# before it is fetched. A public URL that redirects to http://169.254.169.254/
# (cloud metadata) or any other private/internal address is refused instead
# of fetched server-side.
from core.target_validation import (
    validate_redirect_target as _validate_redirect_target,
    private_targets_allowed,
    _host_resolves_to_public_ip,
)

MAX_REDIRECT_HOPS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _next_hop_method(status_code: int, method: str) -> str:
    """Method for the next redirect hop, mirroring httpx's own convention:
    301/302/303 become GET (except HEAD); 307/308 preserve method and body.
    """
    if status_code in (301, 302, 303) and method != "HEAD":
        return "GET"
    return method


def _blocked_redirect_result(method: str, url: str, payload_str: str,
                             req_headers: Dict[str, Any], elapsed: float,
                             reason: str) -> Dict[str, Any]:
    """Synthetic result for a refused redirect hop.

    Same dict shape as every other send_request outcome; status_code 0 with
    an error means the probe contributed nothing — the signature layer
    treats it as unreachable, never as a finding.
    """
    logger.warning("Blocked redirect hop [%s] %s: %s", method, url, reason)
    return {
        "method": method,
        "url": url,
        "payload": payload_str,
        "status_code": 0,
        "response_body": "",
        "response_time": elapsed,
        "response_size": 0,
        "request_headers": req_headers,
        "response_headers": {},
        "truncated": False,
        "error": f"BlockedRedirect: {reason}"
    }


def _prepare_request_parts(method_upper: str, url: str, payload_str: str,
                           query_params: Optional[Dict[str, Any]],
                           form_data: Optional[Dict[str, Any]],
                           json_payload: Optional[Dict[str, Any]],
                           req_headers: Dict[str, Any]) -> "tuple":
    """Split a probe into httpx (params, data, json) parts. Shared by both
    the sync and async send paths so they stay in lockstep."""
    params = None
    data = None
    json_data = None

    if method_upper in ["GET", "DELETE"]:
        if query_params is not None:
            params = query_params
        elif payload_str:
            params = _fallback_query_params(url, payload_str)
    elif method_upper in ["POST", "PUT", "PATCH"]:
        if form_data is not None:
            data = form_data
        elif json_payload is not None:
            json_data = json_payload
        elif payload_str:
            try:
                json_data = json.loads(payload_str)
            except (json.JSONDecodeError, TypeError):
                if req_headers.get("Content-Type") == "application/json":
                    json_data = {"data": payload_str}
                else:
                    data = payload_str
    return params, data, json_data


class RequestEngine:
    """
    Sends HTTP requests (GET, POST, PUT, DELETE) with optional payload attachments
    to specified API target endpoints and collects full request/response telemetry.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        headers: Optional[Dict[str, str]] = None,
        trust_env: bool = True,
    ):
        self.timeout = timeout
        self.trust_env = trust_env
        self.default_headers = headers or {
            "User-Agent": "APISecurityPlatform/1.0",
            "Accept": "application/json, text/html, */*"
        }
        # Per-instance cache for the redirect-guard host checks: a scan fires
        # thousands of probes at one host, and getaddrinfo per probe would be
        # pure overhead. Entries are (allowed: bool).
        self._host_allow_cache: Dict[str, bool] = {}

    def _client_kwargs(self, follow_redirects: bool) -> Dict[str, Any]:
        return client_kwargs(self.timeout, follow_redirects, self.trust_env)

    def _hop_allowed(self, url: str) -> "tuple[bool, str]":
        """Check the FIRST hop of a request against the SSRF guard.

        The web flow already validated the target via
        core.target_validation.validate_target_url, but direct callers (CLI,
        direct probes) may not have — and the guard must hold on every fetch,
        redirect hops included.
        """
        try:
            host = (urlparse(url).hostname or "").strip().lower()
        except ValueError:
            return False, "unparseable URL"
        if not host:
            return False, "URL has no host"
        if private_targets_allowed():
            return True, ""
        cached = self._host_allow_cache.get(host)
        if cached is None:
            # Single shared SSRF policy (core.target_validation), cached per
            # host for the engine's lifetime.
            cached = _host_resolves_to_public_ip(host)
            self._host_allow_cache[host] = cached
        return (True, "") if cached else (False, "target resolves to a private or internal address")

    def send_request(
        self,
        method: str,
        url: str,
        payload: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        json_payload: Optional[Dict[str, Any]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
        follow_redirects: bool = True
    ) -> Dict[str, Any]:
        """
        Dispatches HTTP request to the target URL with provided payload and records performance metrics.
        Returns a structured dictionary containing request and response telemetry details.

        Redirects are followed manually (never by httpx itself): every hop's
        host is validated against the SSRF guard before it is fetched. A
        redirect to a private/internal host is refused — the hop is not
        fetched and a synthetic blocked result is returned. Pass
        follow_redirects=False (as the Open_Redirect probe does) to receive
        the raw 3xx response without any following.
        """
        method_upper = method.upper()
        req_headers = self.default_headers.copy()
        if custom_headers:
            req_headers.update(custom_headers)

        payload_str = payload or ""
        params, data, json_data = _prepare_request_parts(
            method_upper, url, payload_str, query_params, form_data, json_payload, req_headers
        )

        start_time = time.time()

        def _timeout_result(exc) -> Dict[str, Any]:
            elapsed_time = time.time() - start_time
            logger.warning(f"Request timeout for [{method_upper}] {url}")
            return {
                "method": method_upper,
                "url": url,
                "payload": payload_str,
                "status_code": 408,
                "response_body": "",
                "response_time": elapsed_time,
                "response_size": 0,
                "request_headers": req_headers,
                "response_headers": {},
                "truncated": False,
                "error": f"TimeoutException: {str(exc)}"
            }

        def _error_result(exc) -> Dict[str, Any]:
            elapsed_time = time.time() - start_time
            logger.error(f"Request error for [{method_upper}] {url}: {exc}")
            return {
                "method": method_upper,
                "url": url,
                "payload": payload_str,
                "status_code": 0,
                "response_body": "",
                "response_time": elapsed_time,
                "response_size": 0,
                "request_headers": req_headers,
                "response_headers": {},
                "truncated": False,
                "error": f"ConnectionError: {str(exc)}"
            }

        try:
            # httpx never follows on its own: the loop below walks redirects
            # hop by hop so each target is SSRF-validated first.
            with _build_client(httpx.Client, **self._client_kwargs(False)) as client:
                ok, reason = self._hop_allowed(url)
                if not ok:
                    return _blocked_redirect_result(
                        method_upper, url, payload_str, req_headers,
                        time.time() - start_time, reason
                    )
                cur_method, cur_url = method_upper, url
                cur_params, cur_data, cur_json = params, data, json_data
                hops = 0
                while True:
                    with client.stream(
                        method=cur_method,
                        url=cur_url,
                        params=cur_params,
                        data=cur_data,
                        json=cur_json,
                        headers=req_headers
                    ) as response:
                        elapsed_time = time.time() - start_time
                        location = response.headers.get("location")
                        if follow_redirects and response.status_code in _REDIRECT_STATUSES and location:
                            if hops >= MAX_REDIRECT_HOPS:
                                return _blocked_redirect_result(
                                    method_upper, str(response.url), payload_str,
                                    req_headers, elapsed_time,
                                    f"too many redirects (>{MAX_REDIRECT_HOPS} hops)"
                                )
                            hop_ok, target, hop_reason = _validate_redirect_target(
                                str(response.url), location
                            )
                            if not hop_ok:
                                return _blocked_redirect_result(
                                    method_upper, target, payload_str,
                                    req_headers, elapsed_time, hop_reason
                                )
                            hops += 1
                            logger.info(
                                "Following redirect %d [%s] %s -> %s",
                                hops, cur_method, cur_url, target
                            )
                            cur_method = _next_hop_method(response.status_code, cur_method)
                            if cur_method == "GET":
                                # 301/302/303 drop the body; like httpx, the
                                # original query params are not re-attached.
                                cur_params, cur_data, cur_json = None, None, None
                            else:
                                # 307/308 preserve method and body (query params
                                # still belong to the original request only).
                                cur_params = None
                            cur_url = target
                            continue
                        # Streamed and capped at 2 MiB: a huge body (e.g. an LFI
                        # probe hitting a large file) is truncated instead of
                        # loading unbounded bytes into worker memory.
                        raw_body, truncated = _read_capped(response)
                        response_body = _decode_body(raw_body, response.headers.get("content-type", ""))
                        response_bytes = _wire_size(response, len(raw_body))

                        result = {
                            "method": method_upper,
                            "url": str(response.url),
                            "payload": payload_str,
                            "status_code": response.status_code,
                            "response_body": response_body,
                            "response_time": elapsed_time,
                            "response_size": response_bytes,
                            "request_headers": req_headers,
                            "response_headers": dict(response.headers),
                            "truncated": truncated,
                            "error": None
                        }

                        logger.info(f"Request [{method_upper}] {url} -> {response.status_code} ({elapsed_time:.3f}s)")
                        return result

        except httpx.TimeoutException as exc:
            return _timeout_result(exc)
        except Exception as exc:
            return _error_result(exc)

    async def send_request_async(
        self,
        method: str,
        url: str,
        payload: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        json_payload: Optional[Dict[str, Any]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
        follow_redirects: bool = True
    ) -> Dict[str, Any]:
        """
        Asynchronously dispatches HTTP request using httpx.AsyncClient for high-throughput API testing.

        Redirects are followed manually with per-hop SSRF validation, exactly
        like the sync path — see send_request.
        """
        method_upper = method.upper()
        req_headers = self.default_headers.copy()
        if custom_headers:
            req_headers.update(custom_headers)

        payload_str = payload or ""
        params, data, json_data = _prepare_request_parts(
            method_upper, url, payload_str, query_params, form_data, json_payload, req_headers
        )

        start_time = time.time()

        def _timeout_result(exc) -> Dict[str, Any]:
            # Mirror the sync path: a timeout is synthetic 408, which the
            # signature layer treats as a suspected request-impact signal when
            # the baseline was healthy (not a silent status 0).
            elapsed_time = time.time() - start_time
            logger.warning(f"Async request timeout for [{method_upper}] {url}")
            return {
                "method": method_upper,
                "url": url,
                "payload": payload_str,
                "status_code": 408,
                "response_body": "",
                "response_time": elapsed_time,
                "response_size": 0,
                "request_headers": req_headers,
                "response_headers": {},
                "truncated": False,
                "error": f"AsyncTimeoutException: {str(exc)}"
            }

        def _error_result(exc) -> Dict[str, Any]:
            elapsed_time = time.time() - start_time
            logger.error(f"Async request error for [{method_upper}] {url}: {exc}")
            return {
                "method": method_upper,
                "url": url,
                "payload": payload_str,
                "status_code": 0,
                "response_body": "",
                "response_time": elapsed_time,
                "response_size": 0,
                "request_headers": req_headers,
                "response_headers": {},
                "truncated": False,
                "error": f"AsyncError: {str(exc)}"
            }

        try:
            # httpx never follows on its own: the loop below walks redirects
            # hop by hop so each target is SSRF-validated first.
            async with _build_client(httpx.AsyncClient, **self._client_kwargs(False)) as client:
                ok, reason = self._hop_allowed(url)
                if not ok:
                    return _blocked_redirect_result(
                        method_upper, url, payload_str, req_headers,
                        time.time() - start_time, reason
                    )
                cur_method, cur_url = method_upper, url
                cur_params, cur_data, cur_json = params, data, json_data
                hops = 0
                while True:
                    async with client.stream(
                        method=cur_method,
                        url=cur_url,
                        params=cur_params,
                        data=cur_data,
                        json=cur_json,
                        headers=req_headers
                    ) as response:
                        elapsed_time = time.time() - start_time
                        location = response.headers.get("location")
                        if follow_redirects and response.status_code in _REDIRECT_STATUSES and location:
                            if hops >= MAX_REDIRECT_HOPS:
                                return _blocked_redirect_result(
                                    method_upper, str(response.url), payload_str,
                                    req_headers, elapsed_time,
                                    f"too many redirects (>{MAX_REDIRECT_HOPS} hops)"
                                )
                            hop_ok, target, hop_reason = _validate_redirect_target(
                                str(response.url), location
                            )
                            if not hop_ok:
                                return _blocked_redirect_result(
                                    method_upper, target, payload_str,
                                    req_headers, elapsed_time, hop_reason
                                )
                            hops += 1
                            logger.info(
                                "Async following redirect %d [%s] %s -> %s",
                                hops, cur_method, cur_url, target
                            )
                            cur_method = _next_hop_method(response.status_code, cur_method)
                            if cur_method == "GET":
                                cur_params, cur_data, cur_json = None, None, None
                            else:
                                cur_params = None
                            cur_url = target
                            continue
                        raw_body, truncated = await _aread_capped(response)
                        response_body = _decode_body(raw_body, response.headers.get("content-type", ""))
                        response_bytes = _wire_size(response, len(raw_body))

                        result = {
                            "method": method_upper,
                            "url": str(response.url),
                            "payload": payload_str,
                            "status_code": response.status_code,
                            "response_body": response_body,
                            "response_time": elapsed_time,
                            "response_size": response_bytes,
                            "request_headers": req_headers,
                            "response_headers": dict(response.headers),
                            "truncated": truncated,
                            "error": None
                        }

                        logger.info(f"Async Request [{method_upper}] {url} -> {response.status_code} ({elapsed_time:.3f}s)")
                        return result

        except httpx.TimeoutException as exc:
            return _timeout_result(exc)
        except Exception as exc:
            return _error_result(exc)


if __name__ == "__main__":
    engine = RequestEngine()
    res = engine.send_request("GET", "https://httpbin.org/get", payload="test_payload")
    print("\n[+] Sample Request Output:")
    for k, v in res.items():
        if k != "response_body":
            print(f"  {k}: {v}")
