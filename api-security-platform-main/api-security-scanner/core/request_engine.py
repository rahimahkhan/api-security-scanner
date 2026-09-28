import time
from typing import Dict, Any, Optional
import httpx
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from core.http_client import build_client as _build_client, client_kwargs


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

    def _client_kwargs(self, follow_redirects: bool) -> Dict[str, Any]:
        return client_kwargs(self.timeout, follow_redirects, self.trust_env)

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
        """
        method_upper = method.upper()
        req_headers = self.default_headers.copy()
        if custom_headers:
            req_headers.update(custom_headers)

        payload_str = payload or ""
        params = None
        data = None
        json_data = None

        if method_upper in ["GET", "DELETE"]:
            if query_params is not None:
                params = query_params
            elif payload_str:
                params = {"q": payload_str}
        elif method_upper in ["POST", "PUT", "PATCH"]:
            if form_data is not None:
                data = form_data
            elif json_payload is not None:
                json_data = json_payload
            elif payload_str:
                import json
                try:
                    json_data = json.loads(payload_str)
                except (json.JSONDecodeError, TypeError):
                    if req_headers.get("Content-Type") == "application/json":
                        json_data = {"data": payload_str}
                    else:
                        data = payload_str

        start_time = time.time()

        try:
            with _build_client(httpx.Client, **self._client_kwargs(follow_redirects)) as client:
                response = client.request(
                    method=method_upper,
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=req_headers
                )

                elapsed_time = time.time() - start_time
                response_body = response.text
                response_bytes = len(response.content)

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
                    "error": None
                }

                logger.info(f"Request [{method_upper}] {url} -> {response.status_code} ({elapsed_time:.3f}s)")
                return result

        except httpx.TimeoutException as exc:
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
                "error": f"TimeoutException: {str(exc)}"
            }
        except Exception as exc:
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
                "error": f"ConnectionError: {str(exc)}"
            }

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
        """
        method_upper = method.upper()
        req_headers = self.default_headers.copy()
        if custom_headers:
            req_headers.update(custom_headers)

        payload_str = payload or ""
        params = None
        data = None
        json_data = None

        if method_upper in ["GET", "DELETE"]:
            if query_params is not None:
                params = query_params
            elif payload_str:
                params = {"q": payload_str}
        elif method_upper in ["POST", "PUT", "PATCH"]:
            if form_data is not None:
                data = form_data
            elif json_payload is not None:
                json_data = json_payload
            elif payload_str:
                import json
                try:
                    json_data = json.loads(payload_str)
                except (json.JSONDecodeError, TypeError):
                    if req_headers.get("Content-Type") == "application/json":
                        json_data = {"data": payload_str}
                    else:
                        data = payload_str

        start_time = time.time()

        try:
            async with _build_client(httpx.AsyncClient, **self._client_kwargs(follow_redirects)) as client:
                response = await client.request(
                    method=method_upper,
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=req_headers
                )

                elapsed_time = time.time() - start_time
                response_body = response.text
                response_bytes = len(response.content)

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
                    "error": None
                }

                logger.info(f"Async Request [{method_upper}] {url} -> {response.status_code} ({elapsed_time:.3f}s)")
                return result

        except Exception as exc:
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
                "error": f"AsyncError: {str(exc)}"
            }


if __name__ == "__main__":
    engine = RequestEngine()
    res = engine.send_request("GET", "https://httpbin.org/get", payload="test_payload")
    print("\n[+] Sample Request Output:")
    for k, v in res.items():
        if k != "response_body":
            print(f"  {k}: {v}")
