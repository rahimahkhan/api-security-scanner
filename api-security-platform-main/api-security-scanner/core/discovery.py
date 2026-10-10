import re
import json
import yaml
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from core.http_client import build_client, client_kwargs

# Patterns for API paths hiding inside JavaScript (SPA fetch/XHR calls that a
# plain HTML crawl would never see). Applied to inline <script> bodies and to
# fetched same-origin script files.
_JS_API_PATH_PATTERNS = [
    re.compile(r'''fetch\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''\$\.(?:get|post|ajax)\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''(?:url|endpoint|apiUrl|baseURL)\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''["'`](\/api\/[^"'`\s]*)["'`]'''),
]

# Never treat static assets as API endpoints.
_JS_PATH_IGNORED_EXTENSIONS = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
)

_JS_MAX_SCRIPTS_PER_PAGE = 12
_JS_MAX_SCRIPT_BYTES = 512 * 1024
_JS_MAX_PATHS_PER_PAGE = 60

class EndpointDiscovery:
    """
    Crawls a base URL to automatically discover API endpoints, forms,
    and links without requiring an OpenAPI specification document.
    """

    COMMON_API_PATHS = [
        "/api",
        "/graphql",
        "/graphiql",
        "/api/v1",
        "/api/v2",
        "/v1",
        "/v2",
        "/health",
        "/status",
        "/users",
        "/auth",
        "/login",
        "/search",
        "/products",
        "/cart",
        "/admin",
        "/signup",
        "/register",
        "/profile",
        "/account",
        "/dashboard",
        "/comments",
        "/articles",
        "/posts",
        "/categories",
        "/tags",
        # VAmPI specific paths
        "/users/v1",
        "/users/v1/login",
        "/users/v1/register",
        "/users/v1/_debug",
        "/users/v1/debug",
        "/users/v1/admin",
        "/users/v1/name1",
        "/users/v1/me",
        "/users/v1/1",
        "/users/v1/2",
        "/users/v1/3",
        "/books",
        "/books/v1",
        "/books/v1/1",
        "/books/v1/book1",
        "/createdb",
        # OWASP Juice Shop paths
        "/rest/user/login",
        "/rest/products/search",
        "/api/Users",
        "/api/Feedbacks",
        # General API patterns
        "/api/v1/users",
        "/api/v1/admin",
        "/api/v1/login",
        "/api/v1/register"
    ]

    def __init__(self, base_url: str, timeout: float = 10.0, max_depth: int = 3,
                 progress_callback=None):
        parsed_input = urlparse(base_url)
        normalized_input_path = parsed_input.path
        if normalized_input_path.endswith("/."):
            normalized_input_path = normalized_input_path[:-2] + "/"
        normalized_input = parsed_input._replace(path=normalized_input_path).geturl()
        # The crawl seed keeps the exact user-supplied URL (query string and
        # fragment included) so the base page itself is discovered as-is.
        self.seed_url = normalized_input
        # Relative paths are joined against a clean base instead: a query string
        # in the input (e.g. ".../search?q=x") would otherwise corrupt every
        # joined URL (".../search?q=x/api").
        clean_base = parsed_input._replace(
            path=normalized_input_path, query="", fragment=""
        ).geturl()
        self.base_url = clean_base.rstrip("/")
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme or "http"
        self.timeout = timeout
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict[str, str]] = []
        # Optional hook called as progress_callback(pages_crawled, endpoints_found)
        # so long crawls can report live progress (e.g. the dashboard ETA banner).
        self.progress_callback = progress_callback

    def _emit_progress(self) -> None:
        """Report crawl progress; never let a callback bug break discovery."""
        if self.progress_callback is None:
            return
        try:
            self.progress_callback(len(self.visited_urls), len(self.discovered_endpoints))
        except Exception as exc:
            logger.debug(f"Discovery progress callback failed: {exc}")

    @staticmethod
    def query_fields(url: str) -> List[str]:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())

    def is_same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return not parsed.netloc or parsed.netloc == self.domain

    def normalize_url(self, url: str, base: str = "") -> str:
        joined = urljoin(base or self.base_url, url)
        parsed = urlparse(joined)
        normalized_path = parsed.path
        if normalized_path.endswith("/."):
            normalized_path = normalized_path[:-2] + "/"
        query_part = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme}://{parsed.netloc}{normalized_path}{query_part}"

    OPENAPI_SPEC_PATHS = [
        "/openapi.json",
        "/openapi.yaml",
        "/openapi3.yml",
        "/openapi3.yaml",
        "/swagger.json",
        "/swagger.yaml",
        "/v2/api-docs",
        "/api-docs",
        "/api/openapi.json",
        "/api/swagger.json"
    ]

    def discover(self) -> List[Dict[str, str]]:
        """
        Executes endpoint discovery by parsing OpenAPI specs, crawling HTML pages,
        and probing common API paths. Returns a list of dicts with 'url' and 'method'.
        """
        logger.info(f"Starting endpoint discovery on target: {self.base_url}")
        print(f"\n[+] Starting Endpoint Discovery for: {self.base_url}")

        self._emit_progress()
        self._discover_openapi_specs()
        self._crawl_page(self.seed_url, depth=0)
        self._probe_common_paths()

        # Deduplicate results. The identifier is (url, method): the same path
        # exposed over several HTTP methods must keep one entry per method, so
        # e.g. OpenAPI "GET /users" + "POST /users" are both scanned instead of
        # the POST being silently merged away.
        unique_endpoints: List[Dict[str, str]] = []
        by_identifier: Dict[str, Dict[str, Any]] = {}

        def _dedup_list(items):
            result = []
            for item in items:
                if item not in result:
                    result.append(item)
            return result

        for ep in self.discovered_endpoints:
            identifier = (ep["url"], (ep.get("method") or "GET").upper())
            if identifier not in by_identifier:
                by_identifier[identifier] = dict(ep)
                continue
            existing = by_identifier[identifier]
            for key in ("form_fields", "query_fields", "json_fields", "request_content_types", "csrf_token_fields", "security_requirements"):
                combined = (existing.get(key) or []) + (ep.get(key) or [])
                merged = _dedup_list(combined)
                if merged:
                    existing[key] = merged
            if ep.get("form_defaults"):
                existing["form_defaults"] = {**existing.get("form_defaults", {}), **ep["form_defaults"]}
            if ep.get("form_method"):
                existing["form_method"] = ep["form_method"]
                existing["method"] = ep["form_method"]
            if ep.get("operation_id"):
                existing["operation_id"] = ep["operation_id"]

        unique_endpoints = list(by_identifier.values())
        self.discovered_endpoints = unique_endpoints

        print(f"\n[+] Discovery complete. Found {len(self.discovered_endpoints)} unique endpoints:")
        for idx, ep in enumerate(self.discovered_endpoints, start=1):
            print(f"  {idx}. [{ep['method']}] {ep['url']}")

        return self.discovered_endpoints

    def _discover_openapi_specs(self) -> None:
        """Attempts to discover and parse OpenAPI / Swagger specifications."""
        import json
        import yaml

        with build_client(httpx.Client, **client_kwargs(self.timeout)) as client:
            for spec_path in self.OPENAPI_SPEC_PATHS:
                target_url = f"{self.base_url}{spec_path}"
                try:
                    resp = client.get(target_url)
                    if resp.status_code == 200 and len(resp.text.strip()) > 10:
                        spec_data = None
                        try:
                            spec_data = resp.json()
                        except Exception:
                            try:
                                spec_data = yaml.safe_load(resp.text)
                            except Exception:
                                spec_data = None

                        if isinstance(spec_data, dict) and "paths" in spec_data:
                            logger.info(f"Discovered OpenAPI spec at: {target_url}")
                            for api_path, methods in spec_data["paths"].items():
                                # Replace parameterized path variables like {username} with test values
                                clean_path = re.sub(r"\{[^}]+\}", "admin", api_path)
                                full_url = f"{self.base_url}{clean_path}"
                                for http_method, operation in methods.items():
                                    if http_method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                                        continue
                                    endpoint = {
                                        "url": full_url,
                                        "method": http_method.upper()
                                    }
                                    if isinstance(operation, dict):
                                        endpoint["operation_id"] = operation.get("operationId", "")
                                        endpoint["security_requirements"] = operation.get("security", spec_data.get("security", [])) or []
                                        parameters = operation.get("parameters") or []
                                        query_fields = [
                                            parameter.get("name")
                                            for parameter in parameters
                                            if isinstance(parameter, dict) and parameter.get("in") == "query" and parameter.get("name")
                                        ]
                                        if query_fields:
                                            endpoint["query_fields"] = query_fields
                                        request_body = operation.get("requestBody") or {}
                                        content = request_body.get("content") if isinstance(request_body, dict) else {}
                                        if isinstance(content, dict):
                                            endpoint["request_content_types"] = list(content.keys())
                                            for media_type in ("application/json", "application/*+json"):
                                                media_schema = content.get(media_type, {}).get("schema", {}) if isinstance(content.get(media_type), dict) else {}
                                                properties = media_schema.get("properties", {}) if isinstance(media_schema, dict) else {}
                                                if isinstance(properties, dict) and properties:
                                                    endpoint["json_fields"] = list(properties.keys())
                                                    break
                                    self.discovered_endpoints.append(endpoint)
                except Exception as exc:
                    logger.debug(f"OpenAPI probe exception at {target_url}: {exc}")

    @staticmethod
    def _probe_post_fallback(client, target_url: str) -> bool:
        """Return True when a path that rejects GET looks like a live POST endpoint.

        Any path that answers 405 to GET gets one POST baseline probe; it is
        kept as a POST endpoint unless POST also 404s or 405s.
        """
        try:
            post_resp = client.post(target_url, json={})
            return post_resp.status_code not in (404, 405)
        except httpx.RequestError:
            return False

    def _crawl_page(self, current_url: str, depth: int) -> None:
        if depth > self.max_depth or current_url in self.visited_urls:
            return

        self.visited_urls.add(current_url)

        try:
            with build_client(httpx.Client, **client_kwargs(self.timeout)) as client:
                response = client.get(current_url)

                # GraphQL commonly returns 400 JSON when no query is supplied; that still proves the endpoint exists.
                content_type = response.headers.get("content-type", "")
                is_graphql_error = "graphql" in current_url.lower() and response.status_code in {400, 405} and "json" in content_type.lower()
                if response.status_code < 400 or is_graphql_error:
                    self.discovered_endpoints.append({
                        "url": current_url,
                        "method": "GET",
                        "query_fields": self.query_fields(current_url)
                    })
                elif response.status_code == 405:
                    # GET is not allowed here, but the path exists: it may be a
                    # POST-only endpoint (form handlers, API actions). Probe it
                    # once with POST instead of dropping it silently.
                    if self._probe_post_fallback(client, current_url):
                        self.discovered_endpoints.append({
                            "url": current_url,
                            "method": "POST",
                            "query_fields": self.query_fields(current_url)
                        })

                # Parse HTML content if available
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type:
                    soup = BeautifulSoup(response.text, "html.parser")

                    # Extract links (<a> tags)
                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag["href"].strip()
                        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                            full_url = self.normalize_url(href, base=current_url)
                            if self.is_same_domain(full_url):
                                self.discovered_endpoints.append({
                                    "url": full_url,
                                    "method": "GET",
                                    "query_fields": self.query_fields(full_url)
                                })
                                if depth < self.max_depth:
                                    self._crawl_page(full_url, depth + 1)

                    # Extract forms (<form> tags)
                    for form in soup.find_all("form"):
                        action = form.get("action", "").strip()
                        method = form.get("method", "GET").upper()
                        form_url = self.normalize_url(action, base=current_url) if action else current_url
                        if self.is_same_domain(form_url):
                            form_elements = [
                                field for field in form.find_all(["input", "textarea", "select"], attrs={"name": True})
                                if field.get("name") and field.get("name").strip()
                            ]
                            field_names = [
                                field.get("name").strip()
                                for field in form_elements
                                if field.name != "input" or field.get("type", "text").lower() not in {"hidden", "submit", "button", "reset", "file"}
                            ]
                            form_defaults = {
                                field.get("name").strip(): field.get("value", "")
                                for field in form_elements
                            }
                            csrf_token_fields = [
                                field.get("name").strip()
                                for field in form_elements
                                if field.get("type", "").lower() == "hidden"
                                and any(token in field.get("name", "").lower() for token in ("csrf", "nonce", "token"))
                            ]
                            self.discovered_endpoints.append({
                                "url": form_url,
                                "method": method,
                                "form_method": method,
                                "form_fields": field_names,
                                "form_defaults": form_defaults,
                                "csrf_token_fields": csrf_token_fields,
                                "query_fields": self.query_fields(form_url)
                            })

                    # Extract API routes referenced inside JavaScript (SPA
                    # fetch/XHR calls invisible to plain HTML parsing).
                    self._extract_js_api_paths(soup, current_url, client)

        except httpx.RequestError as exc:
            logger.warning(f"Request error while crawling {current_url}: {exc}")
        except Exception as exc:
            logger.error(f"Unexpected error crawling {current_url}: {exc}")
        finally:
            self._emit_progress()

    def _extract_js_api_paths(self, soup, current_url: str, client) -> None:
        """Discover API routes referenced inside JavaScript.

        SPA frontends call APIs from JS bundles that contain no HTML links or
        forms. Inline <script> bodies and same-origin script files (bounded
        count and size) are scanned for fetch/axios-style calls and "/api/..."
        string literals; plausible paths become discovered GET endpoints.
        """
        js_sources: List[str] = []
        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            text = script.string or ""
            if text.strip():
                js_sources.append(text)

        fetched = 0
        for script in soup.find_all("script", src=True):
            if fetched >= _JS_MAX_SCRIPTS_PER_PAGE:
                break
            src = (script.get("src") or "").strip()
            if not src or src.startswith(("data:", "javascript:")):
                continue
            script_url = self.normalize_url(src, base=current_url)
            if not self.is_same_domain(script_url):
                continue
            try:
                # Streamed and capped: a bloated third-party bundle must not
                # blow up discovery memory.
                with client.stream("GET", script_url) as sresp:
                    if sresp.status_code >= 400:
                        continue
                    chunks = []
                    kept = 0
                    for chunk in sresp.iter_bytes(chunk_size=65536):
                        room = _JS_MAX_SCRIPT_BYTES - kept
                        if room <= 0:
                            break
                        if len(chunk) > room:
                            chunks.append(chunk[:room])
                            break
                        chunks.append(chunk)
                        kept += len(chunk)
                    js_sources.append(b"".join(chunks).decode("utf-8", errors="replace"))
                    fetched += 1
            except httpx.RequestError:
                continue

        found = 0
        for js_text in js_sources:
            for pattern in _JS_API_PATH_PATTERNS:
                for match in pattern.finditer(js_text):
                    if found >= _JS_MAX_PATHS_PER_PAGE:
                        return
                    candidate = (match.group(1) or "").strip()
                    if not candidate or "${" in candidate:
                        continue  # dynamic template literal, not a concrete path
                    path_part = urlparse(candidate).path if "://" in candidate else candidate
                    if not path_part.startswith("/"):
                        continue
                    if path_part.lower().endswith(_JS_PATH_IGNORED_EXTENSIONS):
                        continue
                    full_url = self.normalize_url(path_part, base=current_url)
                    if not self.is_same_domain(full_url):
                        continue
                    self.discovered_endpoints.append({
                        "url": full_url,
                        "method": "GET",
                        "query_fields": self.query_fields(full_url),
                        "discovered_via": "javascript",
                    })
                    found += 1
        if found:
            logger.info(f"Discovered {found} API paths from JavaScript on {current_url}")

    def _probe_common_paths(self) -> None:
        with build_client(httpx.Client, **client_kwargs(self.timeout)) as client:
            for idx, relative_path in enumerate(self.COMMON_API_PATHS):
                target_url = f"{self.base_url}{relative_path}"
                if target_url not in self.visited_urls:
                    try:
                        resp = client.get(target_url)
                        if resp.status_code < 404:
                            self.discovered_endpoints.append({"url": target_url, "method": "GET"})
                        elif resp.status_code == 405:
                            # GET not allowed: the path may be POST-only. Keep it
                            # when a POST baseline probe doesn't 404/405.
                            if self._probe_post_fallback(client, target_url):
                                self.discovered_endpoints.append({"url": target_url, "method": "POST"})
                    except httpx.RequestError:
                        continue
                if idx % 10 == 0:
                    self._emit_progress()


if __name__ == "__main__":
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://httpbin.org"
    discoverer = EndpointDiscovery(base_url=test_url)
    results = discoverer.discover()
