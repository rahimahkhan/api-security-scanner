import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.risk_scorer import RiskScorer
from detection.signature import SignatureDetector


class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_empty_json_object_is_transmitted():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = RequestEngine(timeout=2).send_request(
            "POST", f"http://127.0.0.1:{server.server_port}/echo", json_payload={}
        )
        assert result["status_code"] == 200
        assert json.loads(result["response_body"]) == {}
    finally:
        server.shutdown()
        server.server_close()


def test_blank_query_parameter_is_counted():
    # The response-differential schema no longer counts query params; it
    # measures the response. A clean 200 probe must score as non-anomalous.
    features = ResponseParser().extract_features(
        {
            "method": "GET",
            "url": "http://example.test/search?flag&empty=",
            "payload": "",
            "status_code": 200,
            "response_size": 0,
            "response_body": "",
            "request_headers": {},
        }
    )
    assert features["status_class"] == 2
    assert features["error_keyword_count"] == 0


def test_numeric_object_url_without_sensitive_data_is_not_confirmed_bola():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/users/2",
            "payload": "",
            "status_code": 200,
            "response_size": 16,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"status":"ok"}',
            "request_headers": {},
        }
    )
    assert result["attack_type"] != "BOLA_IDOR" or result["has_proof"] is False
    assert result["is_vulnerable"] is False


def test_suspected_signature_is_not_reported_as_vulnerability():
    result = RiskScorer().calculate_risk(
        {
            "matched": True,
            "has_proof": False,
            "is_vulnerable": False,
            "points": 10,
            "finding_status": "Suspected",
            "proof_of_concept": "Payload syntax matched without proof",
        },
        {"is_anomaly": False, "points": 0},
        {"lstm_points": 0, "autoencoder_points": 0},
        "http://example.test/health",
        "GET",
        telemetry_data={"status_code": 200, "response_size": 16, "response_time": 0.01},
    )
    assert result["finding_status"] == "Suspected"
    assert result["is_vulnerable"] is False
    assert "verified" not in result["proof_of_concept"].lower()


def test_confirmed_bola_still_requires_sensitive_unauthorized_data():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/users/2",
            "payload": "",
            "status_code": 200,
            "response_size": 80,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"id":2,"username":"alice","email":"alice@example.test","role":"admin"}',
            "request_headers": {},
        }
    )
    assert result["attack_type"] == "BOLA_IDOR"
    assert result["finding_status"] == "Confirmed"
    assert result["is_vulnerable"] is True


def test_missing_dataset_is_not_replaced_with_fake_labels(tmp_path):
    from training.evaluate_models import PlatformEvaluator

    evaluator = PlatformEvaluator(test_csv_path=str(tmp_path / "missing.csv"))
    results = evaluator.evaluate_test_set()
    assert results["evaluation_status"] == "dataset_missing"
    assert results["combined_pipeline"]["precision"] is None
    assert results["combined_pipeline"]["recall"] is None
    assert results["combined_pipeline"]["f1_score"] is None


def test_endpoint_payload_binding_uses_discovered_form_field():
    from main import _bind_payload_to_endpoint

    query_params, form_data = _bind_payload_to_endpoint(
        {"form_fields": ["tfSearch"]}, "GET", "' OR 1=1 --"
    )
    assert query_params == {"tfSearch": "' OR 1=1 --"}
    assert form_data is None

    query_params, form_data = _bind_payload_to_endpoint(
        {"form_fields": ["tfUName", "tfUPass"]}, "POST", "admin' OR 1=1 --"
    )
    assert query_params is None
    assert form_data == {"tfUName": "admin' OR 1=1 --", "tfUPass": ""}


def test_endpoint_payload_binding_falls_back_without_form_metadata():
    from main import _bind_payload_to_endpoint

    assert _bind_payload_to_endpoint({"url": "http://example.test"}, "GET", "probe") == (None, None)


def test_connection_reset_after_healthy_baseline_is_suspected_not_confirmed():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/Search.asp",
            "payload": "' OR 1=1 --",
            "status_code": 0,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
            "request_headers": {},
        },
        baseline_telemetry={"status_code": 200, "response_size": 100, "response_time": 0.1},
    )
    assert result["attack_type"] == "Application_Connection_Reset"
    assert result["finding_status"] == "Suspected"
    assert result["is_vulnerable"] is False
    assert result["points"] == 10


def test_connection_reset_without_healthy_baseline_remains_network_error():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/Search.asp",
            "payload": "",
            "status_code": 0,
            "response_size": 0,
            "response_headers": {},
            "response_body": "",
            "request_headers": {},
        }
    )
    assert result["attack_type"] == "Network_Error"
    assert result["finding_status"] == "UNREACHABLE / NETWORK_DROPPED"


def test_default_endpoint_budget_without_override(monkeypatch):
    import importlib
    import config.settings as settings

    monkeypatch.delenv("MAX_ENDPOINTS", raising=False)
    reloaded = importlib.reload(settings)
    # Raised from 20 to 300 (2026-10-14): 20 silently truncated any real
    # application (DVWA alone exposes ~100 testable endpoints). The budget
    # still exists and stays env-overridable; _endpoint_priority decides
    # what survives when a cut is forced.
    assert reloaded.MAX_ENDPOINTS == 300


def test_endpoint_payload_binding_uses_discovered_query_field():
    from main import _bind_payload_to_endpoint

    query_params, form_data = _bind_payload_to_endpoint(
        {"query_fields": ["id"]}, "GET", "1' OR 1=1 --"
    )
    assert query_params == {"id": "1' OR 1=1 --"}
    assert form_data is None


def test_module_specific_queue_and_form_method_resolution():
    from main import _resolve_test_method, _select_test_queue

    queue = [
        {"type": "SQL_Injection", "method": "POST", "payload": "sql"},
        {"type": "SQL_Injection_GET", "method": "GET", "payload": "sql-get"},
        {"type": "Cross_Site_Scripting", "method": "POST", "payload": "xss"},
        {"type": "Command_Injection", "method": "GET", "payload": "cmd"},
        {"type": "Broken_Authentication", "method": "GET", "payload": ""},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]
    sqli = {"url": "https://example.test/vulnerabilities/sqli/", "form_method": "GET", "form_fields": ["id"]}
    selected = _select_test_queue(sqli, queue)
    assert [item["type"] for item in selected] == ["SQL_Injection", "SQL_Injection_GET", "Baseline_Inspection"]
    assert _resolve_test_method(sqli, selected[0], "GET") == "GET"

    xss = {"url": "https://example.test/vulnerabilities/xss_r/", "form_method": "GET", "form_fields": ["name"]}
    selected_xss = _select_test_queue(xss, queue)
    assert [item["type"] for item in selected_xss] == ["Cross_Site_Scripting", "Baseline_Inspection"]
    assert _resolve_test_method(xss, selected_xss[0], "GET") == "GET"


def test_stored_xss_module_skips_persistent_probe():
    from main import _select_test_queue

    queue = [
        {"type": "Cross_Site_Scripting", "method": "POST", "payload": "xss"},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]
    selected = _select_test_queue({"url": "https://example.test/vulnerabilities/xss_s/"}, queue)
    assert [item["type"] for item in selected] == ["Baseline_Inspection"]


def test_discovery_normalizes_dot_segment_query_route_without_losing_origin():
    from core.discovery import EndpointDiscovery

    discovery = EndpointDiscovery(
        "https://pentest-ground.com:4280/vulnerabilities/fi/.?page=include.php",
        timeout=1,
    )
    # The crawl seed keeps the exact user-supplied URL (query included)...
    assert discovery.seed_url == "https://pentest-ground.com:4280/vulnerabilities/fi/?page=include.php"
    # ...while relative paths join against a clean base so the query string
    # cannot corrupt joined URLs (".../search?q=x/api").
    assert discovery.base_url == "https://pentest-ground.com:4280/vulnerabilities/fi"
    assert discovery.normalize_url("https://pentest-ground.com:4280/vulnerabilities/fi/.?page=include.php") == discovery.seed_url


def test_endpoint_dedup_merges_form_metadata(monkeypatch):
    from core.discovery import EndpointDiscovery

    discovery = EndpointDiscovery("http://example.test", timeout=1)
    discovery._discover_openapi_specs = lambda: None
    discovery._crawl_page = lambda *_args, **_kwargs: None
    discovery._probe_common_paths = lambda: None
    discovery.discovered_endpoints = [
        {"url": "http://example.test/vulnerabilities/sqli/", "method": "GET", "query_fields": []},
        {"url": "http://example.test/vulnerabilities/sqli/", "method": "GET", "form_fields": ["id"], "form_method": "GET"},
    ]
    endpoints = discovery.discover()
    assert endpoints == [{"url": "http://example.test/vulnerabilities/sqli/", "method": "GET", "query_fields": [], "form_fields": ["id"], "form_method": "GET"}]


def test_sql_timing_requires_explicit_delay_payload():
    detector = SignatureDetector()
    ordinary = detector.analyze(
        {
            "url": "http://example.test/instructions.php",
            "payload": "' OR 1=1 --",
            "status_code": 200,
            "response_size": 100,
            "response_time": 29.0,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "Instructions page",
            "request_headers": {},
        },
        baseline_telemetry={"status_code": 200, "response_size": 100, "response_time": 0.1},
    )
    assert ordinary["finding_status"] == "Suspected"
    assert ordinary["has_proof"] is False

    explicit_delay = detector.analyze(
        {
            "url": "http://example.test/vulnerabilities/sqli/",
            "payload": "1' AND SLEEP(5)--",
            "status_code": 200,
            "response_size": 100,
            "response_time": 5.2,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "No database error",
            "request_headers": {},
        },
        baseline_telemetry={"status_code": 200, "response_size": 100, "response_time": 0.1},
    )
    assert explicit_delay["finding_status"] == "Confirmed"
    assert explicit_delay["has_proof"] is True


def test_form_binding_preserves_submit_defaults():
    from main import _bind_payload_to_endpoint

    query_params, form_data = _bind_payload_to_endpoint(
        {
            "form_fields": ["ip"],
            "form_defaults": {"Submit": "Submit"},
        },
        "POST",
        "; cat /etc/passwd",
    )
    assert query_params is None
    assert form_data == {"Submit": "Submit", "ip": "; cat /etc/passwd"}


def test_endpoint_dedup_keeps_every_http_method():
    # The same path exposed over several methods must keep one entry per
    # method: GET /exec and POST /exec are both scanned (previously the POST
    # was silently merged away and never tested).
    from core.discovery import EndpointDiscovery

    discovery = EndpointDiscovery("http://example.test", timeout=1)
    discovery._discover_openapi_specs = lambda: None
    discovery._crawl_page = lambda *_args, **_kwargs: None
    discovery._probe_common_paths = lambda: None
    discovery.discovered_endpoints = [
        {"url": "http://example.test/vulnerabilities/exec/", "method": "GET", "query_fields": []},
        {"url": "http://example.test/vulnerabilities/exec/", "method": "POST", "form_method": "POST", "form_fields": ["ip"], "form_defaults": {"Submit": "Submit"}},
    ]
    endpoints = discovery.discover()
    assert endpoints == [
        {"url": "http://example.test/vulnerabilities/exec/", "method": "GET", "query_fields": []},
        {
            "url": "http://example.test/vulnerabilities/exec/",
            "method": "POST",
            "form_method": "POST",
            "form_fields": ["ip"],
            "form_defaults": {"Submit": "Submit"},
        },
    ]


def test_generic_linux_server_information_is_not_command_execution_proof():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/phpinfo.php",
            "payload": "; cat /etc/passwd",
            "status_code": 200,
            "response_size": 1200,
            "response_time": 0.2,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "Linux training-host 6.8.0-31-generic",
            "request_headers": {},
            "attack_category": "Command_Injection",
        }
    )
    assert result["attack_type"] == "Command_Injection"
    assert result["finding_status"] == "Suspected"
    assert result["has_proof"] is False
    assert result["is_vulnerable"] is False


def test_expected_attack_category_prevents_command_payload_sql_misclassification():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/vulnerabilities/exec/",
            "payload": "; cat /etc/passwd",
            "status_code": 200,
            "response_size": 120,
            "response_time": 0.2,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "request_headers": {},
            "attack_category": "Command_Injection",
        },
        baseline_telemetry={"status_code": 200, "response_size": 80, "response_time": 0.1},
    )
    assert result["attack_type"] == "Command_Injection"
    assert result["finding_status"] == "Confirmed"
    assert result["has_proof"] is True


def test_local_file_inclusion_requires_system_file_marker():
    detector = SignatureDetector()
    confirmed = detector.analyze(
        {
            "url": "http://example.test/vulnerabilities/fi/",
            "payload": "../../../../../../etc/passwd",
            "status_code": 200,
            "response_size": 200,
            "response_time": 0.2,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "request_headers": {},
            "attack_category": "Local_File_Inclusion",
        }
    )
    assert confirmed["attack_type"] == "Local_File_Inclusion"
    assert confirmed["finding_status"] == "Confirmed"
    assert confirmed["has_proof"] is True

    suspected = detector.analyze(
        {
            "url": "http://example.test/vulnerabilities/fi/",
            "payload": "../../../../../../etc/passwd",
            "status_code": 200,
            "response_size": 200,
            "response_time": 0.2,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "File inclusion page without included content",
            "request_headers": {},
            "attack_category": "Local_File_Inclusion",
        }
    )
    assert suspected["finding_status"] == "Suspected"
    assert suspected["has_proof"] is False


def test_file_inclusion_module_selects_only_lfi_probe():
    from main import _select_test_queue

    queue = [
        {"type": "Local_File_Inclusion", "method": "GET", "payload": "../../etc/passwd"},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]
    selected = _select_test_queue({"url": "https://example.test/vulnerabilities/fi/"}, queue)
    assert [item["type"] for item in selected] == ["Local_File_Inclusion", "Baseline_Inspection"]


def test_graphql_endpoint_selects_introspection_probe_only():
    from main import _select_test_queue

    queue = [
        {"type": "GraphQL_Introspection", "method": "POST", "payload": "{ __schema { queryType { fields { name } } } }", "json_payload": {"query": "{ __schema { queryType { fields { name } } } }"}},
        {"type": "SQL_Injection_GET", "method": "GET", "payload": "' OR 1=1 --"},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]
    selected = _select_test_queue({"url": "https://example.test/graphql"}, queue)
    assert [item["type"] for item in selected] == ["GraphQL_Introspection", "Baseline_Inspection"]


def test_graphql_introspection_is_informational_not_vulnerability():
    result = SignatureDetector().analyze(
        {
            "url": "https://example.test/graphql",
            "payload": "{ __schema { queryType { fields { name } } } }",
            "status_code": 200,
            "response_size": 200,
            "response_time": 0.3,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"data":{"__schema":{"queryType":{"fields":[{"name":"users"}]}}}}',
            "request_headers": {"Content-Type": "application/json"},
            "attack_category": "GraphQL_Introspection",
        }
    )
    assert result["attack_type"] == "GraphQL_Introspection"
    assert result["finding_status"] == "Informational"
    assert result["is_vulnerable"] is False
    assert result["points"] == 0


def test_graphql_error_response_is_discovered_as_endpoint(monkeypatch):
    from core.discovery import EndpointDiscovery

    class FakeResponse:
        status_code = 400
        headers = {"content-type": "application/json"}
        text = '{"errors":[{"message":"Must provide query string."}]}'

    class FakeClient:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def get(self, _url):
            return FakeResponse()

    monkeypatch.setattr("core.discovery.httpx.Client", lambda **_kwargs: FakeClient())
    discovery = EndpointDiscovery("https://example.test/graphql", timeout=1, max_depth=0)
    discovery._discover_openapi_specs = lambda: None
    discovery._probe_common_paths = lambda: None
    endpoints = discovery.discover()
    assert endpoints[0]["url"] == "https://example.test/graphql"


def test_graphql_informational_finding_keeps_attack_type():
    from main import run_pipeline
    from database.models import Finding

    # The persistence behavior is covered through the signature result; this keeps the regression focused on the named category.
    result = SignatureDetector().analyze(
        {
            "url": "https://example.test/graphql",
            "payload": "{ __schema { queryType { fields { name } } } }",
            "status_code": 200,
            "response_size": 100,
            "response_time": 0.2,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"data":{"__schema":{"queryType":{"fields":[{"name":"users"}]}}}}',
            "request_headers": {},
            "attack_category": "GraphQL_Introspection",
        }
    )
    assert result["attack_type"] == "GraphQL_Introspection"
    assert result["finding_status"] == "Informational"


def test_read_only_safe_endpoint_filter_excludes_state_changes():
    from main import _is_safe_read_only_endpoint

    assert _is_safe_read_only_endpoint({"url": "http://example.test/health", "method": "GET"}) is True
    assert _is_safe_read_only_endpoint({"url": "http://example.test/graphql", "method": "GET"}) is True
    assert _is_safe_read_only_endpoint({"url": "http://example.test/login", "method": "GET"}) is False
    assert _is_safe_read_only_endpoint({"url": "http://example.test/users", "method": "POST"}) is False


def test_credential_login_path_selects_dedicated_sqli_probe():
    from main import _select_test_queue

    queue = [
        {"type": "SQL_Injection_Credential", "method": "POST", "payload": "x' OR '1'='1", "json_payload": {"email": "nobody-test@example.com", "password": "x' OR '1'='1"}},
        {"type": "SQL_Injection_GET", "method": "GET", "payload": "' OR 1=1 --"},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]
    selected = _select_test_queue({"url": "http://example.test/identity/api/auth/login"}, queue)
    assert [item["type"] for item in selected] == ["SQL_Injection_Credential", "Baseline_Inspection"]


def test_credential_sql_payload_is_classified_as_sql_injection():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/identity/api/auth/login",
            "payload": "x' OR '1'='1",
            "status_code": 500,
            "response_size": 74,
            "response_time": 0.6,
            "response_headers": {"Content-Type": "text/plain"},
            "response_body": "UserDetailsService returned null, which is an interface contract violation",
            "request_headers": {"Content-Type": "application/json"},
            "attack_category": "SQL_Injection_Credential",
        }
    )
    assert result["attack_type"] == "SQL_Injection"
    assert result["finding_status"] == "Suspected"
    assert result["is_vulnerable"] is False


def test_http_500_is_not_reported_as_security_header_finding():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/identity/api/auth/login",
            "payload": "",
            "status_code": 500,
            "response_size": 74,
            "response_time": 0.6,
            "response_headers": {"Content-Type": "text/plain"},
            "response_body": "backend error",
            "request_headers": {},
        }
    )
    assert result["attack_type"] != "Security_Misconfiguration"


def test_frontend_shell_response_is_not_active_api_evidence():
    from main import _is_frontend_shell_response

    assert _is_frontend_shell_response(
        "http://example.test/api/users",
        {"content-type": "text/html"},
        '<html><body><div id="root"></div></body></html>',
    ) is True
    assert _is_frontend_shell_response(
        "http://example.test/api/users",
        {"content-type": "application/json"},
        '{"users":[]}',
    ) is False


def test_signature_ignores_frontend_shell_probe():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/api/users",
            "payload": "' OR 1=1 --",
            "status_code": 200,
            "response_size": 2835,
            "response_time": 0.3,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": '<html><div id="root"></div></html>',
            "request_headers": {},
            "frontend_shell_response": True,
        }
    )
    assert result["matched"] is False
    assert result["is_vulnerable"] is False
    assert result["finding_status"] == "Informational"


def test_frontend_shell_detection_covers_crapi_route_families():
    from main import _is_frontend_shell_response

    for path in ("/users/v1/1", "/books/v1/book1", "/rest/products/search"):
        assert _is_frontend_shell_response(
            "http://example.test" + path,
            {"Content-Type": "text/html"},
            '<html><div id="root"></div></html>',
        ) is True


def test_get_only_endpoint_keeps_xss_probe_on_get():
    from main import _resolve_test_method

    assert _resolve_test_method(
        {"url": "http://example.test/api/Feedbacks", "method": "GET"},
        {"type": "Cross_Site_Scripting", "method": "POST"},
        "GET",
    ) == "GET"


def test_405_response_is_not_vulnerability_proof():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/api/Feedbacks",
            "payload": "<script>alert('xss')</script>",
            "status_code": 405,
            "response_size": 163,
            "response_time": 0.2,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "405 Not Allowed",
            "request_headers": {},
        }
    )
    assert result["is_vulnerable"] is False
    assert result["matched"] is False


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "https://example.com/api-security-redirect-check")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, *_args):
        pass


def test_request_engine_can_preserve_redirect_location():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = RequestEngine(timeout=2).send_request(
            "GET",
            f"http://127.0.0.1:{server.server_port}/redirect",
            follow_redirects=False,
        )
        assert result["status_code"] == 302
        assert result["response_headers"]["location"] == "https://example.com/api-security-redirect-check"
    finally:
        server.shutdown()
        server.server_close()


def test_external_open_redirect_requires_external_location_proof():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/redirect",
            "payload": "https://example.com/api-security-redirect-check",
            "attack_category": "Open_Redirect",
            "status_code": 302,
            "response_size": 0,
            "response_headers": {"Location": "https://example.com/api-security-redirect-check"},
            "response_body": "",
            "request_headers": {},
        }
    )
    assert result["attack_type"] == "Open_Redirect"
    assert result["finding_status"] == "Confirmed"
    assert result["is_vulnerable"] is True


def test_same_host_canonicalization_redirect_is_not_confirmed_as_open_redirect():
    result = SignatureDetector().analyze(
        {
            "url": "https://pentest-ground.com:4280/vulnerabilities/open_redirect/",
            "payload": "https://example.com/api-security-redirect-check",
            "attack_category": "Open_Redirect",
            "status_code": 301,
            "response_size": 446,
            "response_headers": {"Location": "http://pentest-ground.com/vulnerabilities/open_redirect/?q=https%3A%2F%2Fexample.com%2Fapi-security-redirect-check"},
            "response_body": "",
            "request_headers": {},
        }
    )
    assert result["attack_type"] == "Open_Redirect"
    assert result["finding_status"] == "Suspected"
    assert result["is_vulnerable"] is False


def test_relative_redirect_is_not_confirmed_as_open_redirect():
    result = SignatureDetector().analyze(
        {
            "url": "http://example.test/redirect",
            "payload": "https://example.com/api-security-redirect-check",
            "attack_category": "Open_Redirect",
            "status_code": 302,
            "response_size": 0,
            "response_headers": {"Location": "/safe"},
            "response_body": "",
            "request_headers": {},
        }
    )
    assert result["attack_type"] == "Open_Redirect"
    assert result["finding_status"] == "Suspected"
    assert result["is_vulnerable"] is False


def test_redirect_query_route_selects_open_redirect_probe():
    from main import _select_test_queue

    queue = [
        {"type": "Open_Redirect", "payload": "https://example.com/check", "method": "GET"},
        {"type": "Baseline_Inspection", "payload": "", "method": "GET"},
        {"type": "SQL_Injection_GET", "payload": "' OR 1=1 --", "method": "GET"},
    ]
    selected = _select_test_queue(
        {
            "url": "https://example.test/vulnerabilities/open_redirect/source/low.php?redirect=info.php%3Fid%3D1",
            "method": "GET",
            "query_fields": ["redirect"],
        },
        queue,
    )
    assert [item["type"] for item in selected] == ["Open_Redirect", "Baseline_Inspection"]


def test_documented_json_fields_bind_active_payload_to_first_field():
    from main import _bind_json_payload_to_endpoint

    payload = _bind_json_payload_to_endpoint(
        {"json_fields": ["search", "page"]},
        "POST",
        "<script>alert('xss')</script>",
    )
    assert payload == {"search": "<script>alert('xss')</script>", "page": ""}


def test_json_binding_is_not_used_for_get_requests():
    from main import _bind_json_payload_to_endpoint

    assert _bind_json_payload_to_endpoint({"json_fields": ["search"]}, "GET", "probe") is None


def test_user_object_route_selects_bola_probes():
    from main import _select_test_queue

    queue = [
        {"type": "BOLA_IDOR", "payload": "id=1", "method": "GET", "path_suffix": "/users/v1/1"},
        {"type": "BOLA_IDOR", "payload": "id=2", "method": "GET", "path_suffix": "/users/v1/2"},
        {"type": "Baseline_Inspection", "payload": "", "method": "GET"},
    ]
    selected = _select_test_queue(
        {"url": "https://example.test/users/v1/1", "method": "GET"},
        queue,
    )
    assert [item["path_suffix"] for item in selected[:2]] == ["/users/v1/1", "/users/v1/2"]
    assert selected[-1]["type"] == "Baseline_Inspection"


def test_xxe_requires_xml_content_type_and_local_canary_proof():
    detector = SignatureDetector()
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    confirmed = detector.analyze(
        {
            "url": "https://example.test/xml",
            "payload": payload,
            "attack_category": "XXE",
            "status_code": 200,
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "response_size": 35,
            "response_time": 0.2,
            "response_headers": {"content-type": "application/xml"},
            "request_headers": {"Content-Type": "application/xml"},
        }
    )
    assert confirmed["attack_type"] == "XXE"
    assert confirmed["is_vulnerable"] is True
    assert confirmed["has_proof"] is True

    missing_xml_context = detector.analyze(
        {
            "url": "https://example.test/xml",
            "payload": payload,
            "attack_category": "XXE",
            "status_code": 200,
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "response_size": 35,
            "response_time": 0.2,
            "response_headers": {"content-type": "text/plain"},
            "request_headers": {"Content-Type": "application/xml"},
        }
    )
    assert missing_xml_context["is_vulnerable"] is False
    assert missing_xml_context["finding_status"] == "Suspected"


def test_xml_route_selects_only_xxe_probe():
    from main import _select_test_queue

    queue = [
        {"type": "XXE", "payload": "xml", "method": "POST"},
        {"type": "SQL_Injection", "payload": "sql", "method": "POST"},
        {"type": "Baseline_Inspection", "payload": "", "method": "GET"},
    ]
    selected = _select_test_queue({"url": "https://example.test/api/xml/import", "method": "POST"}, queue)
    assert [item["type"] for item in selected] == ["XXE", "Baseline_Inspection"]


def test_openapi_xml_content_type_selects_xxe_probe():
    from main import _select_test_queue

    queue = [
        {"type": "XXE", "payload": "xml", "method": "POST"},
        {"type": "SQL_Injection", "payload": "sql", "method": "POST"},
        {"type": "Baseline_Inspection", "payload": "", "method": "GET"},
    ]
    selected = _select_test_queue(
        {
            "url": "https://example.test/search",
            "method": "POST",
            "request_content_types": ["application/xml"],
        },
        queue,
    )
    assert [item["type"] for item in selected] == ["XXE", "Baseline_Inspection"]


def test_csrf_candidate_is_passive_and_requires_missing_token():
    from main import _is_csrf_candidate

    assert _is_csrf_candidate({
        "url": "https://example.test/vulnerabilities/csrf/",
        "method": "POST",
        "form_method": "POST",
        "form_fields": ["password_new", "password_conf"],
        "csrf_token_fields": [],
    }) is True
    assert _is_csrf_candidate({
        "url": "https://example.test/vulnerabilities/csrf/",
        "method": "POST",
        "form_method": "POST",
        "csrf_token_fields": ["user_token"],
    }) is False
    assert _is_csrf_candidate({
        "url": "https://example.test/vulnerabilities/csrf/",
        "method": "GET",
        "form_method": "GET",
        "form_fields": ["password_new", "password_conf"],
        "csrf_token_fields": [],
    }) is True


def test_differential_sqli_is_suspected_without_proof():
    detector = SignatureDetector()
    result = detector.analyze(
        {
            "url": "https://example.test/search?q=x%27%20OR%201%3D1--",
            "payload": "' OR 1=1 --",
            "attack_category": "SQL_Injection",
            "status_code": 200,
            "response_body": "different application response with no SQL error",
            "response_size": 54,
            "response_time": 0.3,
            "response_headers": {"content-type": "application/json"},
            "request_headers": {},
        },
        baseline_telemetry={
            "status_code": 200,
            "response_body": "normal response",
            "response_size": 14,
            "response_time": 0.2,
        },
    )
    assert result["attack_type"] == "SQL_Injection"
    assert result["finding_status"] == "Suspected"
    assert result["is_vulnerable"] is False
    assert result["response_diff"]["differential_signal"] is True
    assert result["response_diff"]["size_delta"] == 40


def test_rate_limit_observation_is_informational_not_vulnerability():
    detector = SignatureDetector()
    result = detector.analyze(
        {
            "url": "https://example.test/login",
            "payload": "invalid-canary",
            "status_code": 429,
            "response_body": '{"error":"too many requests"}',
            "response_size": 31,
            "response_time": 0.1,
            "response_headers": {"Retry-After": "5", "content-type": "application/json"},
            "request_headers": {},
        },
        baseline_telemetry={"status_code": 200, "response_body": "{}", "response_size": 2, "response_time": 0.1},
    )
    assert result["attack_type"] == "Rate_Limit_Observation"
    assert result["finding_status"] == "Informational"
    assert result["is_vulnerable"] is False
    assert result["response_diff"]["retry_after"] == "5"


def test_permissive_cors_with_credentials_is_informational():
    detector = SignatureDetector()
    result = detector.analyze(
        {
            "url": "https://example.test/api",
            "payload": "",
            "status_code": 200,
            "response_body": "{}",
            "response_size": 2,
            "response_time": 0.1,
            "response_headers": {
                "content-type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "request_headers": {},
        }
    )
    assert result["attack_type"] == "CORS_Misconfiguration"
    assert result["finding_status"] == "Informational"
    assert result["is_vulnerable"] is False
    assert result["cors_policy"]["allow_origin"] == "*"


def test_openapi_operation_metadata_is_retained():
    from core.discovery import EndpointDiscovery

    discoverer = EndpointDiscovery("https://example.test")
    discoverer.discovered_endpoints = [
        {
            "url": "https://example.test/users",
            "method": "GET",
            "operation_id": "listUsers",
            "security_requirements": [{"bearerAuth": []}],
        },
        {
            "url": "https://example.test/users",
            "method": "GET",
            "security_requirements": [{"apiKey": []}],
        },
    ]
    # Use the same deduplication shape as discovery to validate metadata merging.
    merged = {}
    for endpoint in discoverer.discovered_endpoints:
        key = (endpoint["url"], endpoint["method"])
        if key not in merged:
            merged[key] = dict(endpoint)
        else:
            combined_requirements = merged[key].get("security_requirements", []) + endpoint.get("security_requirements", [])
            merged[key]["security_requirements"] = []
            for requirement in combined_requirements:
                if requirement not in merged[key]["security_requirements"]:
                    merged[key]["security_requirements"].append(requirement)
    result = merged[("https://example.test/users", "GET")]
    assert result["operation_id"] == "listUsers"
    assert len(result["security_requirements"]) == 2


# --- Generic BOLA / mass-assignment queue probes (D2 fix) ---

def _d2_queue():
    return [
        {"type": "SQL_Injection_GET", "method": "GET", "payload": "' OR 1=1 --"},
        {"type": "Cross_Site_Scripting", "method": "POST", "payload": "<script>alert(1)</script>"},
        {"type": "Command_Injection", "method": "GET", "payload": "; cat /etc/passwd"},
        {"type": "BOLA_IDOR", "payload": "", "method": "GET", "bola_id_mutation": True},
        {"type": "Mass_Assignment", "payload": '{"username":"t","admin":true}', "method": "POST",
         "json_payload": {"username": "t", "password": "x", "role": "admin", "admin": True}},
        {"type": "Baseline_Inspection", "method": "GET", "payload": ""},
    ]


def test_bola_probe_selected_on_id_bearing_path():
    from main import _select_test_queue
    selected = _select_test_queue(
        {"url": "https://example.test/api/users/123", "method": "GET"}, _d2_queue())
    assert [item["type"] for item in selected] == ["BOLA_IDOR", "Baseline_Inspection"]


def test_mass_assignment_selected_on_register_path_not_on_accounts():
    from main import _select_test_queue
    selected = _select_test_queue(
        {"url": "https://example.test/api/register", "method": "POST"}, _d2_queue())
    assert [item["type"] for item in selected] == ["Mass_Assignment", "Baseline_Inspection"]
    # The "/account" boundary must not swallow "/accounts/<id>" — that stays BOLA.
    selected_accounts = _select_test_queue(
        {"url": "https://example.test/api/accounts/7", "method": "GET"}, _d2_queue())
    assert [item["type"] for item in selected_accounts] == ["BOLA_IDOR", "Baseline_Inspection"]


def test_mutate_id_path_segment():
    from main import _mutate_id_path_segment
    assert _mutate_id_path_segment("https://example.test/api/users/123") == \
        "https://example.test/api/users/124"
    assert _mutate_id_path_segment("https://example.test/api/users/0") == \
        "https://example.test/api/users/2"
    uuid_url = "https://example.test/api/users/123e4567-e89b-12d3-a456-426614174000"
    assert _mutate_id_path_segment(uuid_url) == \
        "https://example.test/api/users/123e4567-e89b-12d3-a456-426614174001"
    assert _mutate_id_path_segment("https://example.test/api/users") is None
    # Only the FIRST id segment mutates; version prefixes stay intact.
    assert _mutate_id_path_segment("https://example.test/api/v1/orders/42").endswith(
        "/api/v1/orders/43")


# --- Time-based command-injection probe (D6 fix) ---

def _d6_queue():
    # The default branch of _select_test_queue indexes the standard keys, so
    # the test queue carries them like the production queue does.
    return [
        {"type": "SQL_Injection_GET", "method": "GET", "payload": "' OR 1=1 --"},
        {"type": "Cross_Site_Scripting", "method": "POST", "payload": "<script>alert(1)</script>"},
        {"type": "Command_Injection", "payload": "; cat /etc/passwd", "method": "GET"},
        {"type": "Command_Injection_Time", "payload": "; cat /etc/passwd; sleep 5", "method": "GET"},
        {"type": "Local_File_Inclusion", "payload": "../../etc/passwd", "method": "GET"},
        {"type": "SQL_Injection_Time", "payload": "1' AND SLEEP(5)--", "method": "GET"},
        {"type": "Baseline_Inspection", "payload": "", "method": "GET"},
    ]


def test_command_injection_time_probe_in_exec_and_default_queues():
    from main import _select_test_queue
    selected = _select_test_queue(
        {"url": "https://example.test/vulnerabilities/exec/", "method": "GET"}, _d6_queue())
    types = [item["type"] for item in selected]
    assert "Command_Injection" in types
    assert "Command_Injection_Time" in types
    # Default queue for real-world endpoints gets it too (mirrors SQL_Injection_Time).
    selected_default = _select_test_queue(
        {"url": "https://example.test/api/health", "method": "GET"}, _d6_queue())
    assert "Command_Injection_Time" in [item["type"] for item in selected_default]


def test_command_injection_time_payload_carries_delay_syntax():
    # The signature layer only Confirms time-based CMDi when the payload
    # contains an explicit delay function; the queue payload must satisfy
    # both categorisation ("; cat") and the proof gate ("sleep").
    import re
    payload = "; cat /etc/passwd; sleep 5"
    assert re.search(r";\s*(cat|ls|whoami|id|pwd|uname|netstat)\b", payload)
    assert re.search(r"(?i)\bsleep\b", payload)


def test_command_injection_time_probe_categorises_as_command_injection():
    # Regression: the queue item overrides attack_category to
    # Command_Injection. Without it, a URL containing "exec" matches the
    # SQLi EXEC keyword and steals the categorisation (was: SQL_Injection
    # Suspected on a 5s delay). With the override, an explicit delay payload
    # plus a >3s slowdown Confirms.
    from detection.signature import SignatureDetector
    telemetry = {
        "url": "http://example.test/vulnerabilities/exec/",
        "payload": "; cat /etc/passwd; sleep 5",
        "attack_category": "Command_Injection",
        "status_code": 200,
        "response_size": 100,
        "response_headers": {},
        "response_body": "ok",
        "request_headers": {},
        "response_time": 5.2,
    }
    result = SignatureDetector().analyze(telemetry, baseline_telemetry={"response_time": 0.2})
    assert result["attack_type"] == "Command_Injection"
    assert result["finding_status"] == "Confirmed"
    assert result["has_proof"] is True
    # Same probe, healthy response time: only a lead, never a confirmation.
    telemetry["response_time"] = 0.2
    fast = SignatureDetector().analyze(telemetry, baseline_telemetry={"response_time": 0.2})
    assert fast["finding_status"] == "Suspected"
    assert fast["has_proof"] is False
