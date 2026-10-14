"""Regression tests for the DVWA confirmation misses (2026-10-14).

Root causes fixed:
1. GET-form probes dropped the form's submit button (values were built
   from form_fields only), so Submit-gated apps (DVWA's sqli module)
   never executed the vulnerable code path and error-based SQLi could
   never be Confirmed.
2. The MAX_ENDPOINTS cut took endpoints in raw discovery order, so on
   large sites the highest-value endpoints (POST forms, parameterised
   URLs like open-redirect quote links) were silently dropped.
"""
from main import _bind_payload_to_endpoint, _endpoint_priority


def test_get_form_probe_includes_submit_default():
    ep = {
        "url": "http://example.test/vulnerabilities/sqli/",
        "method": "GET",
        "form_fields": ["id"],
        "form_defaults": {"id": "", "Submit": "Submit"},
        "query_fields": [],
    }
    query_params, form_data = _bind_payload_to_endpoint(ep, "GET", "1'")
    assert form_data is None
    assert query_params["id"] == "1'"
    # The whole point: the submit button a browser would send is present.
    assert query_params["Submit"] == "Submit"


def test_get_form_probe_includes_hidden_defaults():
    ep = {
        "url": "http://example.test/search",
        "method": "GET",
        "form_fields": ["q"],
        "form_defaults": {"q": "", "page": "1", "Submit": "Go"},
        "query_fields": [],
    }
    query_params, _ = _bind_payload_to_endpoint(ep, "GET", "x")
    assert query_params == {"q": "x", "page": "1", "Submit": "Go"}


def test_post_form_probe_still_includes_submit_default():
    ep = {
        "url": "http://example.test/vulnerabilities/exec/",
        "method": "POST",
        "form_fields": ["ip"],
        "form_defaults": {"ip": "", "Submit": "Submit"},
        "query_fields": [],
    }
    query_params, form_data = _bind_payload_to_endpoint(ep, "POST", "127.0.0.1; id")
    assert query_params is None
    assert form_data["ip"] == "127.0.0.1; id"
    assert form_data["Submit"] == "Submit"


def test_endpoint_priority_prefers_forms_and_parameters():
    bare = {"url": "http://example.test/about", "method": "GET"}
    query = {"url": "http://example.test/go?url=x", "method": "GET",
             "query_fields": ["url"]}
    get_form = {"url": "http://example.test/sqli/", "method": "GET",
                "form_fields": ["id"], "form_method": "GET"}
    post_form = {"url": "http://example.test/exec/", "method": "POST",
                 "form_fields": ["ip"], "form_method": "POST"}
    ordered = sorted([bare, query, get_form, post_form],
                     key=_endpoint_priority, reverse=True)
    assert ordered[0] is post_form
    assert ordered[-1] is bare
    # A budget cut to 3 must keep every testable endpoint and drop the
    # bare navigation URL.
    kept = ordered[:3]
    assert bare not in kept
    assert post_form in kept and get_form in kept and query in kept
