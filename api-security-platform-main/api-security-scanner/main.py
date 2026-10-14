import argparse
import json
import re
import sys
import os
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait as _futures_wait
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.logging_config import logger
from core.target_validation import validate_target_url
from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.signature import SignatureDetector
from detection.ml_model import MLAnomalyDetector
from detection.deep_learning import DeepLearningDetector
from detection.risk_scorer import RiskScorer
from database.db import init_db, save_scan_session, save_endpoint, save_finding, complete_scan_session, fail_scan_session, update_scan_progress, get_session, get_session_findings, get_session_for_user, set_session_total_endpoints
from dashboard.results_grouping import summarize_findings
from config.settings import MAX_ENDPOINTS, SCAN_TIMEOUT
from urllib.parse import urlsplit, urlunsplit

ACTIVE_CONCURRENCY = max(1, int(os.getenv("ACTIVE_CONCURRENCY", "4")))
# Total budget for one endpoint's concurrent probe batch. A single probe can
# hang past the per-request timeout (e.g. DNS stalls aren't covered by it);
# without this cap one wedged probe stalls the whole scan forever.
ENDPOINT_DISPATCH_TIMEOUT = max(60, int(os.getenv("ENDPOINT_DISPATCH_TIMEOUT", "300")))


def _dispatch_bounded(dispatch, prepared_requests, max_workers, timeout):
    """Run prepared probe requests concurrently, but never wait longer than
    `timeout` seconds for the batch: probes still hanging after the budget
    are dropped so one wedged request can't stall the whole scan. Returns
    results in the original prepared order. Exceptions raised by finished
    probes propagate, matching the old executor.map behaviour."""
    executor = ThreadPoolExecutor(max_workers=max(1, max_workers))
    try:
        future_to_index = {executor.submit(dispatch, item): i for i, item in enumerate(prepared_requests)}
        done, not_done = _futures_wait(future_to_index.keys(), timeout=timeout)
        if not_done:
            logger.warning(
                "Probe dispatch budget exceeded: %d/%d probes still hanging after %ds; "
                "continuing with the %d that finished",
                len(not_done), len(prepared_requests), timeout, len(done),
            )
            for fut in not_done:
                fut.cancel()
        ordered = sorted(
            ((future_to_index[fut], fut) for fut in done),
            key=lambda pair: pair[0],
        )
        return [fut.result() for _, fut in ordered]
    finally:
        # Don't block on hung probes: release the pool and move on.
        executor.shutdown(wait=False, cancel_futures=True)


def _is_frontend_shell_response(url: str, response_headers: Dict[str, Any], response_body: str, payload: str = "") -> bool:
    normalized_headers = {str(key).lower(): value for key, value in (response_headers or {}).items()}
    content_type = str(normalized_headers.get("content-type", "")).lower()
    if "text/html" not in content_type:
        return False
    body_lower = response_body.lower()
    markers = ("<div id=\"root\"", "<div id=\"app\"", "<div id=\"__next\"")
    if not any(marker in body_lower for marker in markers):
        return False
    # Preserve genuine reflection checks for SPA applications that put the payload in the HTML shell.
    return not payload or payload.lower() not in body_lower


def _is_safe_read_only_endpoint(ep_info: Dict[str, Any]) -> bool:
    method = (ep_info.get("method") or "GET").upper()
    path = urlsplit(ep_info.get("url", "")).path.lower()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return False
    excluded_tokens = ("/login", "/signup", "/register", "/forgot", "/password", "/refresh", "/delete", "/remove", "/create", "/update", "/verify")
    return not any(token in path for token in excluded_tokens)


# Upper bound on how many distinct fields of one endpoint get the payload.
# Previously only fields[0] was ever probed, so 2nd/3rd parameters were never
# tested. Bounded to keep scan time sane; concurrency absorbs the extra probes.
MAX_PROBE_FIELDS = 3


def _probe_targets(ep_info: Dict[str, Any], method: str, has_fixed_json: bool) -> List[str]:
    """Field names to inject the payload into, in priority order, bounded.

    Returns [] when the probe carries its own fixed JSON body (nothing to vary).
    """
    if has_fixed_json:
        return []
    fields = [field for field in (ep_info.get("form_fields") or []) if field]
    query_fields = [field for field in (ep_info.get("query_fields") or []) if field]
    json_fields = [field for field in (ep_info.get("json_fields") or []) if field]
    if method.upper() in ("POST", "PUT", "PATCH") and json_fields:
        return json_fields[:MAX_PROBE_FIELDS]
    if fields:
        return fields[:MAX_PROBE_FIELDS]
    if method.upper() in ("GET", "DELETE") and query_fields:
        return query_fields[:MAX_PROBE_FIELDS]
    return []


def _bind_payload_to_endpoint(ep_info: Dict[str, Any], method: str, payload: str, target_field: str = None):
    """Return named query/form data for endpoints discovered from HTML forms."""
    fields = [field for field in (ep_info.get("form_fields") or []) if field]
    query_fields = [field for field in (ep_info.get("query_fields") or []) if field]
    # JSON targets belong to _bind_json_payload_to_endpoint; don't cross-bind.
    if target_field is not None and target_field not in fields and target_field not in query_fields:
        return None, None
    defaults = dict(ep_info.get("form_defaults") or {})
    target = target_field or (fields[0] if fields else None)
    if fields and method.upper() in ["GET", "DELETE"]:
        # Start from ALL form defaults — including the submit button and
        # hidden fields a browser would send. Many apps (DVWA included) only
        # run the vulnerable code path when the submit field is present, so
        # building values from form_fields alone silently drops it and the
        # probe becomes a no-op the proof gate can never confirm.
        values = {key: value for key, value in defaults.items()}
        for field in fields:
            values.setdefault(field, "")
        values[target] = payload
        return values, None
    if fields and method.upper() in ["POST", "PUT", "PATCH"]:
        values = {key: value for key, value in defaults.items()}
        for field in fields:
            values.setdefault(field, "")
        values[target] = payload
        return None, values
    if query_fields and method.upper() in ["GET", "DELETE"]:
        target = target_field or query_fields[0]
        values = {field: "" for field in query_fields}
        values[target] = payload
        return values, None
    return None, None


def _bind_json_payload_to_endpoint(ep_info: Dict[str, Any], method: str, payload: str, target_field: str = None):
    fields = [field for field in (ep_info.get("json_fields") or []) if field]
    if target_field is not None and target_field not in fields:
        return None
    if fields and method.upper() in {"POST", "PUT", "PATCH"}:
        target = target_field or fields[0]
        values = {field: "" for field in fields}
        values[target] = payload
        return values
    return None


def _is_csrf_candidate(ep_info: Dict[str, Any]) -> bool:
    path = urlsplit(ep_info.get("url", "")).path.lower()
    form_method = (ep_info.get("form_method") or ep_info.get("method") or "GET").upper()
    has_form_fields = bool(ep_info.get("form_fields") or [])
    return "csrf" in path and form_method in {"GET", "POST", "PUT", "PATCH", "DELETE"} and has_form_fields and not (ep_info.get("csrf_token_fields") or [])


_NUMERIC_ID_SEGMENT_RE = re.compile(r"^\d+$")
_UUID_ID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _mutate_id_path_segment(url: str) -> Optional[str]:
    """Return a copy of the URL with the first ID-like path segment swapped
    for a sibling ID (numeric 123 -> 124, UUID -> last nibble flipped).

    This is the generic BOLA probe: fetching a *different* object's URL
    without authentication reveals whether the server checks object
    ownership. Returns None when the path has no numeric/UUID segment, in
    which case the caller must skip the probe rather than fire a duplicate
    of the baseline request.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    segments = parts.path.split("/")
    for i, seg in enumerate(segments):
        if _NUMERIC_ID_SEGMENT_RE.match(seg):
            try:
                n = int(seg)
            except ValueError:
                continue
            segments[i] = str(n + 1 if n else 2)
            return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))
        if _UUID_ID_SEGMENT_RE.match(seg):
            flip = "0" if seg[-1].lower() != "0" else "1"
            segments[i] = seg[:-1] + flip
            return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))
    return None


# Query/form parameter names that conventionally carry a redirect target. The
# open-redirect probe is selected when an endpoint exposes one of these, so
# endpoints like /go?url= are tested instead of only path-keyword matches.
_OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirecturl", "redir", "rurl",
    "next", "return", "return_url", "returnurl", "dest", "destination",
    "target", "continue", "forward", "goto",
}


def _endpoint_priority(ep: Dict[str, Any]) -> int:
    """Rank an endpoint by how much testable surface it exposes.

    Used only when the endpoint budget forces a cut: form endpoints, POST
    forms and parameterised URLs carry the confirmable vulnerabilities, so
    they must survive ahead of bare navigation URLs.
    """
    score = 0
    if ep.get("form_fields"):
        score += 4
        if (ep.get("form_method") or ep.get("method") or "").upper() in (
                "POST", "PUT", "PATCH"):
            score += 2
    if ep.get("query_fields"):
        score += 3
    if ep.get("json_fields"):
        score += 3
    return score


def _select_test_queue(ep_info: Dict[str, Any], active_test_queue: List[Dict[str, Any]]):
    """Select a bounded, non-destructive probe set for an endpoint/module."""
    path = urlsplit(ep_info.get("url", "")).path.lower()
    query_fields = {str(field).lower() for field in (ep_info.get("query_fields") or [])}
    content_types = {str(value).lower() for value in (ep_info.get("request_content_types") or [])}
    by_type = {item["type"]: item for item in active_test_queue}

    if "graphql" in path or "graphiql" in path:
        selected = [by_type["GraphQL_Introspection"]]
    elif "application/xml" in content_types or "text/xml" in content_types or "xml" in path or "xxe" in path:
        selected = [by_type["XXE"]]
    elif _is_csrf_candidate(ep_info):
        selected = [by_type["Baseline_Inspection"]]
    elif "identity/api/auth/login" in path or path.endswith("/auth/login"):
        selected = [by_type["SQL_Injection_Credential"]]
    elif "sqli" in path:
        selected = [by_type["SQL_Injection"], by_type["SQL_Injection_GET"]]
        if "SQL_Injection_Time" in by_type:
            selected.append(by_type["SQL_Injection_Time"])
    elif "xss_r" in path or "xss_d" in path:
        selected = [by_type["Cross_Site_Scripting"]]
    elif "xss_s" in path:
        # Do not create persistent stored-XSS content on a shared public lab.
        selected = []
    elif "open_redirect" in path or "redirect" in path or "redirect" in query_fields or query_fields & _OPEN_REDIRECT_PARAMS:
        selected = [by_type["Open_Redirect"]]
    elif re.search(r"/(register|signup|profile|account)(/|$|\?|#)", path):
        # Boundary-aware: "/account" must not swallow "/accounts/123", which
        # belongs to the BOLA branch below.
        selected = [by_type.get("Mass_Assignment", by_type["Baseline_Inspection"])]
    elif any(token in path for token in ("/users/", "/accounts/", "/profiles/")):
        bola_items = [item for item in active_test_queue if item.get("type") == "BOLA_IDOR"]
        selected = bola_items[:2] if bola_items else [by_type["Baseline_Inspection"]]
    elif "exec" in path:
        selected = [by_type["Command_Injection"]]
        if "Command_Injection_Time" in by_type:
            selected.append(by_type["Command_Injection_Time"])
    elif "/fi/" in path or "file" in path:
        selected = [by_type["Local_File_Inclusion"]]
    elif "brute" in path or "login" in path or "auth" in path:
        selected = [by_type["Broken_Authentication"]]
    else:
        # Default queue for real-world endpoints (no path-keyword hints).
        # Previously only 3 probe types ran here; time-based SQLi and LFI are
        # included so genuine APIs get meaningful coverage, not just demo-app
        # paths. The time-based probe costs nothing on clean targets (only a
        # vulnerable target actually sleeps).
        selected = [by_type["SQL_Injection_GET"], by_type["Cross_Site_Scripting"], by_type["Command_Injection"]]
        if "Local_File_Inclusion" in by_type:
            selected.append(by_type["Local_File_Inclusion"])
        if "SQL_Injection_Time" in by_type:
            selected.append(by_type["SQL_Injection_Time"])
        if "Command_Injection_Time" in by_type:
            selected.append(by_type["Command_Injection_Time"])

    if "Baseline_Inspection" not in {item["type"] for item in selected}:
        selected.append(by_type["Baseline_Inspection"])
    return selected


def _resolve_test_method(ep_info: Dict[str, Any], test_item: Dict[str, Any], default_method: str) -> str:
    if test_item.get("path_suffix"):
        return test_item.get("method", default_method).upper()
    form_method = (ep_info.get("form_method") or "").upper()
    if form_method in {"GET", "POST", "PUT", "PATCH", "DELETE"} and test_item.get("type") != "Baseline_Inspection":
        return form_method
    if not form_method and default_method.upper() in {"GET", "HEAD"} and test_item.get("type") == "Cross_Site_Scripting":
        return default_method.upper()
    return test_item.get("method", default_method).upper()


def _safe_extract_auth_token(login_response: Dict[str, Any]) -> str:
    """Extract auth_token from a login probe response without ever raising.

    A failed/unreachable/non-JSON login probe must degrade to an empty token,
    not kill the whole scan (previously json.loads("") raised JSONDecodeError
    and the pipeline returned None -> HTTP 500 on /api/scan).
    """
    try:
        body = (login_response or {}).get("response_body") or "{}"
        data = json.loads(body)
        if isinstance(data, dict):
            return str(data.get("auth_token", "") or "")
    except (json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
        logger.warning("Could not extract auth token from login probe: %s", exc)
    return ""


def _identity_api_verified(probe_response: Dict[str, Any]) -> bool:
    """Return True only if a /users/v1/register probe behaved like a working identity API.

    Discovery wordlist-guesses /users/v1/* paths, and soft-404 sites answer 200
    to every URL -- so a "discovered" path alone does not prove a real identity
    API exists. Requiring a 2xx JSON response from one real registration attempt
    keeps the BOLA gate honest on arbitrary targets while still arming on real
    VAmPI-style deployments.
    """
    try:
        resp = probe_response or {}
        status = resp.get("status_code")
        if not isinstance(status, int) or not 200 <= status < 300:
            return False
        headers = {str(k).lower(): v for k, v in (resp.get("response_headers") or {}).items()}
        if "json" in str(headers.get("content-type", "")).lower():
            return True
        body = resp.get("response_body") or ""
        try:
            parsed = json.loads(body) if isinstance(body, str) else body
        except (json.JSONDecodeError, TypeError, ValueError):
            return False
        return isinstance(parsed, dict)
    except Exception:
        return False


def _make_discovery_progress_callback(session_id, min_interval: float = 3.0):
    """Build the discovery progress hook for run_pipeline.

    Returns a callback suitable for EndpointDiscovery's progress_callback that
    records crawl progress on the scan session so the results page can show
    live "Discovering pages: N crawled…" progress. DB writes are throttled to
    one per min_interval seconds. When session_id is None (CLI runs, where no
    session exists yet during discovery) the callback is a no-op.
    """
    last_emit = [0.0]

    def _callback(pages_crawled: int, endpoints_found: int) -> None:
        if session_id is None:
            return
        now = time.monotonic()
        if now - last_emit[0] < min_interval:
            return
        last_emit[0] = now
        update_scan_progress(
            session_id,
            done=pages_crawled,
            total=0,
            stage=f"Discovering pages ({endpoints_found} endpoints found)",
        )

    return _callback


def run_pipeline(target_url: str, sarif_output: str = None, return_session_id: bool = False, session_id: int = None,
                 extra_headers: Optional[Dict[str, str]] = None):
    """Run the full scan pipeline.

    session_id: when given (background web scans), reuse the already-created
    scan session instead of creating a new one, and mark it failed if the
    pipeline raises.

    extra_headers: optional auth headers (e.g. Authorization, X-API-Key,
    Cookie) merged into the probe requests' default headers. When None
    (the default) every request is built exactly as before.
    """
    valid, normalized_or_reason = validate_target_url(target_url)
    if not valid:
        raise ValueError(f"Invalid target URL: {normalized_or_reason}")
    target_url = normalized_or_reason

    print("\n" + "="*65)
    print("      API SECURITY & ANOMALY DETECTION PLATFORM")
    print("="*65)
    print(f" Target Base URL : {target_url}\n")

    # Initialize Database
    init_db()

    # 1. Endpoint Discovery
    logger.info("Initializing Endpoint Discovery...")
    discoverer = EndpointDiscovery(
        base_url=target_url,
        timeout=SCAN_TIMEOUT,
        progress_callback=_make_discovery_progress_callback(session_id),
    )
    discovered_endpoints = discoverer.discover()

    if os.getenv("READ_ONLY_SAFE", "0").lower() in {"1", "true", "yes", "on"}:
        before = len(discovered_endpoints)
        discovered_endpoints = [ep for ep in discovered_endpoints if _is_safe_read_only_endpoint(ep)]
        logger.info("Read-only safe mode retained %d of %d discovered endpoints", len(discovered_endpoints), before)

    # Gate for the VAmPI-style identity/BOLA proof probes further below: they
    # are written for /users/v1/* APIs, so only arm them when discovery
    # actually surfaced those paths. Computed pre-budget so the endpoint
    # cap cannot hide them.
    vampi_identity_found = any(
        "/users/v1/" in urllib.parse.urlparse((ep or {}).get("url", "")).path
        for ep in (discovered_endpoints or [])
    )
    if not vampi_identity_found:
        logger.info("Skipping VAmPI identity/BOLA probes: no /users/v1/* paths discovered")

    # Apply the configured safety/performance budget. MAX_ENDPOINTS was
    # previously defined but never enforced, allowing a crawl to expand into
    # hundreds of sequential active requests. When a cut is forced, keep the
    # endpoints with the most testable surface first (forms, POST forms,
    # parameterised URLs): a plain first-N cut in discovery order silently
    # drops exactly those on large sites — on DVWA it dropped the
    # open-redirect quote links and crowded out the POST command form,
    # leaving real vulnerabilities at Suspected.
    if len(discovered_endpoints) > MAX_ENDPOINTS:
        logger.info("Limiting discovered endpoints from %d to %d", len(discovered_endpoints), MAX_ENDPOINTS)
        discovered_endpoints = sorted(
            discovered_endpoints, key=_endpoint_priority, reverse=True
        )[:MAX_ENDPOINTS]

    if not discovered_endpoints:
        print("[!] No endpoints discovered. Performing target base URL analysis.")
        discovered_endpoints = [{"url": target_url, "method": "GET"}]

    # 2. Instantiate Engines & Detectors
    if extra_headers:
        # Optional auth headers for protected APIs: merged over (never
        # replacing) the default probe headers. No headers -> old behavior.
        _probe_headers = {
            "User-Agent": "APISecurityPlatform/1.0",
            "Accept": "application/json, text/html, */*",
        }
        _probe_headers.update(extra_headers)
        request_engine = RequestEngine(headers=_probe_headers)
    else:
        request_engine = RequestEngine()
    response_parser = ResponseParser()
    signature_detector = SignatureDetector()
    ml_detector = MLAnomalyDetector()
    dl_detector = DeepLearningDetector()
    risk_scorer = RiskScorer()

    # Save Session (or reuse the pre-created one for background web scans)
    if session_id is not None:
        # Internal fetch: the worker is trusted server-side code, not a web
        # visitor, so it bypasses the per-user ownership check.
        session_obj = get_session(session_id)
        if session_obj is None:
            raise ValueError(f"Scan session {session_id} not found")
        set_session_total_endpoints(session_id, len(discovered_endpoints))
        session_obj.total_endpoints_found = len(discovered_endpoints)
    else:
        session_obj = save_scan_session(target_url=target_url, total_endpoints=len(discovered_endpoints))
    # Progress baseline for the live "time left" banner (reset even on reuse).
    update_scan_progress(
        session_obj.id,
        done=0,
        total=len(discovered_endpoints),
        stage="Discovering endpoints" if not discovered_endpoints else "Testing endpoints",
    )

    try:
        # --- Identity/BOLA proof probes (VAmPI-style /users/v1/* only) ---
        if vampi_identity_found:
            # The /users/v1/* paths may come from discovery's own wordlist
            # guesses: soft-404 sites answer 200 to everything, which would
            # wrongly arm the gate. Verify with one real registration attempt
            # using a dedicated gatecheck identity -- only a 2xx JSON response
            # proves a working identity API worth probing.
            _gatecheck_resp = request_engine.send_request(
                "POST",
                target_url.rstrip("/") + "/users/v1/register",
                json_payload={
                    "username": "gatecheck_qa",
                    "password": "GateCheckPass123!",
                    "email": "gatecheck_qa@test.local",
                },
                custom_headers={"Content-Type": "application/json"},
            )
            vampi_identity_found = _identity_api_verified(_gatecheck_resp)
            if not vampi_identity_found:
                logger.info(
                    "Skipping VAmPI identity/BOLA probes: /users/v1/register did not behave like a working identity API (status=%s)",
                    (_gatecheck_resp or {}).get("status_code"),
                )

        if vampi_identity_found:
            # --- BOLA setup: create two real, distinct identities to test cross-object access ---
            attacker_creds = {"username": "attacker_qa", "password": "AttackerPass123!", "email": "attacker_qa@test.local"}
            victim_creds = {"username": "victim_qa", "password": "VictimPass123!", "email": "victim_qa@test.local"}

            for creds in (attacker_creds, victim_creds):
                request_engine.send_request(
                    "POST",
                    target_url.rstrip("/") + "/users/v1/register",
                    json_payload={"username": creds["username"], "password": creds["password"], "email": creds["email"]},
                    custom_headers={"Content-Type": "application/json"}
                )

            mass_assign_creds = {
                "username": "mass_assign_qc",
                "password": "MassAssignPass123!",
                "email": "mass_assign_qc@test.local",
                "admin": True,
            }
            canary_creds = {
                "username": "canary_delete_qc",
                "password": "CanaryPass123!",
                "email": "canary_delete_qc@test.local",
            }
            request_engine.send_request(
                "POST",
                target_url.rstrip("/") + "/users/v1/register",
                json_payload=mass_assign_creds,
                custom_headers={"Content-Type": "application/json"}
            )
            request_engine.send_request(
                "POST",
                target_url.rstrip("/") + "/users/v1/register",
                json_payload=canary_creds,
                custom_headers={"Content-Type": "application/json"}
            )
            def run_direct_probe(test_type, method, path_suffix, headers, json_payload, marker_key, verify_fn=None):
                url = target_url.rstrip("/") + path_suffix
                req_data = request_engine.send_request(
                    method,
                    url,
                    json_payload=json_payload,
                    custom_headers=headers
                )
                req_data["attack_category"] = test_type
                req_data[marker_key] = True
                # Canary verification: a 2xx on the attack request is not proof.
                # The verify_fn performs a follow-up check (e.g. logging in as
                # the victim with the changed password); only a passing canary
                # lets the signature layer report Confirmed.
                if verify_fn is not None:
                    try:
                        verified = bool(verify_fn())
                    except Exception as exc:
                        logger.warning("Canary verification for %s failed: %s", test_type, exc)
                        verified = False
                    if marker_key == "cross_identity_probe":
                        req_data["canary_verified"] = verified
                    elif marker_key == "mass_assignment_probe":
                        req_data["privilege_verified"] = verified
                    logger.info("Canary verification for %s: %s", test_type, "PASSED" if verified else "FAILED")
                req_data["payload_had_effect"] = True
                payload_str = json.dumps(json_payload) if json_payload else ""
                features = response_parser.extract_features(req_data)
                sig_res = signature_detector.analyze(req_data, baseline_telemetry={})
                ml_res = ml_detector.predict(features)
                dl_res = dl_detector.analyze(req_data.get("response_body", ""), features)
                risk_summary = risk_scorer.calculate_risk(
                    signature_result=sig_res,
                    ml_result=ml_res,
                    dl_result=dl_res,
                    endpoint_url=url,
                    http_method=method,
                    payload_had_effect=True,
                    telemetry_data=req_data
                )
                score = risk_summary["total_score"]

                ep_obj = save_endpoint(session_id=session_obj.id, url=url, method=method)
                if score > 0 or sig_res.get("matched"):
                    save_finding(
                        session_id=session_obj.id,
                        endpoint_id=ep_obj.id,
                        attack_type=sig_res.get("attack_type", "None"),
                        severity=risk_summary["severity"],
                        risk_score=score,
                        finding_status=risk_summary.get("finding_status", "Informational"),
                        signature_triggered=sig_res.get("proof_of_concept") or sig_res.get("pattern_matched", ""),
                        ml_score=ml_res.get("points", 0.0),
                        lstm_score=dl_res.get("lstm_points", 0.0),
                        autoencoder_score=dl_res.get("autoencoder_points", 0.0),
                        recommendation=risk_summary.get("recommendation", ""),
                        request_payload=json.dumps(json_payload) if json_payload is not None else "",
                        response_status=req_data.get("status_code", 200),
                        response_size=req_data.get("response_size", 0),
                        response_time=req_data.get("response_time", 0.0)
                    )
                print(f"  [{test_type}] -> Layer 1: {sig_res['points']} pts | ML: {ml_res['points']} pts | DL: {dl_res['total_layer3_points']} pts | SCORE: {score} [{risk_summary['severity']}]")
                return sig_res

            # --- Direct, one-shot proof probes: refresh tokens immediately before use. ---
            attacker_login = request_engine.send_request(
                "POST",
                target_url.rstrip("/") + "/users/v1/login",
                json_payload={"username": attacker_creds["username"], "password": attacker_creds["password"]},
                custom_headers={"Content-Type": "application/json"}
            )
            attacker_token = _safe_extract_auth_token(attacker_login)
            if attacker_token:
                def _verify_bola_canary():
                    # The attack changed the victim's password to
                    # "hijacked_by_attacker_qa". If we can now log in AS the
                    # victim with that password, the mutation really happened.
                    victim_login = request_engine.send_request(
                        "POST",
                        target_url.rstrip("/") + "/users/v1/login",
                        json_payload={"username": victim_creds["username"], "password": "hijacked_by_attacker_qa"},
                        custom_headers={"Content-Type": "application/json"}
                    )
                    return _safe_extract_auth_token(victim_login) != ""
                run_direct_probe(
                    "BOLA_IDOR",
                    "PUT",
                    f"/users/v1/{victim_creds['username']}/password",
                    {"Authorization": f"Bearer {attacker_token}", "Content-Type": "application/json"},
                    {"password": "hijacked_by_attacker_qa"},
                    "cross_identity_probe",
                    verify_fn=_verify_bola_canary
                )
            else:
                logger.info("Skipping BOLA_IDOR probe: attacker login yielded no auth token")

            mass_login = request_engine.send_request(
                "POST",
                target_url.rstrip("/") + "/users/v1/login",
                json_payload={"username": mass_assign_creds["username"], "password": mass_assign_creds["password"]},
                custom_headers={"Content-Type": "application/json"}
            )
            mass_assign_token = _safe_extract_auth_token(mass_login)
            if mass_assign_token:
                def _verify_mass_assignment_canary():
                    # The account was registered with "admin": true. Read the
                    # stored account back: if the server persisted the elevated
                    # flag, privilege escalation is proven.
                    profile = request_engine.send_request(
                        "GET",
                        target_url.rstrip("/") + f"/users/v1/{mass_assign_creds['username']}",
                        custom_headers={"Authorization": f"Bearer {mass_assign_token}", "Content-Type": "application/json"}
                    )
                    body = (profile or {}).get("response_body") or ""
                    return bool(re.search(r'(?i)"admin"\s*:\s*true', body))
                run_direct_probe(
                    "Mass_Assignment",
                    "DELETE",
                    f"/users/v1/{canary_creds['username']}",
                    {"Authorization": f"Bearer {mass_assign_token}"},
                    None,
                    "mass_assignment_probe",
                    verify_fn=_verify_mass_assignment_canary
                )
            else:
                logger.info("Skipping Mass_Assignment probe: login yielded no auth token")

        active_test_queue = [
            {"type": "GraphQL_Introspection", "payload": "{ __schema { queryType { fields { name } } } }", "method": "POST", "json_payload": {"query": "{ __schema { queryType { fields { name } } } }",}, "headers": {"Content-Type": "application/json"}},
            {"type": "XXE", "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "method": "POST", "headers": {"Content-Type": "application/xml"}},
            {"type": "SQL_Injection_Credential", "payload": "x' OR '1'='1", "method": "POST", "json_payload": {"email": "nobody-test@example.com", "password": "x' OR '1'='1"}, "headers": {"Content-Type": "application/json"}},
            {"type": "SQL_Injection", "payload": "{\"username\": \"admin' OR 1=1 --\", \"password\": \"pass\"}", "method": "POST", "headers": {"Content-Type": "application/json"}},
            {"type": "SQL_Injection_GET", "payload": "' OR 1=1 --", "method": "GET"},
            {"type": "SQL_Injection_Time", "payload": "1' AND SLEEP(5)--", "method": "GET"},
            {"type": "Cross_Site_Scripting", "payload": "<script>alert('xss')</script>", "method": "POST"},
            {"type": "Command_Injection", "payload": "; cat /etc/passwd", "method": "GET"},
            # Time-based CMDi mirror of SQL_Injection_Time (D6 fix): the payload
            # carries BOTH a command the signature layer recognises ("; cat")
            # for categorisation AND an explicit delay function ("sleep") that
            # the time-based proof branch requires before Confirming.
            # attack_category overrides the queue type for the signature
            # layer: "Command_Injection_Time" is not a signature category, and
            # without the override a URL containing "exec" would match the
            # SQLi EXEC keyword and steal the categorisation.
            {"type": "Command_Injection_Time", "attack_category": "Command_Injection", "payload": "; cat /etc/passwd; sleep 5", "method": "GET"},
            {"type": "Local_File_Inclusion", "payload": "../../../../../../etc/passwd", "method": "GET"},
            {"type": "Open_Redirect", "payload": "https://example.com/api-security-redirect-check", "method": "GET", "follow_redirects": False},
            # Generic BOLA probe (D2 fix): the URL's numeric/UUID ID segment is
            # swapped for a sibling ID at dispatch time (bola_id_mutation).
            # No canary flags are set — without cross-identity verification
            # this grades Suspected at most; Confirmed stays canary-only.
            {"type": "BOLA_IDOR", "payload": "", "method": "GET", "bola_id_mutation": True},
            # Generic mass-assignment probe (D2 fix): fixed JSON body carrying
            # extra privilege fields. The "payload" string mirrors the body so
            # the signature layer can categorise the probe; the json_payload
            # dict is what actually goes on the wire. Suspected-grade only —
            # no privilege_verified flag is ever set on the queue path.
            {"type": "Mass_Assignment", "payload": "{\"username\": \"probe-test\", \"password\": \"TestPass123!\", \"role\": \"admin\", \"admin\": true}", "method": "POST", "json_payload": {"username": "probe-test", "password": "TestPass123!", "role": "admin", "admin": True}, "headers": {"Content-Type": "application/json"}},
            {"type": "Broken_Authentication", "payload": "", "method": "GET", "headers": {"Authorization": "Bearer null"}},
            {"type": "Baseline_Inspection", "payload": "", "method": "GET"}
        ]

        for idx, ep_info in enumerate(discovered_endpoints, start=1):
            base_ep_url = ep_info["url"]
            default_method = ep_info["method"]

            print(f"\n[{idx}/{len(discovered_endpoints)}] Testing Endpoint: [{default_method}] {base_ep_url}")

            # Baseline request. Time-based proofs (SLEEP payloads) compare the
            # probe's response time against this baseline, so a single slow
            # baseline sample can fabricate a "Confirmed" via normal jitter.
            # When a time-based probe is queued, take a second baseline and
            # use the faster of the two: a real delay must beat BOTH samples.
            baseline_req = request_engine.send_request(default_method, base_ep_url)
            _prelim_queue = _select_test_queue(ep_info, active_test_queue)
            # Any time-based probe (SQL_Injection_Time, Command_Injection_Time,
            # ...) needs the double-baseline jitter guard.
            needs_time_baseline = any(
                str(item.get("type", "")).endswith("_Time") for item in _prelim_queue
            )
            if needs_time_baseline:
                second_baseline = request_engine.send_request(default_method, base_ep_url)
                try:
                    if float(second_baseline.get("response_time", 0.0)) < float(baseline_req.get("response_time", 0.0)):
                        baseline_req = second_baseline
                except (TypeError, ValueError):
                    pass
            baseline_telemetry = {
                "status_code": baseline_req.get("status_code", 200),
                "response_size": baseline_req.get("response_size", 0),
                "response_time": baseline_req.get("response_time", 0.0),
                # The signature layer diffs response bodies against this; without
                # it every non-empty response looked "100% different" and produced
                # bogus differential-response findings on clean endpoints.
                "response_body": baseline_req.get("response_body", ""),
            }

            # Baseline feature vector for Layer 3: the autoencoder scores each
            # probe's EXCESS reconstruction error over the target's own normal
            # response, so an app unlike the training services doesn't read as
            # anomalous merely for existing (see DeepLearningDetector.analyze).
            baseline_features = response_parser.extract_features(
                {
                    "status_code": baseline_telemetry["status_code"],
                    "response_size": baseline_telemetry["response_size"],
                    "response_time": baseline_telemetry["response_time"],
                    "response_body": baseline_telemetry["response_body"],
                    "headers": baseline_req.get("response_headers", {}),
                    "method": default_method,
                    "payload": "",
                    "url": base_ep_url,
                },
                baseline_telemetry=baseline_telemetry,
            )

            baseline_is_frontend_shell = _is_frontend_shell_response(
                base_ep_url,
                baseline_req.get("response_headers", {}),
                baseline_req.get("response_body", "")
            )

            if _is_csrf_candidate(ep_info):
                csrf_ep = save_endpoint(session_id=session_obj.id, url=base_ep_url, method=default_method)
                save_finding(
                    session_id=session_obj.id,
                    endpoint_id=csrf_ep.id,
                    attack_type="CSRF",
                    severity="Low",
                    risk_score=0.0,
                    finding_status="Informational",
                    signature_triggered="POST form has no detected anti-CSRF token; exploitability not verified",
                    recommendation="Verify Origin/Referer validation and use a framework CSRF token for state-changing forms.",
                    request_payload="",
                    response_status=baseline_req.get("status_code", 200),
                    response_size=baseline_req.get("response_size", 0),
                    response_time=baseline_req.get("response_time", 0.0)
                )
                logger.info("Recorded passive CSRF candidate without submitting state-changing form: %s", base_ep_url)
            if baseline_is_frontend_shell:
                endpoint_queue = [item for item in active_test_queue if item.get("type") == "Baseline_Inspection"]
                logger.info("Skipping active payloads for frontend shell endpoint: %s", base_ep_url)
            else:
                endpoint_queue = _select_test_queue(ep_info, active_test_queue)
            prepared_requests = []
            for test_item in endpoint_queue:
                path_suffix = test_item.get("path_suffix", "")
                if path_suffix:
                    parsed_base = urlsplit(base_ep_url)
                    origin = urlunsplit((parsed_base.scheme, parsed_base.netloc, "", "", ""))
                    test_url = origin.rstrip("/") + path_suffix
                else:
                    test_url = base_ep_url

                test_method = _resolve_test_method(ep_info, test_item, default_method)
                # Generic BOLA probe (D2 fix): swap the URL's ID segment for a
                # sibling object's URL and fetch it unauthenticated. No canary
                # flags are set on this path — without cross-identity
                # verification the signature layer grades this Suspected at
                # most; Confirmed stays canary-only.
                if test_item.get("type") == "BOLA_IDOR" and test_item.get("bola_id_mutation"):
                    mutated_url = _mutate_id_path_segment(test_url)
                    if mutated_url is None:
                        logger.info("Skipping BOLA_IDOR probe: no ID segment in %s", test_url)
                        continue
                    prepared_requests.append(
                        (test_item, mutated_url, test_method, "", None, None, None, None)
                    )
                    continue
                payload_str = test_item.get("payload", "")
                custom_headers = test_item.get("headers", None)
                fixed_json = test_item.get("json_payload")
                # Probe every injectable field (bounded), not just the first:
                # vulnerabilities often hide in the 2nd or 3rd parameter.
                targets = _probe_targets(ep_info, test_method, fixed_json is not None) or [None]
                for target_field in targets:
                    query_params, form_data = _bind_payload_to_endpoint(ep_info, test_method, payload_str, target_field)
                    if fixed_json is not None:
                        json_payload = fixed_json
                    else:
                        json_payload = _bind_json_payload_to_endpoint(ep_info, test_method, payload_str, target_field)
                    headers = dict(custom_headers) if custom_headers else None
                    if json_payload is not None and headers is None:
                        headers = {"Content-Type": "application/json"}
                    prepared_requests.append((test_item, test_url, test_method, payload_str, headers, query_params, form_data, json_payload))

            def dispatch(prepared):
                test_item, test_url, test_method, payload_str, custom_headers, query_params, form_data, json_payload = prepared
                req_data = request_engine.send_request(
                    test_method,
                    test_url,
                    payload=payload_str,
                    custom_headers=custom_headers,
                    json_payload=json_payload,
                    query_params=query_params,
                    form_data=form_data,
                    follow_redirects=test_item.get("follow_redirects", True)
                )
                return test_item, test_url, test_method, payload_str, req_data

            # Requests are bounded and concurrent, but all detection and SQLite writes
            # remain sequential below so proof evaluation and persistence are deterministic.
            # The dispatch budget caps the whole batch: one hung probe is dropped
            # instead of wedging the scan on this endpoint forever.
            dispatched_requests = _dispatch_bounded(
                dispatch,
                prepared_requests,
                max_workers=min(ACTIVE_CONCURRENCY, max(1, len(prepared_requests))),
                timeout=ENDPOINT_DISPATCH_TIMEOUT,
            )

            for test_item, test_url, test_method, payload_str, req_data in dispatched_requests:
                current_size = req_data.get("response_size", 0)
                current_status = req_data.get("status_code", 200)
                response_body = req_data.get("response_body", "")
                req_data["frontend_shell_response"] = _is_frontend_shell_response(test_url, req_data.get("response_headers", {}), response_body, payload_str) and bool(payload_str)

                error_indicators = [
                    "error", "sql", "syntax", "warning",
                    "exception", "invalid", "undefined",
                    "mysql", "ora-", "pg::", "sqlite", "traceback"
                ]
                has_error = any(ind in response_body.lower() for ind in error_indicators)

                if (response_body == baseline_telemetry.get("response_body", "")
                    and current_status == baseline_telemetry.get("status_code", 200)
                    and current_size > 0
                    and not has_error
                    and test_item["type"] not in ["Baseline_Inspection"]):
                    req_data["payload_had_effect"] = False
                else:
                    req_data["payload_had_effect"] = True

                if test_item["type"] == "Baseline_Inspection":
                    req_data["payload_had_effect"] = True

                # The queue "type" drives selection and baseline logic; the
                # signature layer sees attack_category, which a queue item may
                # override (e.g. Command_Injection_Time -> Command_Injection).
                req_data["attack_category"] = test_item.get("attack_category") or test_item.get("type")
                req_data["cross_identity_probe"] = test_item.get("cross_identity_probe", False)
                req_data["mass_assignment_probe"] = test_item.get("mass_assignment_probe", False)
                # Pass the baseline so the ML layer can use response-differential
                # features (how the probe's response deviates from baseline),
                # not just absolute response features.
                features = response_parser.extract_features(req_data, baseline_telemetry=baseline_telemetry)

                # Layer 1 - Signature Detection & Proof Verification
                sig_res = signature_detector.analyze(req_data, baseline_telemetry=baseline_telemetry)

                # Layer 2 - ML Anomaly Detection (Isolation Forest)
                ml_res = ml_detector.predict(features)

                # Layer 3 - Deep Learning (PyTorch LSTM + Autoencoder)
                dl_res = dl_detector.analyze(response_body, features, baseline_feature_dict=baseline_features)

                # Risk Scoring Calculation
                risk_summary = risk_scorer.calculate_risk(
                    signature_result=sig_res,
                    ml_result=ml_res,
                    dl_result=dl_res,
                    endpoint_url=test_url,
                    http_method=test_method,
                    payload_had_effect=req_data.get("payload_had_effect", True),
                    telemetry_data=req_data
                )

                score = risk_summary["total_score"]
                severity = risk_summary["severity"]

                # Print Console Breakdown
                print(f"  [{test_item['type']}] -> Layer 1: {sig_res['points']} pts | ML: {ml_res['points']} pts | DL: {dl_res['total_layer3_points']} pts | SCORE: {score} [{severity}]")

                # Persist Result to SQLite Database
                ep_obj = save_endpoint(session_id=session_obj.id, url=test_url, method=test_method)

                confirmed = bool(risk_summary.get("is_vulnerable") or sig_res.get("is_vulnerable"))
                attack_name = sig_res.get("attack_type", "None") if (confirmed or sig_res.get("matched") or sig_res.get("finding_status") == "Informational") else "None"

                # Persist non-zero triage signals for auditability, but only
                # confirmed proof contributes to the vulnerability total.
                if score > 0 or sig_res.get("matched"):
                    save_finding(
                        session_id=session_obj.id,
                        endpoint_id=ep_obj.id,
                        attack_type=attack_name,
                        severity=severity,
                        risk_score=score,
                        finding_status=risk_summary.get("finding_status", "Informational"),
                        signature_triggered=sig_res.get("proof_of_concept") or sig_res.get("pattern_matched", ""),
                        ml_score=ml_res.get("points", 0.0),
                        lstm_score=dl_res.get("lstm_points", 0.0),
                        autoencoder_score=dl_res.get("autoencoder_points", 0.0),
                        recommendation=risk_summary.get("recommendation", ""),
                        request_payload=payload_str,
                        response_status=req_data.get("status_code", 200),
                        response_size=req_data.get("response_size", 0),
                        response_time=req_data.get("response_time", 0.0)
                    )

            # Bump the live progress counter so the results page can show
            # "endpoint X of Y — about Z left".
            update_scan_progress(session_obj.id, done=idx)

        # Final risk roll-up ------------------------------------------------
        # The single scoring rule (dashboard/results_grouping.py): the stored
        # session numbers are computed from the saved findings exactly like
        # the results page, history and dashboard compute them at render time.
        update_scan_progress(session_obj.id, stage="Finalizing results")
        _saved = get_session_findings(session_obj.id)
        _dicts = [{
            "url": f.endpoint.url if f.endpoint else target_url,
            "method": f.endpoint.method if f.endpoint else "GET",
            "attack_type": f.attack_type,
            "severity": f.severity,
            "finding_status": f.finding_status,
            "risk_score": f.risk_score,
        } for f in _saved]
        summary = summarize_findings(_dicts)
        complete_scan_session(
            session_id=session_obj.id,
            overall_risk_score=summary["risk_score"],
            overall_severity=summary["severity"],
            total_vulnerabilities=summary["vulnerabilities"]
        )

        if sarif_output:
            from reports.sarif_exporter import SARIFReportExporter
            persisted_session = get_session(session_obj.id)
            persisted_findings = get_session_findings(session_obj.id)
            session_data = {
                "id": persisted_session.id,
                "target_url": persisted_session.target_url,
                "overall_risk_score": persisted_session.overall_risk_score,
                "overall_severity": persisted_session.overall_severity,
                "total_endpoints_found": persisted_session.total_endpoints_found,
                "total_vulnerabilities_found": persisted_session.total_vulnerabilities_found,
            }
            findings_data = [
                {
                    "url": finding.endpoint.url if finding.endpoint else persisted_session.target_url,
                    "method": finding.endpoint.method if finding.endpoint else "GET",
                    "attack_type": finding.attack_type,
                    "finding_status": finding.finding_status,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "signature_triggered": finding.signature_triggered,
                    "recommendation": finding.recommendation,
                    "request_payload": finding.request_payload,
                    "response_status": finding.response_status,
                    "response_size": finding.response_size,
                    "response_time": finding.response_time,
                }
                for finding in persisted_findings
            ]
            SARIFReportExporter().export(session_data, findings_data, output_path=sarif_output)

        print("\n" + "="*65)
        print(" SCAN PIPELINE COMPLETED SUCCESSFULLY")
        print(" All inspection records persisted to database.")
        print(" Launch web dashboard via `python main.py --dashboard` to view reports.")
        print("="*65 + "\n")
        return session_obj.id if return_session_id else summary["vulnerabilities"]

    except Exception as exc:
        logger.error(f"Error during scan pipeline execution: {exc}")
        if session_id is not None:
            try:
                fail_scan_session(session_id, str(exc))
            except Exception as mark_exc:
                logger.error(f"Could not mark scan session {session_id} as failed: {mark_exc}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered API Security & Anomaly Detection Platform"
    )
    parser.add_argument(
        "--url",
        type=str,
        help="Target API base URL to inspect"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch Flask web dashboard"
    )
    parser.add_argument(
        "--sarif-output",
        type=str,
        help="Write a SARIF 2.1.0 report to this path after scanning"
    )
    args = parser.parse_args()

    if args.dashboard:
        logger.info("Launching Web Dashboard...")
        from dashboard.app import create_app
        from config.settings import FLASK_PORT, FLASK_DEBUG
        app = create_app()
        app.run(host="0.0.0.0", port=FLASK_PORT, debug=FLASK_DEBUG, use_reloader=False)

    elif args.url:
        confirmed_count = run_pipeline(args.url, sarif_output=args.sarif_output)
        if isinstance(confirmed_count, int) and confirmed_count > 0:
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
