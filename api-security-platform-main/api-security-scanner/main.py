import argparse
import json
import re
import sys
import os
import threading
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
from database.models import parse_skipped_endpoints
from dashboard.results_grouping import summarize_findings
from ml_pipeline.telemetry_schema import build_telemetry_record
from config.settings import MAX_ENDPOINTS, SCAN_TIMEOUT
from core.concurrency import (
    BoundedSlot, SlotTimeout, run_bounded_pool, get_stop_event, release_stop_event,
)
from urllib.parse import urlsplit, urlunsplit

ACTIVE_CONCURRENCY = max(1, int(os.getenv("ACTIVE_CONCURRENCY", "8")))
# Endpoints used to be scanned strictly one at a time, so wall-clock time
# was the sum of every endpoint's slowest probe batch. Endpoints are
# independent (own baselines, probes, findings), so up to
# ENDPOINT_CONCURRENCY of them run at once. Total in-flight HTTP requests
# stay capped by MAX_IN_FLIGHT_REQUESTS so the scan never floods the target
# or the free-tier container, however many probe threads are parked.
ENDPOINT_CONCURRENCY = max(1, int(os.getenv("ENDPOINT_CONCURRENCY", "4")))
MAX_IN_FLIGHT_REQUESTS = max(1, int(os.getenv("MAX_IN_FLIGHT_REQUESTS", "8")))
_IN_FLIGHT_SEMAPHORE = threading.BoundedSemaphore(MAX_IN_FLIGHT_REQUESTS)
# Serializes DB writes across endpoint workers: SQLite serializes writers
# internally and a contended commit can raise "database is locked"; the lock
# makes parallel writes safe on every backend (Firestore is natively safe,
# the lock just costs nothing there).
_DB_WRITE_LOCK = threading.Lock()
# Total budget for one endpoint's concurrent probe batch. A single probe can
# hang past the per-request timeout (e.g. DNS stalls aren't covered by it);
# without this cap one wedged probe stalls the whole scan forever.
# Default 120s from evidence, not a guess: the slowest legitimate endpoint
# in the Nov 25 replica log took 12.5s end-to-end (a time-based SQLi endpoint
# with real SLEEP probes + re-probes); live DVWA endpoints averaged ~59s of
# worker time (Nov 27 runs). The only endpoint ever needing more was a
# wedged one that ate the full old budget twice.
ENDPOINT_DISPATCH_TIMEOUT = max(60, int(os.getenv("ENDPOINT_DISPATCH_TIMEOUT", "120")))
# Max seconds a probe waits for a free in-flight slot. Without a bound, hung
# probes that keep their permit (DNS stall, etc.) starve every other worker
# forever. On timeout the probe is skipped with a logged reason.
SLOT_ACQUIRE_TIMEOUT = max(5, int(os.getenv("SLOT_ACQUIRE_TIMEOUT", "60")))
# Hard wall-clock budget for ONE endpoint (baselines + probe batch +
# detection). An endpoint over budget is abandoned and reported, so it can
# never block the final roll-up. Must exceed ENDPOINT_DISPATCH_TIMEOUT.
# Default 180s = dispatch budget + 60s margin; saves ~7 min per wedged
# endpoint vs the old 600s while keeping a 3x margin over the slowest
# legitimate live endpoint observed.
ENDPOINT_WALL_BUDGET = max(
    ENDPOINT_DISPATCH_TIMEOUT + 60,
    int(os.getenv("ENDPOINT_WALL_BUDGET", "180")),
)


def _in_flight():
    """Acquire a global in-flight request slot, or raise SlotTimeout."""
    return BoundedSlot(_IN_FLIGHT_SEMAPHORE, SLOT_ACQUIRE_TIMEOUT)


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


def _append_payload_to_path_segment(url: str, payload: str) -> Optional[str]:
    """Return a copy of the URL with the payload appended to the last path segment.

    Generic path-parameter probing: REST routes like /users/{id} carry user
    input in the path, not in a query/form field, so a payload bound to a
    query parameter never reaches the sink. Appending the payload to the
    last segment (e.g. /users/v1/name1 -> /users/v1/name1') tests the sink
    directly. Returns None when there is no value-like last segment
    (trailing slash, empty path, or a filename-like segment).
    """
    if not payload:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.path.endswith("/"):
        # Trailing slash: the last segment is a collection/resource, not
        # a value — appending to it would probe the wrong thing.
        return None
    segments = [seg for seg in parts.path.split("/") if seg]
    if not segments:
        return None
    last = segments[-1]
    if "." in last and not last.startswith("."):
        # Looks like a filename (api.json, index.html) — not a path param.
        return None
    segments[-1] = last + payload
    return urlunsplit((parts.scheme, parts.netloc, "/" + "/".join(segments),
                       parts.query, parts.fragment))


# Injection probe types that also get a path-segment variant when the
# endpoint has no query/form/json field to bind to (see _scan_one_endpoint).
_PATH_INJECTION_TYPES = {
    "SQL_Injection_GET", "SQL_Injection_Error",
    "Cross_Site_Scripting", "Command_Injection",
}


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


# Last path segments that mark a database seed/setup endpoint. These rewrite
# shared state on every call, so they get baseline-only treatment (see
# _select_test_queue): active probes would race the seed and the resulting
# database errors would masquerade as injection evidence.
# LIMITATION (not a complete fix): a skip list also hides any real
# vulnerability on an endpoint with such a name. The principled protection
# is the SQL-error verification (verify_sql_error_proof: sequential repeat
# + balanced-quote control), which rules out transient errors wherever
# they occur; the skip list stays as a safety rule for state-changing
# endpoints, not as the proof.
_SEED_ENDPOINT_SEGMENTS = {
    "createdb", "seed", "seed-db", "reset-db", "init-db",
    "populate", "migrate", "truncate",
}


def _select_test_queue(ep_info: Dict[str, Any], active_test_queue: List[Dict[str, Any]]):
    """Select a bounded, non-destructive probe set for an endpoint/module."""
    path = urlsplit(ep_info.get("url", "")).path.lower()
    query_fields = {str(field).lower() for field in (ep_info.get("query_fields") or [])}
    content_types = {str(value).lower() for value in (ep_info.get("request_content_types") or [])}
    by_type = {item["type"]: item for item in active_test_queue}

    if "graphql" in path or "graphiql" in path:
        selected = [by_type["GraphQL_Introspection"]]
    elif path.rsplit("/", 1)[-1] in _SEED_ENDPOINT_SEGMENTS:
        # Baseline only. A seed/setup endpoint (createdb, seed, migrate,
        # ...) REWRITES the database on every call: active probes hit it
        # concurrently, race the seed, and the resulting error (a database
        # lock or duplicate-key traceback) looks like injection evidence
        # even though the payload caused nothing. Probing it is both unsafe
        # (it mutates shared state) and noisy, so observe it, don't attack it.
        selected = [by_type["Baseline_Inspection"]]
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
        if "SQL_Injection_Error" in by_type:
            selected.append(by_type["SQL_Injection_Error"])
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
        selected = bola_items[:2] if bola_items else []
        # Path parameters are user input too: an object route can hide an
        # injection sink in the path itself (VAmPI's /users/v1/{username}
        # SQLi was missed entirely because these routes got BOLA probes
        # only). Append the generic injection set so object routes get
        # injection coverage, not just BOLA. The probes bind to the path
        # segment (see _append_payload_to_path_segment) when the endpoint
        # has no query/form fields to bind to.
        for inj_type in ("SQL_Injection_GET", "SQL_Injection_Error",
                         "Cross_Site_Scripting", "Command_Injection"):
            if inj_type in by_type:
                selected.append(by_type[inj_type])
        if not selected:
            selected = [by_type["Baseline_Inspection"]]
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
        if "SQL_Injection_Error" in by_type:
            selected.append(by_type["SQL_Injection_Error"])
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


def verify_time_based_proof(request_engine, signature_detector, test_item, test_method,
                            test_url, payload_str, custom_headers, query_params,
                            form_data, json_payload, req_data, baseline_telemetry):
    """Re-verify a time-based Confirmed finding before it stands (2026-10-15).

    The tightened proof margin requires the delay to reproduce: after the
    signature layer Confirms a finding purely on a timing delay, this sends
    one identical re-probe and re-runs the analysis with the reproduction
    measurement attached. A delay that was one-off target slowness under scan
    load (seen live on /about.php and /logout.php, 2026-10-14) downgrades to
    Suspected with the reason in the proof text.

    The re-probe is sequential and bounded by the engine's own request
    timeout, so it cannot wedge the scan; a failed or timed-out re-probe
    downgrades outright (a timeout's synthetic ~30s response time must never
    count as a reproduced delay). Returns the final signature result.
    """
    repro_delta = None
    repro_failed = False
    try:
        repro = request_engine.send_request(
            test_method,
            test_url,
            payload=payload_str,
            custom_headers=custom_headers,
            json_payload=json_payload,
            query_params=query_params,
            form_data=form_data,
            follow_redirects=test_item.get("follow_redirects", True),
        )
    except Exception as exc:
        logger.warning("Time-proof re-probe failed for %s: %s", test_url, exc)
        repro = None
    if repro is None:
        repro_failed = True
    else:
        err_text = str(repro.get("error", "") or "").lower()
        if (repro.get("status_code") == 408 or "timeout" in err_text
                or "timed out" in err_text):
            repro_failed = True
        else:
            try:
                repro_delta = max(
                    0.0,
                    float(repro.get("response_time", 0.0))
                    - float(baseline_telemetry.get("response_time", 0.0)),
                )
            except (TypeError, ValueError):
                repro_failed = True
    req_data["time_proof_repro_delta"] = repro_delta
    req_data["time_proof_repro_failed"] = repro_failed
    return signature_detector.analyze(req_data, baseline_telemetry=baseline_telemetry)


def _response_has_sql_error(signature_detector, response_body):
    """True when any SQL error pattern matches the response body."""
    body = response_body or ""
    return any(re.search(pat, body) for pat in signature_detector.SQL_ERROR_PATTERNS)


def _balanced_quote_control(payload):
    """Balanced-quote control payload for a quote-bearing SQLi probe.

    A syntactically valid quoted string ('' is an empty string literal)
    that must NOT break the query. If the endpoint errors on this too,
    the error is not caused by the injected quote. Returns None when the
    payload has no quote to balance (then only the repeat gate applies).
    """
    if not payload or ("'" not in payload and '"' not in payload):
        return None
    return "''"


# --- Dataset logging (2026-11-27, fixed 2026-11-27) ------------------------
# When DATASET_LOG_DIR is set, every dispatched (baseline, probe) response
# pair is appended as one JSON line to dataset-session-<id>.jsonl in that
# directory. That file IS the dataset record the ML work is trained on.
#
# DESIGN (corrected 2026-11-27): the log carries NO training label. A label
# taken from the scanner's own verdict would be circular — a model trained
# to predict "Confirmed" just copies the signature layer and learns nothing
# about the Suspected cases, which are the ones that need ranking. Instead
# the log carries the fields needed to JOIN to ground truth offline
# (target app, run id, mode, endpoint template, parameter, probe type),
# and the labeling script (evaluation/label_dataset.py) fills the label
# from the ground-truth YAML. The scanner's verdict is stored as a
# separate feature column (scanner_label), never as the label.
#
# Features: the logged dict is the live extractor's output — the 15
# differential keys the tabular models consume (ml_pipeline/feature_extractor
# FEATURE_KEYS). The autoencoder's 17 raw features are NOT in that dict;
# they are recomputed offline from the raw bodies, which is why the raw
# logs matter. (An earlier comment wrongly said "17-feature dict".)
#
# SECRETS: raw responses can contain secrets (VAmPI returns plaintext
# passwords). Logs are gitignored (dataset-logs/, dataset-session-*.jsonl)
# and must never be committed. Never log a real third-party target without
# consent, and never log a held-out app (Juice Shop, crAPI) — the guard
# below refuses those targets outright.
_DATASET_LOG_LOCK = threading.Lock()
_DATASET_BODY_CAP = 100_000
_DATASET_HELD_OUT = tuple(
    p.strip().lower()
    for p in os.getenv("DATASET_HELD_OUT", "juice-shop,crapi").split(",")
    if p.strip()
)


def _dataset_target_app(target_url):
    """Explicit DATASET_TARGET_APP, else the target hostname."""
    app = os.getenv("DATASET_TARGET_APP", "").strip()
    if app:
        return app
    try:
        return urlsplit(target_url).netloc or target_url
    except Exception:
        return target_url


def _normalize_template(url):
    """Best-effort endpoint template: value-like path segments -> {param}.

    Numeric segments, UUIDs and long hex strings are values, not routes.
    The labeling script matches the raw endpoint_url against the
    ground-truth templates too, so this field is a join convenience, not
    the only key.
    """
    try:
        path = urlsplit(url).path
    except Exception:
        return url
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
        elif seg.isdigit():
            out.append("{param}")
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", seg, re.I):
            out.append("{param}")
        elif re.fullmatch(r"[0-9a-f]{16,}", seg, re.I):
            out.append("{param}")
        else:
            out.append(seg)
    return "/".join(out)


def _dataset_log_path(session_id, target_url):
    directory = os.getenv("DATASET_LOG_DIR", "")
    if not directory:
        return None
    # The guard keys on both the URL and the declared app name: a local
    # Juice Shop runs on 127.0.0.1:3000, which carries no marker in the URL.
    lowered = ((target_url or "") + " " + _dataset_target_app(target_url)).lower()
    if any(p in lowered for p in _DATASET_HELD_OUT):
        logger.warning(
            "Dataset logging refused for a held-out target (%s): "
            "held-out apps are never training data.", target_url)
        return None
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"dataset-session-{session_id}.jsonl")


def _cap_body(body):
    body = body or ""
    if len(body) > _DATASET_BODY_CAP:
        return body[:_DATASET_BODY_CAP], True
    return body, False


def log_dataset_pair(session_id, target_url, test_item, test_method, test_url,
                     payload_str, baseline_telemetry, req_data, features,
                     sig_res, risk_summary, parameter="", ml_res=None,
                     dl_res=None):
    """Append one raw (baseline, probe) pair to the dataset log.

    Called for EVERY dispatched probe, not just findings — clean pairs are
    the negative class. The record carries the join fields for the offline
    labeling script, the per-layer shipped-model scores (so the models can
    be measured on the labeled set without re-running the scan), and the
    scanner's verdict as a feature column; the training label is None
    until the labeling script fills it from ground truth. `group` is the
    target app — VAmPI's vulnerable and secure modes are ONE group for
    splitting (training on one mode and testing on the other is leakage).
    Never raises: a logging failure is warned, never fatal to the scan.
    """
    path = _dataset_log_path(session_id, target_url)
    if path is None:
        return
    try:
        row = build_telemetry_record(
            dict(features or {}),
            finding_status=risk_summary.get("finding_status"),
            has_proof=bool(sig_res.get("has_proof")),
            response_status=req_data.get("status_code"),
            attack_type=sig_res.get("attack_type") or "None",
            target_id=target_url,
            endpoint_id=test_url,
            payload_family=test_item.get("type", ""),
        )
        # The scanner's verdict is a feature, never the label. A model
        # trained on the scanner's own verdict would just copy Layer 1.
        row["label_name"] = None
        row["label"] = None
        row["label_source"] = "ground_truth_join (pending)"
        row["scanner_finding_status"] = risk_summary.get("finding_status")
        row["scanner_has_proof"] = bool(sig_res.get("has_proof"))
        row["scanner_score"] = risk_summary.get("total_score")
        row["scanner_label"] = (
            1 if risk_summary.get("finding_status") == "Confirmed" else 0)
        baseline_body, baseline_truncated = _cap_body(
            baseline_telemetry.get("response_body", ""))
        probe_body, probe_truncated = _cap_body(req_data.get("response_body", ""))
        target_app = _dataset_target_app(target_url)
        record = {
            # Join fields for the offline labeling script.
            "target_app": target_app,
            "group": target_app,
            "run_id": session_id,
            "mode": os.getenv("DATASET_MODE", ""),
            "endpoint_template": _normalize_template(test_url),
            "parameter": parameter,
            "probe_type": test_item.get("type", ""),
            "session_id": session_id,
            "target_url": target_url,
            "endpoint_url": test_url,
            "http_method": test_method,
            "payload": payload_str,
            # Per-layer shipped-model scores, for measuring the models on
            # the labeled set (PR-AUC, recall at fixed FPR, ablation).
            # These are the models as shipped — measuring them changes
            # nothing; retraining is a separate, later step.
            "layer_scores": {
                "signature_points": sig_res.get("points"),
                "ml_anomaly_score": (ml_res or {}).get("anomaly_score"),
                "ml_points": (ml_res or {}).get("points"),
                "lstm_probability": (dl_res or {}).get("lstm_probability"),
                "lstm_points": (dl_res or {}).get("lstm_points"),
                "autoencoder_error": (dl_res or {}).get("autoencoder_error"),
                "autoencoder_points": (dl_res or {}).get("autoencoder_points"),
                "total_score": risk_summary.get("total_score"),
            },
            "baseline": {
                "status_code": baseline_telemetry.get("status_code"),
                "response_time": baseline_telemetry.get("response_time"),
                "response_size": baseline_telemetry.get("response_size"),
                "response_body": baseline_body,
                "truncated": baseline_truncated,
            },
            "probe": {
                "status_code": req_data.get("status_code"),
                "response_time": req_data.get("response_time"),
                "response_size": req_data.get("response_size"),
                "response_body": probe_body,
                "truncated": probe_truncated,
            },
            "finding": {
                "attack_type": sig_res.get("attack_type"),
                "finding_status": risk_summary.get("finding_status"),
                "has_proof": bool(sig_res.get("has_proof")),
                "score": risk_summary.get("total_score"),
                "severity": risk_summary.get("severity"),
            },
            "telemetry": row,
        }
        with _DATASET_LOG_LOCK:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.warning("Dataset logging failed for %s: %s", test_url, exc)


def _control_request(test_url, payload_str, query_params, form_data, json_payload, control_payload):
    """Rebuild a probe request with the control payload in place of the original.

    The payload may live in the URL path (path-appended variant), in a query
    param, in form data, or in a JSON body — replace it wherever it was bound
    so the control request is identical in shape to the original.
    """
    control_url = test_url
    if payload_str and test_url.endswith(payload_str):
        control_url = test_url[: -len(payload_str)] + control_payload

    def _swap(mapping):
        if mapping is None:
            return None
        return {k: (control_payload if v == payload_str else v)
                for k, v in mapping.items()}

    control_json = None
    if isinstance(json_payload, dict):
        control_json = {k: (control_payload if v == payload_str else v)
                        for k, v in json_payload.items()}
    elif json_payload is not None:
        control_json = json_payload
    return control_url, _swap(query_params), _swap(form_data), control_json


def verify_sql_error_proof(request_engine, signature_detector, sig_res, test_item, test_method,
                           test_url, payload_str, custom_headers, query_params,
                           form_data, json_payload, req_data, baseline_telemetry):
    """Re-verify an error-based SQLi Confirmed finding before it stands (2026-11-27).

    A database error in one probe response is not proof the payload caused
    it — a transient error (a "database is locked" race, a wedged seed)
    produces the same text. Two gates, both required:
    1. Reproduce: re-send the identical probe sequentially; the SQL error
       text must appear again. A one-off transient error fails this.
    2. Control: send the same request with a balanced-quote payload ('').
       The SQL error text must be ABSENT. If the endpoint errors on a
       syntactically valid quoted string too, the error is not caused by
       the injected quote.
    Either gate failing downgrades the finding to Suspected (differential
    without proof) with the reason in the proof text. The repeat/control
    requests are sequential and bounded by the engine's own request timeout,
    so they cannot wedge the scan; a failed repeat/control downgrades
    outright. Returns the final signature result (the original dict
    unchanged when both gates pass).
    """
    if not (sig_res.get("has_proof") and sig_res.get("finding_status") == "Confirmed"
            and sig_res.get("attack_type") == "SQL_Injection"
            and "SQL Error signature matched" in str(sig_res.get("proof_of_concept", ""))):
        return sig_res

    def _send(url, payload, qparams, fdata, jpayload):
        try:
            return request_engine.send_request(
                test_method, url, payload=payload, custom_headers=custom_headers,
                json_payload=jpayload, query_params=qparams, form_data=fdata,
                follow_redirects=test_item.get("follow_redirects", True),
            )
        except Exception as exc:
            logger.warning("SQL-error verification request failed for %s: %s", url, exc)
            return None

    def _downgrade(reason):
        downgraded = dict(sig_res)
        downgraded["finding_status"] = "Suspected"
        downgraded["has_proof"] = False
        downgraded["is_vulnerable"] = False
        downgraded["confidence"] = "Medium"
        downgraded["points"] = 15
        downgraded["proof_of_concept"] = (
            f"SQL error did not verify ({reason}); graded Suspected, "
            "differential without proof"
        )
        return downgraded

    # Gate 1: the error must reproduce on a sequential identical repeat.
    repeat = _send(test_url, payload_str, query_params, form_data, json_payload)
    if repeat is None or not _response_has_sql_error(signature_detector, repeat.get("response_body", "")):
        return _downgrade("error did not reproduce on sequential repeat")

    # Gate 2: the error must be absent on the balanced-quote control.
    control_payload = _balanced_quote_control(payload_str)
    if control_payload is not None:
        control_url, control_q, control_f, control_j = _control_request(
            test_url, payload_str, query_params, form_data, json_payload, control_payload)
        control = _send(control_url, control_payload, control_q, control_f, control_j)
        if control is None:
            return _downgrade("balanced-quote control request failed")
        if _response_has_sql_error(signature_detector, control.get("response_body", "")):
            return _downgrade("error also present on balanced-quote control")
    return sig_res


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
            # Bare-quote error probe (ported from the platform's bb5e1b9 queue):
            # a lone quote reliably forces a database syntax error on injectable
            # endpoints (e.g. DVWA's sqli module dies with its MariaDB error),
            # which the signature layer confirms on the response evidence alone
            # — no boolean or time-based payload needed. attack_category pins
            # the expected category since the bare quote matches no
            # payload-syntax rule by itself.
            {"type": "SQL_Injection_Error", "attack_category": "SQL_Injection", "payload": "'", "method": "GET"},
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

        def _scan_one_endpoint(idx, ep_info):
                base_ep_url = ep_info["url"]
                default_method = ep_info["method"]

                print(f"\n[{idx}/{len(discovered_endpoints)}] Testing Endpoint: [{default_method}] {base_ep_url}")

                # Baseline request. Time-based proofs (SLEEP payloads) compare the
                # probe's response time against this baseline, so a single slow
                # baseline sample can fabricate a "Confirmed" via normal jitter.
                # When a time-based probe is queued, take a second baseline and
                # use the faster of the two: a real delay must beat BOTH samples.
                # Baselines share the global in-flight cap with probe traffic.
                with _in_flight():
                    baseline_req = request_engine.send_request(default_method, base_ep_url)
                _prelim_queue = _select_test_queue(ep_info, active_test_queue)
                # Any time-based probe (SQL_Injection_Time, Command_Injection_Time,
                # ...) needs the double-baseline jitter guard.
                needs_time_baseline = any(
                    str(item.get("type", "")).endswith("_Time") for item in _prelim_queue
                )
                if needs_time_baseline:
                    with _in_flight():
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
                    with _DB_WRITE_LOCK:
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
                    bound_any = False
                    for target_field in targets:
                        query_params, form_data = _bind_payload_to_endpoint(ep_info, test_method, payload_str, target_field)
                        if fixed_json is not None:
                            json_payload = fixed_json
                        else:
                            json_payload = _bind_json_payload_to_endpoint(ep_info, test_method, payload_str, target_field)
                        headers = dict(custom_headers) if custom_headers else None
                        if json_payload is not None and headers is None:
                            headers = {"Content-Type": "application/json"}
                        if query_params is not None or form_data is not None or json_payload is not None:
                            bound_any = True
                        prepared_requests.append((test_item, test_url, test_method, payload_str, headers, query_params, form_data, json_payload))
                    # Path-parameter variant: when the endpoint has no field
                    # to bind the payload to, the standard request carries
                    # it as a query parameter — which never reaches a sink
                    # that interpolates the PATH segment (VAmPI's
                    # /users/v1/{username} SQLi). Also send the payload
                    # appended to the last path segment, so path-param sinks
                    # get tested on every route, not just object routes.
                    # SAFETY: GET only. A path-appended payload must never
                    # be sent with a state-changing method — DELETE (or
                    # POST/PUT/PATCH) with a mutated path segment could
                    # change or delete real data. (Endpoints WITH fields
                    # keep field binding only; a field-plus-path-param
                    # combo is not covered yet.)
                    if (not bound_any and test_item.get("type") in _PATH_INJECTION_TYPES
                            and test_method == "GET"):
                        path_url = _append_payload_to_path_segment(test_url, payload_str)
                        if path_url and path_url != test_url:
                            headers = dict(custom_headers) if custom_headers else None
                            prepared_requests.append((test_item, path_url, test_method, payload_str, headers, None, None, None))

                def dispatch(prepared):
                    test_item, test_url, test_method, payload_str, custom_headers, query_params, form_data, json_payload = prepared
                    # Global in-flight cap: however many endpoint/probe threads
                    # are parked, at most MAX_IN_FLIGHT_REQUESTS HTTP requests
                    # are live at once, so the scan never floods the target.
                    try:
                        with _in_flight():
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
                    except SlotTimeout:
                        logger.warning(
                            "Probe skipped (no request slot after %ss): [%s] %s type=%s",
                            SLOT_ACQUIRE_TIMEOUT, test_method, test_url, test_item.get("type"),
                        )
                        return None
                    return (test_item, test_url, test_method, payload_str, custom_headers,
                            query_params, form_data, json_payload, req_data)

                # Requests are bounded and concurrent; detection runs per
                # endpoint in parallel, while DB writes are serialized by
                # _DB_WRITE_LOCK so persistence stays deterministic.
                # The dispatch budget caps the whole batch: one hung probe is dropped
                # instead of wedging the scan on this endpoint forever.
                dispatched_requests = _dispatch_bounded(
                    dispatch,
                    prepared_requests,
                    max_workers=min(ACTIVE_CONCURRENCY, max(1, len(prepared_requests))),
                    timeout=ENDPOINT_DISPATCH_TIMEOUT,
                )

                dispatched_requests = [r for r in dispatched_requests if r is not None]
                for (test_item, test_url, test_method, payload_str, custom_headers,
                     query_params, form_data, json_payload, req_data) in dispatched_requests:
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

                    # Time-based proof margin (2026-10-15): a single slow response
                    # is not proof the delay payload executed. When the signature
                    # layer Confirms purely on a timing delay, re-probe identically
                    # and require the delay to reproduce before the finding stands.
                    if (sig_res.get("has_proof")
                            and sig_res.get("finding_status") == "Confirmed"
                            and "Time-based" in str(sig_res.get("proof_of_concept", ""))):
                        sig_res = verify_time_based_proof(
                            request_engine, signature_detector, test_item, test_method,
                            test_url, payload_str, custom_headers, query_params,
                            form_data, json_payload, req_data, baseline_telemetry)

                    # SQL error proof margin (2026-11-27): a database error in
                    # one probe response is not proof the payload caused it —
                    # a transient error (a lock, a race, a wedged seed) shows
                    # the same text. When the signature layer Confirms SQLi
                    # on an error signature, require the error to reproduce
                    # on a sequential repeat AND to be absent on a
                    # balanced-quote control before the finding stands.
                    if (sig_res.get("has_proof")
                            and sig_res.get("finding_status") == "Confirmed"
                            and sig_res.get("attack_type") == "SQL_Injection"
                            and "SQL Error signature matched" in str(sig_res.get("proof_of_concept", ""))):
                        sig_res = verify_sql_error_proof(
                            request_engine, signature_detector, sig_res, test_item,
                            test_method, test_url, payload_str, custom_headers,
                            query_params, form_data, json_payload, req_data,
                            baseline_telemetry)

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

                    # Dataset record: log the raw (baseline, probe) pair for
                    # every dispatched probe (clean pairs are the negative
                    # class). Gated by DATASET_LOG_DIR; never breaks a scan.
                    # The parameter is the field the payload was bound to
                    # ("path" for the path-appended variant, "" if unknown).
                    _bound_param = ""
                    for _bound in (query_params, form_data, json_payload):
                        if isinstance(_bound, dict):
                            for _k, _v in _bound.items():
                                if _v == payload_str:
                                    _bound_param = _k
                                    break
                            if _bound_param:
                                break
                    if not _bound_param and payload_str and payload_str in test_url:
                        _bound_param = "path"
                    log_dataset_pair(
                        session_obj.id, target_url, test_item, test_method,
                        test_url, payload_str, baseline_telemetry, req_data,
                        features, sig_res, risk_summary,
                        parameter=_bound_param, ml_res=ml_res, dl_res=dl_res)

                    # Print Console Breakdown
                    print(f"  [{test_item['type']}] -> Layer 1: {sig_res['points']} pts | ML: {ml_res['points']} pts | DL: {dl_res['total_layer3_points']} pts | SCORE: {score} [{severity}]")

                    # Persist Result to SQLite Database
                    with _DB_WRITE_LOCK:
                        ep_obj = save_endpoint(session_id=session_obj.id, url=test_url, method=test_method)

                    confirmed = bool(risk_summary.get("is_vulnerable") or sig_res.get("is_vulnerable"))
                    attack_name = sig_res.get("attack_type", "None") if (confirmed or sig_res.get("matched") or sig_res.get("finding_status") == "Informational") else "None"

                    # Persist non-zero triage signals for auditability, but only
                    # confirmed proof contributes to the vulnerability total.
                    if score > 0 or sig_res.get("matched"):
                        with _DB_WRITE_LOCK:
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

        # Endpoints are independent (own baselines, probes, findings), so
        # scan them concurrently instead of strictly one at a time — wall
        # time used to be the sum of every endpoint's slowest probe batch.
        # A fault in one endpoint is logged and skipped; it must not kill
        # the whole scan. Progress counts completed endpoints, in
        # completion order.
        _progress_lock = threading.Lock()
        _completed = {"count": 0}
        _settled = set()          # endpoint idx values already counted
        _skipped_endpoints = []   # (url, reason) - reported at the end
        _total_endpoints = len(discovered_endpoints)
        _stop_event = get_stop_event(session_obj.id)

        def _count_endpoint_done(idx) -> bool:
            """Count an endpoint once, whether it finished or was abandoned."""
            with _progress_lock:
                if idx in _settled:
                    return False
                _settled.add(idx)
                _completed["count"] += 1
                done = _completed["count"]
            update_scan_progress(session_obj.id, done=done)
            return True

        def _run_endpoint_guarded(idx_ep):
            idx, ep_info = idx_ep
            url = ep_info.get("url")
            started = time.monotonic()
            logger.info("Endpoint %d/%d START [%s] %s", idx, _total_endpoints,
                        ep_info.get("method"), url)
            outcome = "ok"
            try:
                if _stop_event.is_set():
                    outcome = "skipped: scan stopped"
                    return
                _scan_one_endpoint(idx, ep_info)
            except SlotTimeout as exc:
                outcome = f"skipped: {exc}"
                _skipped_endpoints.append((url, outcome))
            except Exception as exc:  # one bad endpoint must not kill the scan
                outcome = f"failed: {exc}"
                logger.error("Endpoint %s failed, continuing scan: %s", url, exc)
            finally:
                logger.info("Endpoint %d/%d END   [%s] %s -> %s in %.1fs", idx,
                            _total_endpoints, ep_info.get("method"), url, outcome,
                            time.monotonic() - started)
                _count_endpoint_done(idx)

        def _on_endpoint_abandoned(idx_ep, elapsed):
            idx, ep_info = idx_ep
            reason = (f"abandoned after {elapsed:.0f}s "
                      f"(budget {ENDPOINT_WALL_BUDGET}s)" if not _stop_event.is_set()
                      else "abandoned: scan stopped")
            logger.error("Endpoint %d/%d [%s] %s %s", idx, _total_endpoints,
                         ep_info.get("method"), ep_info.get("url"), reason)
            _skipped_endpoints.append((ep_info.get("url"), reason))
            _count_endpoint_done(idx)

        try:
            _pool_result = run_bounded_pool(
                list(enumerate(discovered_endpoints, start=1)),
                _run_endpoint_guarded,
                concurrency=min(ENDPOINT_CONCURRENCY, max(1, _total_endpoints)),
                per_item_budget=ENDPOINT_WALL_BUDGET,
                on_abandon=_on_endpoint_abandoned,
                stop_event=_stop_event,
            )
        finally:
            _was_stopped = _stop_event.is_set()
            release_stop_event(session_obj.id)
        if _was_stopped:
            # Cancelled by the user or reaped by the watchdog: the session was
            # already marked failed. Return without the roll-up so a stopped
            # scan is never resurrected as "complete".
            logger.warning("Scan %s was stopped; skipping final roll-up.", session_obj.id)
            return session_obj.id if return_session_id else 0
        if _skipped_endpoints:
            logger.warning(
                "Scan %s finished with %d skipped endpoint(s): %s",
                session_obj.id, len(_skipped_endpoints),
                "; ".join(f"{u} ({r})" for u, r in _skipped_endpoints),
            )
            print(f"\n[!] {len(_skipped_endpoints)} endpoint(s) were skipped - partial results finalized:")
            for _u, _r in _skipped_endpoints:
                print(f"    - {_u}: {_r}")
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
            total_vulnerabilities=summary["vulnerabilities"],
            # Persist the abandoned endpoints on the session: a completed
            # scan with skips is partial coverage, and the UI/report must
            # say so instead of showing a bare "COMPLETE 50/50".
            skipped_endpoints=[{"url": u, "reason": r} for u, r in _skipped_endpoints],
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
                "skipped_endpoints": parse_skipped_endpoints(
                    getattr(persisted_session, "skipped_endpoints", None)),
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
