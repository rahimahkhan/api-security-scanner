"""Canonical response-differential feature definitions (schema: response-diff-13-v1).

This module is the SINGLE source of truth for Layer-2/3 feature extraction.
Every other component imports from here:

  - core/response_parser.py  (serving time — ResponseParser.extract_features delegates here)
  - ml_pipeline/train_csic.py (training time — dataset builder + trainer use this)
  - detection/ml_model.py     (imports FEATURE_KEYS)
  - detection/deep_learning.py (imports FEATURE_KEYS)

Design
------
The ML layer is a *response* anomaly detector. Features describe the probe's
HTTP response and — when a baseline response is supplied — how that response
*deviates* from the baseline. A benign probe returns a response that looks
like the baseline (same status, similar size, fast, no error text); an
exploited probe does not (SQL error page, reflected payload, 5xx, delay).

Request-side measurements are deliberately limited to two minor context
features (payload_length_log, encoded_method). They can never dominate the
signal the way the old 17-feature request-side schema did.

When no baseline is available the differential features degrade to 0 and the
absolute response features (status_class, response_size_log, response_time_s,
error_keyword_count, sensitive_field_count) still carry signal.
"""

import difflib
import math
import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Feature schema (documented here — the one place)
# ---------------------------------------------------------------------------
# Differential vs baseline (0 when no baseline supplied):
#   status_changed        0/1  — probe status code differs from baseline status
#   size_delta_ratio      signed (probe-base)/max(base,1), clipped to [-2, 2]
#   time_delta_ratio      signed (probe-base)/max(base,0.05), clipped to [-2, 10]
#   body_diff_ratio       1 - difflib similarity between baseline and probe bodies, 0..1
#                       (0 = identical, higher = more different)
#   content_type_changed  0/1  — response content-type class differs
#   error_keyword_delta   max(0, probe_err - base_err), clipped to [0, 10]
#   payload_reflected     0/1  — payload verbatim in probe body but not baseline
#   unsafe_reflection     0/1  — payload reflected where it can execute: verbatim
#                       in an HTML/XML response (not JSON/data). A safe JSON echo
#                       sets payload_reflected=1 but unsafe_reflection=0.
# Absolute response features:
#   status_class          0 (none), 2, 3, 4, 5
#   response_size_log     log10(1 + response_size)
#   response_time_s       response time in seconds, clipped to [0, 30]
#   error_keyword_count   error-indicator keywords in probe body, clipped [0, 10]
#   sensitive_field_count sensitive patterns in probe body, clipped to [0, 8]
# Minor request context:
#   payload_length_log    log10(1 + len(payload))
#   encoded_method        GET=1, POST=2, PUT=3, DELETE=4, PATCH=5, OPTIONS=6, HEAD=7
FEATURE_KEYS = [
    "status_changed",
    "size_delta_ratio",
    "time_delta_ratio",
    "body_diff_ratio",
    "content_type_changed",
    "error_keyword_delta",
    "payload_reflected",
    "unsafe_reflection",
    "status_class",
    "response_size_log",
    "response_time_s",
    "error_keyword_count",
    "sensitive_field_count",
    "payload_length_log",
    "encoded_method",
]

SCHEMA_VERSION = "response-diff-14-v1"

METHOD_ENCODING = {
    "GET": 1,
    "POST": 2,
    "PUT": 3,
    "DELETE": 4,
    "PATCH": 5,
    "OPTIONS": 6,
    "HEAD": 7,
}

# Error indicators that appear in application error pages (SQL errors,
# tracebacks, driver messages). Counted in the *response body*.
ERROR_KEYWORDS = [
    "sql", "syntax", "exception", "traceback", "mysql", "ora-",
    "pg::", "sqlite", "odbc", "jdbc", "stack trace", "fatal error",
    "warning:", "notice:", "query failed", "database error",
]

SENSITIVE_FIELD_PATTERNS = [
    r"password",
    r"passwd",
    r"secret",
    r"token",
    r"api[_-]?key",
    r"auth[_-]?token",
    r"access[_-]?token",
    r"card[_-]?number",
    r"credit[_-]?card",
    r"ssn",
    r"private[_-]?key",
]

# Cap body sizes before diffing so a multi-MB dump can't stall extraction.
_MAX_DIFF_CHARS = 20000


def _safe_status_code(telemetry: Dict[str, Any]) -> int:
    """Extract status code, mapping None/missing/garbage to 0 (never raises)."""
    raw = telemetry.get("status_code", 0)
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(result) or math.isinf(result):
        return default
    return result


def _content_type_class(headers: Dict[str, Any]) -> str:
    if not headers:
        return ""
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            return str(value).split(";")[0].strip().lower()
    return ""


def _count_error_keywords(body: str) -> int:
    if not body:
        return 0
    lowered = body.lower()
    return sum(1 for kw in ERROR_KEYWORDS if kw in lowered)


def _count_sensitive_fields(body: str) -> int:
    if not body:
        return 0
    return sum(1 for pattern in SENSITIVE_FIELD_PATTERNS if re.search(pattern, body, re.IGNORECASE))


def _clip(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def extract_response_features(
    telemetry: Dict[str, Any],
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Extract the canonical response-differential feature dict.

    Args:
        telemetry: probe telemetry with keys like the scanner's req_data —
            status_code, response_size, response_time, response_body,
            response_headers, payload, method.
        baseline: optional baseline telemetry (same keys) for the same
            endpoint without the attack payload. When omitted, differential
            features are 0.

    Returns:
        dict with one entry per FEATURE_KEYS plus "feature_vector"
        (ordered list matching FEATURE_KEYS).
    """
    telemetry = telemetry or {}
    baseline = baseline or {}
    has_baseline = bool(baseline)

    # --- Probe response attributes (absolute) ---
    status_code = _safe_status_code(telemetry)
    status_class = status_code // 100 if status_code >= 100 else 0
    response_size = max(0, int(_safe_float(telemetry.get("response_size", 0))))
    response_time = _clip(_safe_float(telemetry.get("response_time", 0.0)), 0.0, 30.0)
    probe_body = str(telemetry.get("response_body") or "")
    probe_headers = telemetry.get("response_headers") or {}
    if not isinstance(probe_headers, dict):
        probe_headers = {}

    error_keyword_count = _clip(_count_error_keywords(probe_body), 0, 10)
    sensitive_field_count = _clip(_count_sensitive_fields(probe_body), 0, 8)

    # --- Minor request context (never the main signal) ---
    payload = str(telemetry.get("payload") or "")
    payload_length_log = round(math.log10(1 + len(payload)), 4)
    method_str = str(telemetry.get("method", "GET")).upper()
    encoded_method = METHOD_ENCODING.get(method_str, 0)

    # --- Differential vs baseline ---
    status_changed = 0
    size_delta_ratio = 0.0
    time_delta_ratio = 0.0
    body_diff_ratio = 0.0
    content_type_changed = 0
    error_keyword_delta = 0
    payload_reflected = 0

    if has_baseline:
        base_status = _safe_status_code(baseline)
        if status_code != base_status:
            status_changed = 1

        base_size = max(0, int(_safe_float(baseline.get("response_size", 0))))
        size_delta_ratio = round(_clip((response_size - base_size) / max(base_size, 1), -2.0, 2.0), 4)

        base_time = max(0.0, _safe_float(baseline.get("response_time", 0.0)))
        time_delta_ratio = round(_clip((response_time - base_time) / max(base_time, 0.05), -2.0, 10.0), 4)

        base_body = str(baseline.get("response_body") or "")
        if base_body or probe_body:
            similarity = difflib.SequenceMatcher(
                None,
                base_body[:_MAX_DIFF_CHARS],
                probe_body[:_MAX_DIFF_CHARS],
            ).ratio()
            body_diff_ratio = round(1.0 - similarity, 4)

        base_ct = _content_type_class(baseline.get("response_headers") or {})
        probe_ct = _content_type_class(probe_headers)
        if base_ct and probe_ct and base_ct != probe_ct:
            content_type_changed = 1

        base_err = _count_error_keywords(base_body)
        error_keyword_delta = int(_clip(max(0, _count_error_keywords(probe_body) - base_err), 0, 10))

        if len(payload) >= 4 and payload in probe_body and payload not in base_body:
            payload_reflected = 1

    # unsafe_reflection: the payload is reflected where it can execute.
    # Verbatim reflection inside an HTML/XML document is dangerous (XSS);
    # the same bytes inside a JSON string (or any non-HTML content) are inert
    # data. This is the feature that lets the model tell a safe echo apart
    # from a vulnerable reflection.
    unsafe_reflection = 0
    if payload_reflected:
        ct = str((probe_headers or {}).get("content-type", "") or "").lower()
        # Also sniff the body: some apps serve HTML without a proper header.
        looks_like_html = ("text/html" in ct or "application/xml" in ct
                           or probe_body.lstrip()[:1] == "<")
        if looks_like_html:
            unsafe_reflection = 1

    feature_vector = [
        status_changed,
        size_delta_ratio,
        time_delta_ratio,
        body_diff_ratio,
        content_type_changed,
        error_keyword_delta,
        payload_reflected,
        unsafe_reflection,
        status_class,
        round(math.log10(1 + response_size), 4),
        round(response_time, 4),
        error_keyword_count,
        sensitive_field_count,
        payload_length_log,
        encoded_method,
    ]

    feature_dict = dict(zip(FEATURE_KEYS, feature_vector))
    feature_dict["feature_vector"] = feature_vector
    feature_dict["schema_version"] = SCHEMA_VERSION
    return feature_dict


# ---------------------------------------------------------------------------
# Backwards-compatibility shim for serving-time callers that only have the
# old request-side extractor name. Deprecated: use extract_response_features.
# ---------------------------------------------------------------------------
def extract_features_from_request(req_data: Dict[str, Any]) -> Dict[str, Any]:  # noqa: D103
    import warnings

    warnings.warn(
        "extract_features_from_request is deprecated: it measured the scanner's own "
        "request, not the target's response. Use extract_response_features instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return extract_response_features(req_data or {}, None)
