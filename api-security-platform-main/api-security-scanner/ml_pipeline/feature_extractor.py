import math
import re
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs

FEATURE_KEYS = [
    "encoded_method",
    "path_depth",
    "url_length",
    "query_param_count",
    "query_string_length",
    "payload_length",
    "payload_entropy",
    "special_char_count",
    "header_count",
    "auth_header_present",
    "status_code",
    "response_size",
    "keyword_risk_score",
    "param_name_risk",
    "url_encoded_ratio",
    "payload_digit_ratio",
    "has_sql_structure",
]

METHOD_ENCODING = {
    "GET": 1,
    "POST": 2,
    "PUT": 3,
    "DELETE": 4,
    "PATCH": 5,
    "OPTIONS": 6,
    "HEAD": 7,
}


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def count_special_characters(text: str) -> int:
    if not text:
        return 0
    return len(re.findall(r"[^\w\s]", text))


def extract_features_from_request(req_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts the 17-feature schema (runtime-http-17-v1) from a request dictionary.
    Supports standard scanner format and CSIC 2010 request-side formats.
    """
    method_str = str(req_data.get("Method") or req_data.get("method") or "GET").strip().upper()
    encoded_method = METHOD_ENCODING.get(method_str, 1)

    raw_url = str(req_data.get("URL") or req_data.get("url") or "")
    url_clean = raw_url.split(" HTTP")[0].strip()
    parsed_url = urlparse(url_clean)

    path_segments = [seg for seg in parsed_url.path.split("/") if seg]
    path_depth = len(path_segments)
    url_length = len(url_clean)

    query_string = parsed_url.query
    query_params = parse_qs(query_string, keep_blank_values=True)
    query_param_count = len(query_params)
    query_string_length = len(query_string)

    payload = str(req_data.get("content") if req_data.get("content") is not None else (req_data.get("payload") or ""))
    payload_length = len(payload)
    payload_entropy = calculate_shannon_entropy(payload)
    # Match training (prepare_dataset.py): special chars counted over payload + URL
    # with the same explicit character set.
    _TRAIN_SPECIAL = set("'\";<>(){}[]&|`!@#$%^*\\=+")
    special_char_count = sum(1 for c in (payload + url_clean) if c in _TRAIN_SPECIAL)

    # Header analysis. For CSIC-2010-format dicts, replicate the training count:
    # number of non-empty values among the 10 recorded header columns.
    # For scanner-format dicts, count the request_headers mapping instead.
    _CSIC_HEADER_COLS = (
        "User-Agent", "Pragma", "Cache-Control", "Accept", "Accept-encoding",
        "Accept-charset", "language", "cookie", "content-type", "connection",
    )
    if any(col in req_data for col in _CSIC_HEADER_COLS):
        header_count = sum(
            1 for col in _CSIC_HEADER_COLS
            if str(req_data.get(col, "")).strip() not in ("", "nan")
        )
    else:
        headers = req_data.get("request_headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        header_count = len(headers)
        if "host" in req_data and req_data["host"]:
            header_count += 1
        if "cookie" in req_data and req_data["cookie"]:
            header_count += 1
        if "content-type" in req_data and req_data["content-type"]:
            header_count += 1
        header_count = max(header_count, 1)

    # Auth header check (match training: any auth material or a session cookie)
    auth_header_present = 0
    cookie_str = str(req_data.get("cookie") or "").lower()
    if "session" in cookie_str or "auth" in cookie_str or "token" in cookie_str or "jwt" in cookie_str:
        auth_header_present = 1
    elif cookie_str.strip():
        # Training marks any present cookie as auth material.
        auth_header_present = 1
    headers = req_data.get("request_headers") or {}
    if isinstance(headers, dict):
        for h, hv in headers.items():
            h_l = str(h).lower()
            if h_l in ["authorization", "x-api-key", "x-access-token"]:
                auth_header_present = 1
                break
            if isinstance(hv, str) and hv.strip().lower().startswith("bearer "):
                auth_header_present = 1
                break
    for h, hv in headers.items():
        h_l = str(h).lower()
        if h_l in ["authorization", "x-api-key", "x-access-token"]:
            auth_header_present = 1
            break
        if isinstance(hv, str) and hv.strip().lower().startswith("bearer "):
            auth_header_present = 1
            break

    # Request-only CSIC dataset records have no response telemetry.
    # prepare_dataset.py trains with status_code=200 and response_size=min(payload_len*2, 5000),
    # so the defaults here must match the training assumption; otherwise the
    # standardized features explode (e.g. status_code 0 -> z-score -200).
    status_code = int(req_data.get("status_code") or 200)
    response_size = int(req_data.get("response_size") or min(payload_length * 2, 5000))

    risk_keywords = [
        "select", "union", "insert", "drop",
        "delete", "update", "exec", "script",
        "alert", "onerror", "onload", "eval",
        "base64", "passwd", "shadow", "whoami",
        "null", "none", "true", "admin", "root"
    ]
    combined_text = (payload + " " + url_clean).lower()
    words = re.findall(r"\w+", combined_text)
    total_words = max(len(words), 1)
    keyword_matches = sum(1 for kw in risk_keywords if kw in combined_text)
    keyword_risk_score = round(min(keyword_matches / total_words, 1.0), 4)

    risky_params = [
        "id", "user", "uid", "admin", "debug",
        "test", "token", "key", "pass", "pwd",
        "cmd", "exec", "query", "sql", "file"
    ]
    param_names = [k.lower() for k in query_params.keys()]
    if payload.strip().startswith("{") and payload.strip().endswith("}"):
        try:
            import json
            j_data = json.loads(payload)
            if isinstance(j_data, dict):
                param_names.extend([k.lower() for k in j_data.keys()])
        except Exception:
            pass
    elif "=" in payload:
        try:
            body_params = parse_qs(payload, keep_blank_values=True)
            param_names.extend([k.lower() for k in body_params.keys()])
        except Exception:
            pass

    param_name_risk = sum(1 for p in param_names if any(rp in p for rp in risky_params))
    url_encoded_ratio = round(url_clean.count("%") / max(len(url_clean), 1), 4)
    digit_count = sum(1 for c in payload if c.isdigit())
    payload_digit_ratio = round(digit_count / max(len(payload), 1), 4)

    sql_patterns = [
        r"'\s*(or|and)\s+'",
        r"\bunion\b.*\bselect\b",
        r"--\s*$",
        r";\s*(drop|delete|insert|update)",
        r"'\s*=\s*'"
    ]
    has_sql_structure = 1 if any(re.search(p, combined_text, re.IGNORECASE) for p in sql_patterns) else 0

    return {
        "encoded_method": encoded_method,
        "path_depth": path_depth,
        "url_length": url_length,
        "query_param_count": query_param_count,
        "query_string_length": query_string_length,
        "payload_length": payload_length,
        "payload_entropy": payload_entropy,
        "special_char_count": special_char_count,
        "header_count": header_count,
        "auth_header_present": auth_header_present,
        "status_code": status_code,
        "response_size": response_size,
        "keyword_risk_score": keyword_risk_score,
        "param_name_risk": param_name_risk,
        "url_encoded_ratio": url_encoded_ratio,
        "payload_digit_ratio": payload_digit_ratio,
        "has_sql_structure": has_sql_structure,
    }
