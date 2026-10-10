import math
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
# Canonical response-differential feature definitions — the single source of
# truth. Serving-time extraction delegates here so train and serve can never
# drift apart again.
from ml_pipeline.feature_extractor import (
    FEATURE_KEYS,
    METHOD_ENCODING,
    SENSITIVE_FIELD_PATTERNS,
    extract_response_features,
)

class ResponseParser:
    """
    Parses request/response telemetry data and extracts the canonical
    response-differential feature vector for the ML/DL models.

    The feature schema is defined once in ml_pipeline/feature_extractor.py
    (FEATURE_KEYS); this class is the serving-time entry point used by
    main.py and the dashboard. It also keeps the sensitive-field leak check.
    """

    # Re-exported for backwards compatibility with existing callers/tests.
    METHOD_ENCODING = METHOD_ENCODING
    SENSITIVE_FIELD_PATTERNS = SENSITIVE_FIELD_PATTERNS

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculates Shannon entropy of string payload (kept for API compatibility)."""
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

    @staticmethod
    def count_special_characters(text: str) -> int:
        """Counts special non-alphanumeric characters (kept for API compatibility)."""
        if not text:
            return 0
        return len(re.findall(r"[^\w\s]", text))

    def extract_features(
        self,
        response_data: Dict[str, Any],
        baseline_telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extracts the canonical response-differential feature dict.

        Args:
            response_data: probe telemetry (status_code, response_size,
                response_time, response_body, response_headers, payload,
                method). A status_code of None is treated as 0 (unreachable).
            baseline_telemetry: optional baseline response for the same
                endpoint (same keys). When supplied, differential features
                (status_changed, size/time deltas, reflection, …) are
                computed; otherwise they degrade to 0.

        Returns:
            dict with one entry per FEATURE_KEYS plus "feature_vector"
            (ordered list) and "sensitive_fields_leaked".
        """
        feature_dict = extract_response_features(response_data or {}, baseline_telemetry)

        # Sensitive-field leak check on the probe response body (unchanged behavior).
        response_body = (response_data or {}).get("response_body", "")
        feature_dict["sensitive_fields_leaked"] = self.check_sensitive_fields(response_body)
        return feature_dict

    def check_sensitive_fields(self, response_body: str) -> List[str]:
        """Scans response body text for exposed sensitive field patterns."""
        if not response_body:
            return []
        found_matches = []
        for pattern in self.SENSITIVE_FIELD_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE):
                found_matches.append(pattern)
        return found_matches


if __name__ == "__main__":
    parser = ResponseParser()
    baseline = {
        "method": "GET",
        "url": "https://api.example.com/v1/users",
        "payload": "",
        "status_code": 200,
        "response_size": 512,
        "response_time": 0.12,
        "response_body": '{"users": []}',
        "response_headers": {"Content-Type": "application/json"},
    }
    probe = dict(baseline)
    probe["payload"] = "' OR '1'='1"
    probe["response_body"] = "SQL syntax error near ''1'' at line 1 (mysql)"
    probe["response_size"] = 64
    probe["status_code"] = 500
    extracted = parser.extract_features(probe, baseline)
    print("\n[+] Extracted response-differential features:")
    for k in FEATURE_KEYS:
        print(f"  {k}: {extracted[k]}")
