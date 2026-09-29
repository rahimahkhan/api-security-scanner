import difflib
import os
import re
import sys
from typing import Dict, Any, List, Optional
from pathlib import Path
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import PAYLOADS_DIR

class SignatureDetector:
    """
    Layer 1 — Signature & Response Verification Detection Engine
    Analyzes HTTP telemetry for known attack patterns, enforces response verification gates
    (reflection checks, SQL error traces, WAF status code filtering), security header misconfigurations,
    and sensitive field leaks.
    """

    REGEX_RULES = {
        "SQL_Injection": [
            r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|HAVING)\b)",
            r"(?i)('|\"|;|\bOR\b|\bAND\b)\s*1\s*=\s*1",
            r"(?i)(?:'|\")\s*(?:OR|AND)\s*(?:'|\")?\s*\d+\s*(?:'|\")?\s*=\s*(?:'|\")?\s*\d+",
            r"(?i)--\s*$",
            r"(?i)\bSLEEP\s*\(\s*\d+\s*\)",
            r"(?i)\bBENCHMARK\s*\("
        ],
        "XSS": [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)javascript\s*:",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)<iframe[^>]*>"
        ],
        "Command_Injection": [
            r";\s*(cat|ls|whoami|id|pwd|uname|netstat)\b",
            r"\|\s*(cat|ls|whoami|id|pwd|uname)\b",
            r"`.*`",
            r"\$\(.*\)"
        ],
        "Local_File_Inclusion": [
            r"(?i)(?:\.\./){2,}[^\s]+",
            r"(?i)(?:php|file|data)://"
        ],
        "XXE": [
            r"(?is)<!DOCTYPE[^>]+(?:<!ENTITY|SYSTEM)",
            r"(?i)file:///[A-Za-z0-9_./-]+"
        ],
        "GraphQL_Introspection": [
            r"(?i)__schema",
            r"(?i)__typename"
        ],
        "Open_Redirect": [
            r"(?i)(?:https?://|//)[^\s]+"
        ],
        "BOLA_IDOR": [
            r"/users?/\d+",
            r"/accounts?/\d+",
            r"id=\d+"
        ],
        "Auth_Weakness": [
            r"(?i)bearer\s+null",
            r"(?i)bearer\s+undefined",
            r"(?i)alg\s*:\s*\"?none\"?"
        ],
        "Mass_Assignment": [
            r"(?i)\"admin\"\s*:\s*true"
        ]
    }

    SQL_ERROR_PATTERNS = [
        r"(?i)SQLAlchemyError",
        r"(?i)SyntaxError.*SQL",
        r"(?i)SQL syntax",
        r"(?i)MySQL server version",
        r"(?i)SQLite3::SQLException",
        r"(?i)ORA-\d{5}",
        r"(?i)PostgreSQL.*ERROR",
        r"(?i)PG::SyntaxError",
        r"(?i)Microsoft OLE DB Provider for SQL Server",
        r"(?i)unclosed quotation mark after the character string"
    ]

    CMD_OUTPUT_PATTERNS = [
        r"root:x:0:0:",
        r"uid=\d+\(.*\)\s+gid=\d+",
        r"Windows\s+IP\s+Configuration"
    ]

    LFI_OUTPUT_PATTERNS = [
        r"root:x:0:0:",
        r"daemon:x:\d+:",
        r"nobody:x:\d+:",
        r"\[boot loader\]"
    ]

    XXE_OUTPUT_PATTERNS = LFI_OUTPUT_PATTERNS + [
        r"(?i)localhost",
        r"(?i)hostname"
    ]

    REQUIRED_SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]

    VERBOSE_ERROR_PATTERNS = [
        r"Traceback \(most recent call last\):",
        r"SyntaxError:",
        r"SQLAlchemyError",
        r"Fatal error:",
        r"Uncaught Exception",
        r"ZeroDivisionError",
        r"NullPointerException"
    ]

    SENSITIVE_DATA_PATTERNS = [
        r"(?i)[\"']?password[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)[\"']?secret_key[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)[\"']?access_token[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)[\"']?api_key[\"']?\s*[:=]\s*[\"'][^\"']+[\"']"
    ]

    def __init__(self, payloads_dir: Optional[str] = None):
        self.payloads_dir = Path(payloads_dir) if payloads_dir else Path(PAYLOADS_DIR)
        self.custom_patterns: Dict[str, List[str]] = self._load_payload_patterns()

    def _load_payload_patterns(self) -> Dict[str, List[str]]:
        patterns = {}
        if not self.payloads_dir.exists():
            return patterns

        for file_name in ["sqli.txt", "xss.txt", "cmd_injection.txt", "bola.txt", "auth.txt"]:
            file_path = self.payloads_dir / file_name
            category = file_name.replace(".txt", "")
            patterns[category] = []
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_clean = line.strip()
                        if line_clean and not line_clean.startswith("#"):
                            patterns[category].append(line_clean)
        return patterns

    @staticmethod
    def _body_difference_ratio(baseline_body: str, response_body: str) -> float:
        baseline = (baseline_body or "").strip()
        current = (response_body or "").strip()
        if not baseline and not current:
            return 0.0
        if not baseline or not current:
            return 1.0

        # Mask dynamic runtime noise (timestamps, UUIDs) to prevent false differential drift
        time_uuid_pattern = r'\b(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b'
        norm_baseline = re.sub(time_uuid_pattern, "NORM_VAR", baseline)
        norm_current = re.sub(time_uuid_pattern, "NORM_VAR", current)

        # Use accurate ratio() on contiguous character sequences rather than quick_ratio() approximation
        similarity = difflib.SequenceMatcher(None, norm_baseline, norm_current).ratio()
        difference_ratio = round(1.0 - similarity, 4)
        return float(difference_ratio)

    def analyze(self, telemetry_data: Dict[str, Any], baseline_telemetry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyzes HTTP telemetry for known attack patterns and enforces strict Proof Verifiers.
        Enforces Hard Circuit-Breaker Gates (status 0, None, 403, 404, 429, 502, 503, 504).
        Returns telemetry proof status, proof description, points, and vulnerability classification.
        """
        url = telemetry_data.get("url", "")
        payload = telemetry_data.get("payload", "") or ""
        resp_status = telemetry_data.get("status_code", 200)
        resp_size = telemetry_data.get("response_size", 0)
        resp_time = telemetry_data.get("response_time", 0.0)
        resp_headers = telemetry_data.get("response_headers", {}) or {}
        resp_body = telemetry_data.get("response_body", "") or ""
        baseline_body = (baseline_telemetry or {}).get("response_body", "") or ""
        retry_after = next((str(value) for key, value in resp_headers.items() if str(key).lower() == "retry-after"), "")

        target_string = f"{url} {payload}"
        content_type = str(resp_headers.get("content-type", "") or resp_headers.get("Content-Type", "")).lower()

        # Hard Response Gate 1: Network / Unreachable / Status 0 or None.
        # If the baseline was healthy and only the active probe disconnected,
        # preserve that differential as a suspected request-impact signal.
        if resp_status in [0, None]:
            baseline_status = (baseline_telemetry or {}).get("status_code")
            baseline_reachable = baseline_status is not None and 200 <= int(baseline_status) < 500 and baseline_status != 404
            if baseline_reachable and payload:
                return {
                    "matched": True,
                    "has_proof": False,
                    "is_vulnerable": False,
                    "attack_type": "Application_Connection_Reset",
                    "pattern_matched": "Active payload caused target connection reset",
                    "finding_status": "Suspected",
                    "confidence": "Low",
                    "points": 10,
                    "proof_of_concept": "Target disconnected during an active probe after a healthy baseline; exploit proof not established",
                    "missing_headers": []
                }
            return {
                "matched": False,
                "has_proof": False,
                "is_vulnerable": False,
                "attack_type": "Network_Error",
                "pattern_matched": "HTTP Status 0 / Network Dropped",
                "finding_status": "UNREACHABLE / NETWORK_DROPPED",
                "confidence": "None",
                "points": 0,
                "proof_of_concept": "HTTP request failed or network connection dropped (Status 0/None)",
                "missing_headers": []
            }

        if telemetry_data.get("frontend_shell_response"):
            return {
                "matched": False,
                "has_proof": False,
                "is_vulnerable": False,
                "attack_type": "None",
                "pattern_matched": "Frontend SPA shell returned for API-path probe",
                "finding_status": "Informational",
                "confidence": "High",
                "points": 0,
                "proof_of_concept": "Payload was not processed by an API; target returned the frontend shell",
                "missing_headers": []
            }

        # Rate-limit observation is useful telemetry but is not a vulnerability proof.
        if retry_after:
            return {
                "matched": True,
                "has_proof": False,
                "is_vulnerable": False,
                "attack_type": "Rate_Limit_Observation",
                "pattern_matched": "HTTP 429 or Retry-After response observed",
                "finding_status": "Informational",
                "confidence": "High",
                "points": 0,
                "proof_of_concept": f"Rate-limit signal observed; HTTP {resp_status}, Retry-After={retry_after or 'absent'}",
                "missing_headers": [],
                "response_diff": {"retry_after": retry_after, "status_changed": False, "body_difference_ratio": 0.0, "size_delta": 0, "time_delta": 0.0}
            }

        # Hard Response Gate 2: WAF Block / Edge Block / 404 Not Found
        if resp_status in [403, 404, 405, 429, 502, 503, 504] or (resp_status == 202 and resp_size == 0):
            status_desc = "Resource Not Found" if resp_status == 404 else "WAF / Edge Block"
            return {
                "matched": False,
                "has_proof": False,
                "is_vulnerable": False,
                "attack_type": "None",
                "pattern_matched": f"HTTP {resp_status} {status_desc}",
                "finding_status": "BLOCKED_OR_NOT_FOUND",
                "confidence": "None",
                "points": 0,
                "proof_of_concept": f"HTTP {resp_status} {status_desc} - Request blocked or endpoint non-existent",
                "missing_headers": []
            }

        # Check payload syntax matches for injection candidate categories
        candidate_category = None
        candidate_rule = ""
        auth_header_val = telemetry_data.get("request_headers", {}).get("Authorization", "")
        combined_probe_text = f"{target_string} {auth_header_val}"

        expected_category = telemetry_data.get("attack_category")
        if telemetry_data.get("cross_identity_probe"):
            candidate_category = "BOLA_IDOR"
            candidate_rule = "marker-backed probe"
        elif telemetry_data.get("mass_assignment_probe"):
            candidate_category = "Mass_Assignment"
            candidate_rule = "marker-backed probe"
        else:
            if expected_category == "SQL_Injection_Credential":
                expected_category = "SQL_Injection"
            categories = [expected_category] if expected_category in self.REGEX_RULES else []
            categories += [category for category in ["SQL_Injection", "XSS", "Command_Injection", "Local_File_Inclusion", "XXE", "GraphQL_Introspection", "Open_Redirect", "Auth_Weakness", "BOLA_IDOR"] if category != expected_category]
            for category in categories:
                rules = self.REGEX_RULES.get(category, [])
                for rule in rules:
                    probe_match = re.search(rule, payload) if category == "Open_Redirect" else (re.search(rule, payload) or re.search(rule, combined_probe_text))
                    if probe_match:
                        candidate_category = category
                        candidate_rule = rule
                        break
                if candidate_category:
                    break

        has_proof = False
        proof_of_concept = ""
        matched = False
        attack_type = "None"
        pattern_matched = ""
        finding_status = "Informational"
        confidence = "Low"
        points = 0

        # Baseline Differential Comparison
        baseline_time = baseline_telemetry.get("response_time", 0.0) if baseline_telemetry else 0.0
        baseline_size = baseline_telemetry.get("response_size", 0) if baseline_telemetry else 0
        baseline_status = baseline_telemetry.get("status_code", 200) if baseline_telemetry else 200

        time_delta = max(0.0, resp_time - baseline_time)
        size_delta = resp_size - baseline_size
        body_difference_ratio = self._body_difference_ratio(baseline_body, resp_body)
        status_changed = resp_status != baseline_status
        differential_signal = bool(baseline_telemetry) and (status_changed or abs(size_delta) >= 64 or body_difference_ratio >= 0.25)

        # Strict Proof Verifiers Criteria (Section 3)
        if candidate_category:
            attack_type = candidate_category
            pattern_matched = candidate_rule

            if candidate_category == "XSS":
                # Verbatim unescaped Reflection check in text/html or application/xml
                is_html_xml = any(ct in content_type for ct in ["text/html", "application/xml"])
                if payload and payload in resp_body and is_html_xml and resp_size > 0 and resp_status == 200:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Unescaped string reflection detected in {content_type} body"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Payload syntax matched but missing verbatim HTML/XML unescaped reflection"

            elif candidate_category == "SQL_Injection":
                # Error-based SQL trace verification OR Time-based SQLi (time_delta > 3.0s)
                matched_sql_err = next((err for err in self.SQL_ERROR_PATTERNS if re.search(err, resp_body)), None)
                if matched_sql_err:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"SQL Error signature matched: {matched_sql_err}"
                elif time_delta > 3.0 and re.search(r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", payload):
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Time-based SQLi response delay detected for an explicit delay payload: {time_delta:.2f}s > 3.00s"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Medium" if differential_signal else "Low"
                    points = 15 if differential_signal else 10
                    if differential_signal:
                        proof_of_concept = (
                            "SQL parameter payload caused a differential response without database-error or timing proof: "
                            f"status_changed={status_changed}, size_delta={size_delta}, "
                            f"body_difference_ratio={body_difference_ratio:.4f}"
                        )
                    else:
                        proof_of_concept = "SQL parameter payload syntax matched without database error, differential response, or execution time delay"

            elif candidate_category == "GraphQL_Introspection":
                matched_graphql = bool(re.search(r'(?i)"__schema"|"queryType"|"__typename"', resp_body))
                if matched_graphql and resp_status in {200, 400} and resp_size > 0:
                    matched = True
                    has_proof = False
                    finding_status = "Informational"
                    confidence = "High"
                    points = 0
                    proof_of_concept = "GraphQL introspection response exposed schema metadata"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "GraphQL endpoint accepted an introspection probe without schema proof"

            elif candidate_category == "Open_Redirect":
                location = next((str(value) for key, value in resp_headers.items() if str(key).lower() == "location"), "")
                resolved_location = urlsplit(urljoin(url, location)) if location else None
                base_location = urlsplit(url)
                # Reverse proxies and canonical URL handlers may redirect between
                # schemes or ports on the same host. Treat those as same-site
                # canonicalization, not proof of an unvalidated external redirect.
                resolved_hostname = (resolved_location.hostname or "").lower() if resolved_location else ""
                base_hostname = (base_location.hostname or "").lower()
                is_external = bool(resolved_hostname and resolved_hostname != base_hostname)
                if 300 <= int(resp_status or 0) < 400 and is_external:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"External redirect confirmed via Location header: {location}"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Redirect payload matched without an external 3xx Location response"

            elif candidate_category == "XXE":
                matched_xxe_sig = next((pattern for pattern in self.XXE_OUTPUT_PATTERNS if re.search(pattern, resp_body)), None)
                is_xml_probe = bool(re.search(r"(?is)<!DOCTYPE[^>]+(?:<!ENTITY|SYSTEM)", payload)) and "xml" in content_type
                if matched_xxe_sig and is_xml_probe and resp_status == 200 and resp_size > 0:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"XML external entity expansion marker matched: {matched_xxe_sig}"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "XXE entity syntax matched without XML content type and local canary proof"

            elif candidate_category == "Local_File_Inclusion":
                matched_lfi_sig = next((pattern for pattern in self.LFI_OUTPUT_PATTERNS if re.search(pattern, resp_body)), None)
                if matched_lfi_sig and resp_status == 200 and resp_size > 0:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Local file content signature matched: {matched_lfi_sig}"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "File traversal syntax matched without known local-file content"

            elif candidate_category == "Command_Injection":
                # Shell output signature OR Time-based delay > 3.0s
                matched_cmd_sig = next((cmd_pat for cmd_pat in self.CMD_OUTPUT_PATTERNS if re.search(cmd_pat, resp_body)), None)
                if matched_cmd_sig:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Command execution signature matched: {matched_cmd_sig}"
                elif time_delta > 3.0:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Time-based Command Injection delay detected: {time_delta:.2f}s > 3.00s"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Command payload syntax matched without shell output or execution delay"

            elif candidate_category == "Auth_Weakness":
                auth_hdr = telemetry_data.get("request_headers", {}).get("Authorization", "")
                is_jwt_alg_none = bool(re.search(r"(?i)alg\s*:\s*\"?none\"?", target_string))
                has_sensitive_data = any(re.search(pat, resp_body, re.I) for pat in [r"\"email\":", r"\"password\":", r"\"admin\":", r"\"token\":"])
                if (resp_status in [200, 201] and (has_sensitive_data or not auth_hdr or is_jwt_alg_none)):
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = "Unauthenticated access or invalid auth token returned sensitive resource telemetry"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Unverified auth parameter payload"

            elif candidate_category == "BOLA_IDOR":
                if telemetry_data.get("cross_identity_probe") and resp_status in [200, 204]:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 45
                    proof_of_concept = "Authenticated as one user, successfully mutated a different user's object via path parameter - object ownership was never checked"
                else:
                    auth_header = telemetry_data.get("request_headers", {}).get("Authorization", "")
                    has_sensitive_data = any(re.search(pat, resp_body, re.I) for pat in [r"\"email\":", r"\"ssn\":", r"\"password\":", r"\"role\":", r"\"token\":", r"\"username\":"])
                    if resp_status in [200, 201] and has_sensitive_data and not auth_header:
                        matched = True
                        has_proof = True
                        finding_status = "Confirmed"
                        confidence = "High"
                        points = 40
                        proof_of_concept = "Unauthorized object access returned sensitive object properties in 200 OK body"
                    else:
                        matched = True
                        has_proof = False
                        finding_status = "Suspected"
                        confidence = "Low"
                        points = 10
                        proof_of_concept = "Object ID path queried without confirmed sensitive object disclosure"

            elif candidate_category == "Mass_Assignment":
                if telemetry_data.get("mass_assignment_probe") and resp_status in [200, 204]:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 45
                    proof_of_concept = (
                        "Registered a new account with an unexpected 'admin' field in the request body; "
                        "the server accepted it, and the resulting account was later able to perform an "
                        "admin-only action, proving unauthorized privilege escalation"
                    )
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Extra field submitted in write request without confirmed privilege change"

        # BOLA / IDOR Proof Verification (fallback)
        if not matched and resp_status in [200, 201]:
            has_bola_pattern = any(re.search(r, combined_probe_text) for r in self.REGEX_RULES["BOLA_IDOR"])
            auth_header = telemetry_data.get("request_headers", {}).get("Authorization", "")
            has_sensitive_data = any(re.search(pat, resp_body, re.I) for pat in [r"\"email\":", r"\"ssn\":", r"\"password\":", r"\"role\":", r"\"token\":", r"\"username\":"])

            if has_bola_pattern and has_sensitive_data and not auth_header:
                matched = True
                has_proof = True
                attack_type = "BOLA_IDOR"
                pattern_matched = "Unauthenticated object access returned sensitive user data"
                finding_status = "Confirmed"
                confidence = "High"
                points = 40
                proof_of_concept = "Unauthorized object access returned sensitive object properties in 200 OK body"

        # Verbose Stack Traces Verification
        if not matched and resp_status not in [404, 401, 403, 405, 429, 502, 503, 504]:
            for err_pat in self.VERBOSE_ERROR_PATTERNS:
                if re.search(err_pat, resp_body):
                    matched = True
                    has_proof = True
                    attack_type = "Verbose_Error_Exposure"
                    pattern_matched = err_pat
                    finding_status = "Confirmed"
                    confidence = "Medium"
                    points = 25
                    proof_of_concept = f"Verbose stack trace trace exposed in response: {err_pat}"
                    break

        # Sensitive Data Exposure Verification
        if not matched and resp_status not in [404, 401, 403, 405, 429, 502, 503, 504]:
            for sens_pat in self.SENSITIVE_DATA_PATTERNS:
                if re.search(sens_pat, resp_body):
                    matched = True
                    has_proof = True
                    attack_type = "Sensitive_Data_Exposure"
                    pattern_matched = sens_pat
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 35
                    proof_of_concept = f"Sensitive credentials exposed in response: {sens_pat}"
                    break

        # Passive CORS policy check. This is informational and never a confirmed exploit.
        allow_origin = next((str(value).strip() for key, value in resp_headers.items() if str(key).lower() == "access-control-allow-origin"), "")
        allow_credentials = next((str(value).strip().lower() for key, value in resp_headers.items() if str(key).lower() == "access-control-allow-credentials"), "")
        if not matched and allow_origin == "*" and allow_credentials == "true":
            matched = True
            has_proof = False
            attack_type = "CORS_Misconfiguration"
            pattern_matched = "Access-Control-Allow-Origin: * with credentials enabled"
            finding_status = "Informational"
            confidence = "High"
            points = 0
            proof_of_concept = "Permissive cross-origin policy allows any origin while credentials are enabled; browser exploitability requires origin and cookie-context verification"

        # Missing Security Headers Check
        missing_headers = []
        resp_headers_lower = {k.lower(): v for k, v in resp_headers.items()}
        for req_h in self.REQUIRED_SECURITY_HEADERS:
            if req_h.lower() not in resp_headers_lower:
                missing_headers.append(req_h)

        if not matched and missing_headers and resp_status not in [404, 401, 403, 405, 406, 429, 502, 503, 504] and not (500 <= int(resp_status or 0) < 600):
            matched = True
            has_proof = False  # Header misconfigurations do not constitute injection exploit proof
            attack_type = "Security_Misconfiguration"
            pattern_matched = f"Missing headers: {', '.join(missing_headers)}"
            finding_status = "Informational"
            confidence = "Low"
            points = 10
            proof_of_concept = f"Missing security headers: {', '.join(missing_headers)}"

        return {
            "matched": matched,
            "has_proof": has_proof,
            "is_vulnerable": has_proof and points > 0,
            "attack_type": attack_type,
            "pattern_matched": pattern_matched,
            "finding_status": finding_status,
            "confidence": confidence,
            "points": min(points, 45),
            "proof_of_concept": proof_of_concept or ("No vulnerability proof criteria met" if not has_proof else "Vulnerability proof verified"),
            "missing_headers": missing_headers,
            "cors_policy": {"allow_origin": allow_origin, "allow_credentials": allow_credentials},
            "response_diff": {
                "retry_after": retry_after,
                "status_changed": status_changed,
                "body_difference_ratio": body_difference_ratio,
                "size_delta": size_delta,
                "time_delta": round(time_delta, 4),
                "differential_signal": differential_signal,
            }
        }


if __name__ == "__main__":
    detector = SignatureDetector()
    sample_data = {
        "url": "http://localhost:5000/api/users?id=1' OR 1=1 --",
        "payload": "",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"error\":\"SQLAlchemyError: syntax error at or near OR\"}"
    }
    result = detector.analyze(sample_data)
    print("\n[+] Confirmed Response Verification Test Result:")
    for k, v in result.items():
        print(f"  {k}: {v}")
