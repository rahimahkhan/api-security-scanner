import os
import sys
from datetime import datetime
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger

class RiskScorer:
    """
    Risk Scoring Engine
    Combines point contributions from Layer 1 (Signature), Layer 2 (Isolation Forest ML),
    and Layer 3 (PyTorch LSTM + Autoencoder DL), normalizes the score to 0-100, and assigns severity.
    """

    MAX_SIG_POINTS = 40.0
    MAX_ML_POINTS = 25.0
    MAX_LSTM_POINTS = 15.0
    MAX_AE_POINTS = 20.0
    MAX_SUPERVISED_POINTS = 10.0
    MAX_TOTAL_POINTS = 100.0

    SEVERITY_RECOMMENDATIONS = {
        "Low": "Baseline telemetry parameters normal. Maintain routine security monitoring and header hardening.",
        "Medium": "Elevated structural anomaly or header misconfiguration detected. Audit API endpoint input parameters.",
        "High": "Significant anomaly or signature match detected. Review input validation and database query parameterization.",
        "Critical": "Critical attack pattern detected across multiple engine layers. Immediately enforce WAF filtering and remediate underlying endpoint code."
    }

    @staticmethod
    def classify_severity(score: float) -> str:
        if score >= 70.0:
            return "CRITICAL"
        elif score >= 40.0:
            return "HIGH"
        elif score >= 15.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "NONE"

    @staticmethod
    def calculate_hybrid_confidence(sig_matched: bool, ml_is_anomaly: bool, dl_is_suspicious: bool):
        layers_triggered = sum([
            1 if sig_matched else 0,
            1 if ml_is_anomaly else 0,
            1 if dl_is_suspicious else 0
        ])

        if layers_triggered == 3:
            return 1.0, layers_triggered    # All three agree - high conf
        elif layers_triggered == 2:
            return 0.75, layers_triggered   # Two agree - medium conf
        elif layers_triggered == 1:
            return 0.35, layers_triggered   # Only one - low confidence
        else:
            return 0.0, layers_triggered    # Nothing detected

    def calculate_risk(
        self,
        signature_result: Dict[str, Any],
        ml_result: Dict[str, Any],
        dl_result: Dict[str, Any],
        endpoint_url: str = "",
        http_method: str = "GET",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Calculates combined risk score from all 3 detection layers using Hybrid Confidence Multiplier.
        A finding is only HIGH or CRITICAL when at least 2 layers agree, and
        CRITICAL is reserved for findings with verified exploit proof —
        suspected (unproven) findings are capped at HIGH.
        """
        telemetry = kwargs.get("telemetry_data", {}) or {}
        resp_status = telemetry.get("status_code", kwargs.get("status_code", 200))
        resp_size = telemetry.get("response_size", kwargs.get("response_size", 0))
        resp_time = telemetry.get("response_time", kwargs.get("response_time", 0.0))

        # Section 1: Hard Response Gate (Circuit Breaker)
        # Status 0/None (connection dropped) or our synthetic 408 (probe timed out
        # with no usable response) -> UNREACHABLE / NETWORK_DROPPED, scored 0.
        # Timeouts must never become findings: there is no response to analyze.
        if resp_status in [0, None, 408]:
            timestamp = datetime.utcnow().isoformat() + "Z"
            proof = ("Probe request timed out with no usable response (HTTP 408); "
                     "target unreachable or network stalled") if resp_status == 408 else \
                    "HTTP request failed or network connection dropped (Status 0/None)"
            return {
                "endpoint": endpoint_url,
                "method": http_method.upper(),
                "timestamp": timestamp,
                "is_vulnerable": False,
                "total_score": 0.0,
                "risk_score": 0.0,
                "severity": "NONE",
                "finding_status": "UNREACHABLE / NETWORK_DROPPED",
                "confidence_level": 0,
                "layers_triggered": 0,
                "confidence_multiplier": 0.0,
                "proof_of_concept": proof,
                "telemetry_status": {
                    "status_code": resp_status,
                    "response_size": resp_size,
                    "response_time": resp_time
                },
                "points_breakdown": {
                    "signature_points": 0.0,
                    "ml_points": 0.0,
                    "lstm_points": 0.0,
                    "autoencoder_points": 0.0,
                    "supervised_points": 0.0,
                    "raw_total_points": 0.0
                },
                "signature_result": signature_result,
                "ml_result": ml_result,
                "dl_result": dl_result,
                "recommendation": self.SEVERITY_RECOMMENDATIONS["Low"]
            }

        # Status 403, 404, 429, 502, 503, 504 -> BLOCKED_OR_NOT_FOUND
        if resp_status in [403, 404, 429, 502, 503, 504] or (resp_status == 202 and resp_size == 0):
            timestamp = datetime.utcnow().isoformat() + "Z"
            status_desc = "Resource Not Found" if resp_status == 404 else "WAF / Edge Block"
            return {
                "endpoint": endpoint_url,
                "method": http_method.upper(),
                "timestamp": timestamp,
                "is_vulnerable": False,
                "total_score": 0.0,
                "risk_score": 0.0,
                "severity": "NONE",
                "finding_status": "BLOCKED_OR_NOT_FOUND",
                "confidence_level": 0,
                "layers_triggered": 0,
                "confidence_multiplier": 0.0,
                "proof_of_concept": f"HTTP {resp_status} {status_desc} - Request dropped or endpoint non-existent",
                "telemetry_status": {
                    "status_code": resp_status,
                    "response_size": resp_size,
                    "response_time": resp_time
                },
                "points_breakdown": {
                    "signature_points": 0.0,
                    "ml_points": 0.0,
                    "lstm_points": 0.0,
                    "autoencoder_points": 0.0,
                    "supervised_points": 0.0,
                    "raw_total_points": 0.0
                },
                "signature_result": signature_result,
                "ml_result": ml_result,
                "dl_result": dl_result,
                "recommendation": self.SEVERITY_RECOMMENDATIONS["Low"]
            }

        # Section 4: Layer Point Calculations
        ml_points = min(float(ml_result.get("points", 0.0)), self.MAX_ML_POINTS)
        lstm_points = min(float(dl_result.get("lstm_points", 0.0)), self.MAX_LSTM_POINTS)
        ae_points = min(float(dl_result.get("autoencoder_points", 0.0)), self.MAX_AE_POINTS)
        supervised_points = min(float(ml_result.get("supervised_points", 0.0)), self.MAX_SUPERVISED_POINTS)

        # Triggered Layer Conditions. A signature match is a detection signal;
        # proof is a stricter condition that is required before declaring a
        # vulnerability. Keeping these concepts separate prevents suspected
        # payload matches from being reported as confirmed findings.
        signature_triggered = bool(signature_result.get("matched", False) or signature_result.get("is_vulnerable", False))
        has_proof = bool(signature_result.get("has_proof", False) or signature_result.get("is_vulnerable", False))
        sig_points_raw = float(signature_result.get("points", 0.0))
        sig_points = min(sig_points_raw, self.MAX_SIG_POINTS) if signature_triggered else 0.0

        ml_is_anomaly = bool(ml_result.get("is_anomaly", False) or ml_points >= 10.0)
        dl_is_suspicious = bool(dl_result.get("is_anomaly", False) or (lstm_points + ae_points) >= 10.0 or dl_result.get("lstm_probability", 0.0) > 0.5)

        # Deterministic proof is stronger evidence than statistical consensus.
        # Keep hybrid confidence for anomaly-only findings, but never discount
        # a confirmed response proof because fewer anomaly layers agreed.
        layers_triggered = sum([
            1 if signature_triggered else 0,
            1 if ml_is_anomaly else 0,
            1 if dl_is_suspicious else 0
        ])
        if has_proof:
            confidence, layers_triggered = 1.0, max(layers_triggered, 1)
        else:
            confidence, layers_triggered = self.calculate_hybrid_confidence(signature_triggered, ml_is_anomaly, dl_is_suspicious)

        # Calculate combined total score with confidence weighting
        raw_total = sig_points + ml_points + lstm_points + ae_points + supervised_points
        final_risk_score = round(max(0.0, min(self.MAX_TOTAL_POINTS, raw_total * confidence)), 2)
        severity = self.classify_severity(final_risk_score)

        # Severity must reflect proof, not just anomaly strength. A strong
        # multi-layer anomaly score without verified exploit proof is a
        # lead, not an incident — cap suspected findings at HIGH and
        # reserve CRITICAL for confirmed vulnerabilities.
        if not has_proof and severity == "CRITICAL":
            severity = "HIGH"

        # A high anomaly score is useful for triage, but it is not exploit
        # proof. Only a verified response indicator is a vulnerability.
        is_vulnerable = has_proof
        if has_proof:
            finding_status = "Confirmed"
        elif final_risk_score > 0.0:
            finding_status = "Suspected"
        else:
            finding_status = "Informational"

        rec_key = severity.capitalize() if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else "Low"
        recommendation = self.SEVERITY_RECOMMENDATIONS.get(rec_key, self.SEVERITY_RECOMMENDATIONS["Low"])
        timestamp = datetime.utcnow().isoformat() + "Z"

        proof_poc = ""
        if has_proof:
            proof_poc = signature_result.get("proof_of_concept", "") or "Vulnerability signature verified with active response indicators"
        elif signature_triggered:
            proof_poc = signature_result.get("proof_of_concept", "") or signature_result.get("pattern_matched", "Signature matched without proof")
        elif final_risk_score > 0.0:
            proof_poc = f"Multi-layer anomaly score ({final_risk_score}/100) triggered by {layers_triggered}/3 detection layers; exploit proof not established"
        else:
            proof_poc = "No vulnerability or anomaly criteria met"

        result_summary = {
            "endpoint": endpoint_url,
            "method": http_method.upper(),
            "timestamp": timestamp,
            "is_vulnerable": is_vulnerable,
            "total_score": final_risk_score,
            "risk_score": final_risk_score,
            "severity": severity,
            "confidence_level": layers_triggered,
            "layers_triggered": layers_triggered,
            "confidence_multiplier": confidence,
            "finding_status": finding_status,
            "proof_of_concept": proof_poc,
            "telemetry_status": {
                "status_code": resp_status,
                "response_size": resp_size,
                "response_time": resp_time
            },
            "points_breakdown": {
                "signature_points": sig_points,
                "ml_points": ml_points,
                "lstm_points": lstm_points,
                "autoencoder_points": ae_points,
                "supervised_points": supervised_points,
                "raw_total_points": raw_total,
                "confidence_multiplier": confidence
            },
            "signature_result": signature_result,
            "ml_result": ml_result,
            "dl_result": dl_result,
            "recommendation": recommendation
        }

        logger.info(f"Risk Evaluation [{http_method}] {endpoint_url} -> Score: {final_risk_score}/100 ({severity}) [Proof: {is_vulnerable}]")
        return result_summary


if __name__ == "__main__":
    scorer = RiskScorer()

    mock_sig = {"matched": True, "attack_type": "SQL_Injection", "points": 90, "pattern_matched": "1=1"}
    mock_ml = {"is_anomaly": True, "anomaly_score": 0.65, "points": 26.0}
    mock_dl = {"lstm_probability": 0.85, "lstm_points": 25.5, "autoencoder_points": 18.0}

    res = scorer.calculate_risk(mock_sig, mock_ml, mock_dl, "http://localhost:5000/api/users", "GET")
    print("\n[+] Risk Scorer Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
