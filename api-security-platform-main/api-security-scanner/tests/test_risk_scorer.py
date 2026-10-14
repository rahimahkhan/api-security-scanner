import pytest
from detection.risk_scorer import RiskScorer

def test_risk_scorer_calculations():
    scorer = RiskScorer()
    
    mock_sig = {"matched": True, "has_proof": True, "attack_type": "SQL_Injection", "points": 40.0, "finding_status": "Confirmed"}
    mock_ml = {"is_anomaly": True, "anomaly_score": 0.5, "points": 12.5}
    mock_dl = {"lstm_probability": 0.5, "lstm_points": 7.5, "autoencoder_points": 10.0}

    res = scorer.calculate_risk(mock_sig, mock_ml, mock_dl, "http://localhost/api", "GET")
    
    assert res["total_score"] == 100.0  # 70 raw + 30 verified-proof bonus, capped at 100
    assert res["severity"] == "CRITICAL"
    assert res["confidence_level"] == 3
    assert res["finding_status"] == "Confirmed"
    assert "recommendation" in res

def test_risk_scorer_layer_caps_and_boundaries():
    scorer = RiskScorer()

    # Enforce layer caps (Sig=40, ML=25, LSTM=15, AE=20, Total=100)
    mock_sig_over = {"matched": True, "has_proof": True, "points": 90.0, "finding_status": "Confirmed"}
    mock_ml_over = {"is_anomaly": True, "points": 50.0}
    mock_dl_over = {"lstm_points": 30.0, "autoencoder_points": 40.0}

    res_cap = scorer.calculate_risk(mock_sig_over, mock_ml_over, mock_dl_over)
    assert res_cap["points_breakdown"]["signature_points"] == 40.0
    assert res_cap["points_breakdown"]["ml_points"] == 25.0
    assert res_cap["points_breakdown"]["lstm_points"] == 15.0
    assert res_cap["points_breakdown"]["autoencoder_points"] == 20.0
    assert res_cap["total_score"] == 100.0
    assert res_cap["severity"] == "CRITICAL"

    # Updated severity boundaries: 0=NONE, 0-15=LOW, 15-39=MEDIUM, 40-69=HIGH, 70+=CRITICAL
    assert RiskScorer.classify_severity(0.0) == "NONE"
    assert RiskScorer.classify_severity(14.0) == "LOW"
    assert RiskScorer.classify_severity(15.0) == "MEDIUM"
    assert RiskScorer.classify_severity(39.0) == "MEDIUM"
    assert RiskScorer.classify_severity(40.0) == "HIGH"
    assert RiskScorer.classify_severity(69.0) == "HIGH"
    assert RiskScorer.classify_severity(70.0) == "CRITICAL"

def test_ml_dl_independent_contribution_and_zero_baseline():
    scorer = RiskScorer()
    
    # 1. Clean request with zero signature/ML/DL points -> Total score 0.0
    clean_sig = {"matched": False, "has_proof": False, "attack_type": "None", "points": 0.0}
    clean_ml = {"is_anomaly": False, "points": 0.0}
    clean_dl = {"lstm_points": 0.0, "autoencoder_points": 0.0}

    res_clean = scorer.calculate_risk(clean_sig, clean_ml, clean_dl, "http://localhost/api", "GET")
    assert res_clean["total_score"] == 0.0
    assert res_clean["severity"] == "NONE"
    assert res_clean["is_vulnerable"] is False

    # 2. Signature has no proof, ML + DL detect anomalies -> 2 layers -> conf=0.75 -> Score = (12.5 + 7.5 + 10) * 0.75 = 22.5
    mock_sig_no_proof = {"matched": False, "has_proof": False, "attack_type": "SQL_Injection", "points": 40.0}
    mock_ml = {"is_anomaly": True, "points": 12.5}
    mock_dl = {"lstm_points": 7.5, "autoencoder_points": 10.0}

    res_anom = scorer.calculate_risk(mock_sig_no_proof, mock_ml, mock_dl, "http://localhost/api", "GET")
    assert res_anom["total_score"] == 22.5
    assert res_anom["severity"] == "MEDIUM"
    assert res_anom["confidence_level"] == 2


def test_confirmed_proof_gets_full_confidence_without_layer_agreement():
    scorer = RiskScorer()
    result = scorer.calculate_risk(
        {"matched": True, "has_proof": True, "points": 40.0, "finding_status": "Confirmed"},
        {"is_anomaly": False, "points": 0.0},
        {"lstm_points": 0.0, "autoencoder_points": 0.0}
    )

    assert result["confidence_multiplier"] == 1.0
    assert result["layers_triggered"] == 1
    # Verified proof carries a +30 bonus: a lone confirmed signature (40)
    # reaches 70 = CRITICAL, per "CRITICAL is reserved for verified proof".
    assert result["total_score"] == 70.0
    assert result["severity"] == "CRITICAL"
    assert result["finding_status"] == "Confirmed"


def test_suspected_findings_capped_below_critical():
    """A strong multi-layer anomaly WITHOUT exploit proof is capped at HIGH;
    CRITICAL is reserved for confirmed (proof-backed) findings."""
    scorer = RiskScorer()
    mock_sig = {"matched": True, "has_proof": False, "attack_type": "XSS", "points": 40.0}
    mock_ml = {"is_anomaly": True, "points": 20.0}
    mock_dl = {"is_anomaly": True, "lstm_points": 15.0, "autoencoder_points": 20.0}

    res = scorer.calculate_risk(
        mock_sig, mock_ml, mock_dl, "http://localhost/api", "GET",
        telemetry_data={"status_code": 200, "response_size": 100, "response_time": 0.1},
    )
    assert res["total_score"] >= 70.0  # raw strength would be CRITICAL
    assert res["severity"] == "HIGH"   # ...but proof-gating caps it
    assert res["is_vulnerable"] is False
    assert res["finding_status"] == "Suspected"

    # With proof, CRITICAL is allowed.
    mock_sig["has_proof"] = True
    res_confirmed = scorer.calculate_risk(
        mock_sig, mock_ml, mock_dl, "http://localhost/api", "GET",
        telemetry_data={"status_code": 200, "response_size": 100, "response_time": 0.1},
    )
    assert res_confirmed["severity"] == "CRITICAL"
    assert res_confirmed["finding_status"] == "Confirmed"


def test_passive_informational_note_stays_informational():
    """D3: the signature layer labels missing security headers as
    Informational (a hygiene note, no exploit proof). ML/DL anomaly points
    still contribute to the numeric score, but the status must not be
    promoted to Suspected — status is what vulnerability counts are
    driven by."""
    scorer = RiskScorer()
    sig = {
        "matched": True,
        "has_proof": False,
        "is_vulnerable": False,
        "attack_type": "Security_Misconfiguration",
        "points": 10.0,
        "finding_status": "Informational",
        "pattern_matched": "Missing headers: X-Content-Type-Options",
    }
    # ML sees an anomaly in the same response; DL contributes nothing.
    ml = {"is_anomaly": True, "points": 20.0, "supervised_points": 5.0}
    dl = {"lstm_points": 0.0, "autoencoder_points": 0.0}
    res = scorer.calculate_risk(
        sig, ml, dl, "http://localhost/api", "GET",
        telemetry_data={"status_code": 200, "response_size": 500, "response_time": 0.2},
    )
    assert res["total_score"] > 0.0       # numeric signal preserved for triage
    assert res["finding_status"] == "Informational"
    assert res["is_vulnerable"] is False
    # And the counting layer must not register it as a vulnerability.
    from dashboard.results_grouping import summarize_findings
    s = summarize_findings([{
        "url": "http://localhost/api", "method": "GET",
        "attack_type": "Security_Misconfiguration",
        "severity": res["severity"], "finding_status": res["finding_status"],
        "risk_score": res["risk_score"],
    }])
    assert s["vulnerabilities"] == 0
    assert s["informational"] == 1


def test_signature_suspected_without_match_still_suspected():
    """Sanity on the D3 boundary: a pure ML anomaly lead with NO signature
    match (signature status absent) keeps the intended Suspected status —
    only signature-labeled Informational notes are pinned down."""
    scorer = RiskScorer()
    res = scorer.calculate_risk(
        {"matched": False, "has_proof": False, "points": 0.0},
        {"is_anomaly": True, "points": 22.0},
        {"lstm_points": 0.0, "autoencoder_points": 0.0},
        "http://localhost/api", "GET",
        telemetry_data={"status_code": 200, "response_size": 500, "response_time": 0.2},
    )
    assert res["finding_status"] == "Suspected"


def test_confirmed_note_not_pinned_to_informational():
    """A signature-labeled Confirmed/Informational-with-proof edge case:
    proof always wins over the Informational pin."""
    scorer = RiskScorer()
    res = scorer.calculate_risk(
        {"matched": True, "has_proof": True, "points": 40.0,
         "finding_status": "Informational"},  # weird but possible input
        {"is_anomaly": False, "points": 0.0},
        {"lstm_points": 0.0, "autoencoder_points": 0.0},
        "http://localhost/api", "GET",
        telemetry_data={"status_code": 200, "response_size": 500, "response_time": 0.2},
    )
    assert res["finding_status"] == "Confirmed"
