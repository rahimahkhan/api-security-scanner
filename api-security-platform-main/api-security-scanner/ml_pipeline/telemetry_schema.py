"""Schema and labeling helpers for proof-verified scanner telemetry."""
from __future__ import annotations

from typing import Any, Dict, Optional

VALID_LABELS = {
    "confirmed",
    "not_vulnerable",
    "blocked",
    "suspected",
    "network_error",
    "not_applicable",
}


def label_from_result(
    finding_status: Optional[str],
    has_proof: bool = False,
    response_status: Optional[int] = None,
) -> str:
    """Map scanner evidence to a conservative training label.

    A suspicious payload is never labeled as confirmed without proof. This
    keeps the training target aligned with the scanner's manual-verification
    standard.
    """
    status = (finding_status or "").strip().lower()
    if has_proof or status == "confirmed":
        return "confirmed"
    if response_status in {0, None} or "network" in status or "unreachable" in status:
        return "network_error"
    if response_status in {401, 403, 404, 429, 502, 503, 504} or "blocked" in status:
        return "blocked"
    if status in {"suspected", "suspicious", "anomaly"}:
        return "suspected"
    if status in {"not_applicable", "n/a"}:
        return "not_applicable"
    return "not_vulnerable"


def build_telemetry_record(
    feature_dict: Dict[str, Any],
    *,
    finding_status: Optional[str] = None,
    has_proof: bool = False,
    response_status: Optional[int] = None,
    attack_type: str = "None",
    target_id: str = "",
    endpoint_id: str = "",
    payload_family: str = "",
) -> Dict[str, Any]:
    """Build a serializable training row from measured scanner telemetry."""
    label_name = label_from_result(finding_status, has_proof, response_status)
    row = dict(feature_dict)
    row.update(
        {
            "target_id": target_id,
            "endpoint_id": endpoint_id,
            "payload_family": payload_family,
            "attack_type": attack_type,
            "finding_status": finding_status or "",
            "has_proof": bool(has_proof),
            "label_name": label_name,
            "label": 1 if label_name == "confirmed" else 0,
        }
    )
    return row
