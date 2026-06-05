from typing import Tuple

from utils.config import CRITICALITY_WEIGHTS, SEVERITY_BANDS
from utils.constants import (
    DETECTION_FAILED_LOGIN_BURST,
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
)
from utils.schema import Incident


def calculate_criticality(incident: Incident) -> Tuple[float, str]:
    """Compute a criticality score and severity label for an incident.

    The score is a weighted sum based on which detection types are present
    and whether IDS alert evidence exists.
    """
    score = 0.0
    detection_types = {d.detection_type for d in incident.detections}

    if DETECTION_FAILED_LOGIN_BURST in detection_types:
        score += CRITICALITY_WEIGHTS["failed_login_burst"]
    if DETECTION_SUCCESS_AFTER_FAILURES in detection_types:
        score += CRITICALITY_WEIGHTS["success_after_failures"]
    if DETECTION_SUSPICIOUS_OUTBOUND in detection_types:
        score += CRITICALITY_WEIGHTS["suspicious_outbound"]

    has_ids = incident.metadata.get("has_ids_alert", False)
    if has_ids:
        score += CRITICALITY_WEIGHTS["ids_alert_boost"]

    avg_confidence = (
        sum(d.confidence for d in incident.detections) / len(incident.detections)
        if incident.detections
        else 0.5
    )
    score *= avg_confidence

    score = min(max(score, 0), 100)
    severity = _score_to_severity(score)

    return round(score, 1), severity


def _score_to_severity(score: float) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score < high:
            return label
    return "critical"
