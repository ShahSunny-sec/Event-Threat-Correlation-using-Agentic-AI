from typing import List, Tuple

from utils.constants import (
    DETECTION_FAILED_LOGIN_BURST,
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
)
from utils.schema import Incident


def generate_recommendations(incident: Incident) -> Tuple[List[str], List[str]]:
    """Generate recommended containment actions and next steps for an incident."""
    actions: List[str] = []
    next_steps: List[str] = []
    detection_types = {d.detection_type for d in incident.detections}

    if DETECTION_FAILED_LOGIN_BURST in detection_types:
        actions.append(
            f"Temporarily lock or monitor account '{incident.affected_user}' for further brute force activity."
        )
        actions.append(
            f"Block or rate-limit source IP {incident.primary_src_ip} at the firewall."
        )
        next_steps.append("Review authentication logs for additional compromised accounts from the same source.")

    if DETECTION_SUCCESS_AFTER_FAILURES in detection_types:
        actions.append(
            f"Force password reset for user '{incident.affected_user}'."
        )
        actions.append(
            f"Audit recent activity by '{incident.affected_user}' on host '{incident.affected_host}'."
        )
        next_steps.append("Check for privilege escalation or lateral movement originating from this session.")

    if DETECTION_SUSPICIOUS_OUTBOUND in detection_types:
        actions.append(
            f"Block outbound traffic to {incident.primary_dst_ip} at the network perimeter."
        )
        actions.append(
            f"Isolate host '{incident.affected_host}' for forensic analysis."
        )
        next_steps.append("Investigate destination IPs for known C2 or malicious infrastructure.")

    has_ids = incident.metadata.get("has_ids_alert", False)
    if has_ids:
        actions.append("Escalate to Tier 2 / Incident Response team due to IDS alert confirmation.")
        next_steps.append("Collect full packet capture for the flagged network session if available.")

    next_steps.append("Document findings and update incident ticket with analyst notes.")
    next_steps.append("Schedule post-incident review if confirmed compromise.")

    return actions, next_steps
