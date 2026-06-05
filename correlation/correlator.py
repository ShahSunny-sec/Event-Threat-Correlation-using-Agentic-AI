from typing import Dict, List, Optional, Set, Tuple

from utils.config import INCIDENT_CORRELATION_WINDOW_MINUTES
from utils.constants import (
    DETECTION_FAILED_LOGIN_BURST,
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
    INCIDENT_TYPE_MULTI_STAGE,
)
from utils.helpers import minutes_between
from utils.schema import DetectionResult, Event, Incident


def _entity_key(det: DetectionResult) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    return (det.user, det.host, det.src_ip)


def _entities_overlap(a: DetectionResult, b: DetectionResult) -> bool:
    """Check if two detections share at least one strong entity."""
    if a.host and b.host and a.host == b.host:
        return True
    if a.user and b.user and a.user == b.user:
        return True
    if a.src_ip and b.src_ip and a.src_ip == b.src_ip:
        return True
    return False


def _time_proximity(a: DetectionResult, b: DetectionResult) -> bool:
    if not a.first_seen or not b.first_seen:
        return False
    t1 = a.last_seen or a.first_seen
    t2 = b.first_seen
    return minutes_between(t1, t2) <= INCIDENT_CORRELATION_WINDOW_MINUTES


def correlate_detections(detections: List[DetectionResult]) -> List[Incident]:
    """Group detections into incidents when the full attack chain is present.

    An incident requires:
      - failed_login_burst
      - success_after_failures
      - suspicious_outbound
    All must share entities and fall within the configured time window.
    """
    by_type: Dict[str, List[DetectionResult]] = {}
    for d in detections:
        by_type.setdefault(d.detection_type, []).append(d)

    bursts = by_type.get(DETECTION_FAILED_LOGIN_BURST, [])
    successes = by_type.get(DETECTION_SUCCESS_AFTER_FAILURES, [])
    outbounds = by_type.get(DETECTION_SUSPICIOUS_OUTBOUND, [])

    incidents: List[Incident] = []
    used_detection_ids: Set[str] = set()

    for burst in bursts:
        for success in successes:
            if not _entities_overlap(burst, success):
                continue
            if not _time_proximity(burst, success):
                continue

            for outbound in outbounds:
                if not (_entities_overlap(success, outbound) or _entities_overlap(burst, outbound)):
                    continue
                if not _time_proximity(success, outbound):
                    continue

                det_ids = {burst.detection_id, success.detection_id, outbound.detection_id}
                if det_ids & used_detection_ids:
                    continue

                dets = [burst, success, outbound]
                all_events_map: Dict[str, Event] = {}
                for d in dets:
                    for e in d.events:
                        all_events_map[e.event_id] = e
                all_events = sorted(all_events_map.values(), key=lambda e: e.timestamp or e.event_id)

                has_ids = outbound.metadata.get("has_ids_alert", False)
                base_confidence = min(
                    d.confidence for d in dets
                )
                confidence = min(base_confidence + (0.1 if has_ids else 0.0), 1.0)

                timestamps = [e.timestamp for e in all_events if e.timestamp]
                user = burst.user or success.user
                host = burst.host or success.host
                src_ip = burst.src_ip or success.src_ip
                dst_ip = outbound.dst_ip

                incident = Incident(
                    incident_type=INCIDENT_TYPE_MULTI_STAGE,
                    title=f"Multi-Stage Attack: Brute Force → Login → Suspicious Outbound on {host}",
                    summary=(
                        f"Detected a multi-stage attack chain targeting user '{user}' on "
                        f"host '{host}'. A burst of failed logins from {src_ip} was followed "
                        f"by a successful login and subsequent suspicious outbound connections"
                        f"{' with IDS alert confirmation' if has_ids else ''}."
                    ),
                    detections=dets,
                    events=all_events,
                    first_seen=min(timestamps) if timestamps else None,
                    last_seen=max(timestamps) if timestamps else None,
                    confidence=confidence,
                    affected_user=user,
                    affected_host=host,
                    primary_src_ip=src_ip,
                    primary_dst_ip=dst_ip,
                    correlation_keys=[
                        f"user:{user}", f"host:{host}", f"src_ip:{src_ip}"
                    ],
                    tags=["multi_stage", "brute_force", "lateral_movement"],
                    metadata={"has_ids_alert": has_ids},
                )
                incidents.append(incident)
                used_detection_ids.update(det_ids)

    # Agentic-only fallback: create single-stage incidents for high-confidence detections
    # that were not consumed by the full multi-stage chain builder above.
    for d in detections:
        if d.detection_id in used_detection_ids:
            continue
        if d.confidence < 0.55:
            continue

        all_events = sorted(d.events, key=lambda e: e.timestamp or e.event_id)
        timestamps = [e.timestamp for e in all_events if e.timestamp]
        user = d.user
        host = d.host
        src_ip = d.src_ip
        dst_ip = d.dst_ip
        tags = list(dict.fromkeys((d.tags or []) + ["single_stage", "agentic"]))

        incident = Incident(
            incident_type="single_stage_agentic",
            title=f"Single-Stage Alert: {d.detection_name}",
            summary=(
                f"Agentic detector produced a high-confidence security alert "
                f"('{d.detection_name}') with correlated entities and events."
            ),
            detections=[d],
            events=all_events,
            first_seen=min(timestamps) if timestamps else d.first_seen,
            last_seen=max(timestamps) if timestamps else d.last_seen,
            confidence=d.confidence,
            affected_user=user,
            affected_host=host,
            primary_src_ip=src_ip,
            primary_dst_ip=dst_ip,
            correlation_keys=[
                f"user:{user}" if user else "",
                f"host:{host}" if host else "",
                f"src_ip:{src_ip}" if src_ip else "",
            ],
            tags=[t for t in tags if t],
            metadata={"single_stage_reason": "agentic_high_confidence"},
        )
        incidents.append(incident)
        used_detection_ids.add(d.detection_id)

    return incidents
