from typing import List

from utils.config import SUSPICIOUS_OUTBOUND_WINDOW_MINUTES
from utils.constants import (
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
    DIRECTION_OUTBOUND,
    EVENT_TYPE_IDS_ALERT,
    EVENT_TYPE_NETWORK_OUTBOUND,
)
from utils.helpers import minutes_between
from utils.schema import DetectionResult, Event


def detect_suspicious_outbound(
    events: List[Event],
    prior_detections: List[DetectionResult],
) -> List[DetectionResult]:
    """Detect suspicious outbound connections after suspicious login activity.

    Uses the success timestamp from the success_after_failures detection
    rather than re-scanning all auth events (avoids picking up unrelated
    legitimate logins on the same host).
    Confidence is boosted if IDS alert evidence is present for the same flow.
    """
    suspicious_contexts = []
    for det in prior_detections:
        if det.detection_type == DETECTION_SUCCESS_AFTER_FAILURES:
            suspicious_contexts.append({
                "src_ip": det.src_ip,
                "host": det.host,
                "user": det.user,
                "success_time": det.last_seen,
            })

    if not suspicious_contexts:
        return []

    outbound = [
        e for e in events
        if e.event_type in (EVENT_TYPE_NETWORK_OUTBOUND, EVENT_TYPE_IDS_ALERT)
        and (e.direction or "").lower() == DIRECTION_OUTBOUND
        and e.timestamp
    ]
    ids_alerts = [e for e in events if e.event_type == EVENT_TYPE_IDS_ALERT and e.timestamp]

    results: List[DetectionResult] = []
    seen_hosts: set = set()

    for ctx in suspicious_contexts:
        src_ip = ctx["src_ip"]
        host = ctx["host"]
        success_time = ctx["success_time"]

        if host in seen_hosts or success_time is None:
            continue

        suspicious_flows = [
            e for e in outbound
            if (e.src_ip == src_ip or e.host == host)
            and e.timestamp >= success_time
            and minutes_between(success_time, e.timestamp)
            <= SUSPICIOUS_OUTBOUND_WINDOW_MINUTES
        ]

        if not suspicious_flows:
            continue

        has_ids = any(
            a for a in ids_alerts
            if (a.src_ip == src_ip or a.host == host)
            and a.timestamp >= success_time
        )

        confidence = 0.6 if not has_ids else 0.85
        severity = "high" if has_ids else "medium"

        all_events = list(suspicious_flows)
        if has_ids:
            matching_ids = [
                a for a in ids_alerts
                if (a.src_ip == src_ip or a.host == host)
                and a.timestamp >= success_time
            ]
            all_events.extend(matching_ids)

        unique_events = list({e.event_id: e for e in all_events}.values())
        unique_events.sort(key=lambda e: e.timestamp)

        dst_ips = list({e.dst_ip for e in suspicious_flows if e.dst_ip})

        det = DetectionResult(
            detection_type=DETECTION_SUSPICIOUS_OUTBOUND,
            detection_name="Suspicious Outbound Connection",
            description=(
                f"Outbound connection from host '{host}' (src {src_ip}) to "
                f"{', '.join(dst_ips)} after suspicious login. "
                f"{'IDS alert present.' if has_ids else 'No IDS alert.'}"
            ),
            severity=severity,
            confidence=confidence,
            event_ids=[e.event_id for e in unique_events],
            events=unique_events,
            first_seen=unique_events[0].timestamp,
            last_seen=unique_events[-1].timestamp,
            src_ip=src_ip,
            dst_ip=dst_ips[0] if dst_ips else None,
            host=host,
            risk_score=confidence * 80,
            tags=["c2", "exfiltration"] + (["ids_alert"] if has_ids else []),
            metadata={"has_ids_alert": has_ids, "dst_ips": dst_ips},
        )
        results.append(det)
        seen_hosts.add(host)

    return results
