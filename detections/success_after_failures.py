from collections import defaultdict
from typing import List

from utils.config import SUCCESS_AFTER_FAILURE_WINDOW_MINUTES
from utils.constants import (
    DETECTION_SUCCESS_AFTER_FAILURES,
    EVENT_TYPE_AUTH_FAILURE,
    EVENT_TYPE_AUTH_SUCCESS,
)
from utils.helpers import minutes_between
from utils.schema import DetectionResult, Event


def detect_success_after_failures(events: List[Event]) -> List[DetectionResult]:
    """Detect a successful login that follows multiple failed logins for the same user/host."""
    auth_events = [
        e for e in events
        if e.event_type in (EVENT_TYPE_AUTH_FAILURE, EVENT_TYPE_AUTH_SUCCESS) and e.timestamp
    ]
    grouped = defaultdict(list)
    for e in auth_events:
        key = (e.user or "unknown", e.host or "unknown")
        grouped[key].append(e)

    results: List[DetectionResult] = []
    for (user, host), group in grouped.items():
        group.sort(key=lambda x: x.timestamp)
        failures = [e for e in group if e.event_type == EVENT_TYPE_AUTH_FAILURE]
        successes = [e for e in group if e.event_type == EVENT_TYPE_AUTH_SUCCESS]

        if len(failures) < 3 or not successes:
            continue

        last_failure = failures[-1]
        for success in successes:
            if (
                success.timestamp >= last_failure.timestamp
                and minutes_between(failures[0].timestamp, success.timestamp)
                <= SUCCESS_AFTER_FAILURE_WINDOW_MINUTES
            ):
                all_events = failures + [success]
                confidence = min(0.6 + 0.05 * len(failures), 1.0)
                det = DetectionResult(
                    detection_type=DETECTION_SUCCESS_AFTER_FAILURES,
                    detection_name="Successful Login After Failures",
                    description=(
                        f"User '{user}' on host '{host}' logged in successfully after "
                        f"{len(failures)} failed attempts."
                    ),
                    severity="high",
                    confidence=confidence,
                    event_ids=[e.event_id for e in all_events],
                    events=all_events,
                    first_seen=failures[0].timestamp,
                    last_seen=success.timestamp,
                    user=user,
                    src_ip=success.src_ip or failures[0].src_ip,
                    host=host,
                    risk_score=confidence * 75,
                    tags=["credential_compromise", "valid_accounts"],
                )
                results.append(det)
                break

    return results
