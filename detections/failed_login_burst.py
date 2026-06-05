from collections import defaultdict
from typing import List

from utils.config import FAILED_LOGIN_BURST_THRESHOLD, FAILED_LOGIN_BURST_WINDOW_MINUTES
from utils.constants import DETECTION_FAILED_LOGIN_BURST, EVENT_TYPE_AUTH_FAILURE
from utils.helpers import minutes_between
from utils.schema import DetectionResult, Event


def detect_failed_login_burst(events: List[Event]) -> List[DetectionResult]:
    """Detect bursts of failed logins grouped by (user, host) within a time window."""
    failures = [e for e in events if e.event_type == EVENT_TYPE_AUTH_FAILURE and e.timestamp]
    grouped = defaultdict(list)
    for e in failures:
        key = (e.user or "unknown", e.host or "unknown")
        grouped[key].append(e)

    results: List[DetectionResult] = []
    for (user, host), group in grouped.items():
        group.sort(key=lambda x: x.timestamp)

        best_window: List[Event] = []
        window: List[Event] = []
        for evt in group:
            window = [
                w for w in window
                if minutes_between(w.timestamp, evt.timestamp) <= FAILED_LOGIN_BURST_WINDOW_MINUTES
            ]
            window.append(evt)
            if len(window) > len(best_window):
                best_window = list(window)

        if len(best_window) >= FAILED_LOGIN_BURST_THRESHOLD:
            confidence = min(0.5 + 0.1 * (len(best_window) - FAILED_LOGIN_BURST_THRESHOLD), 1.0)
            det = DetectionResult(
                detection_type=DETECTION_FAILED_LOGIN_BURST,
                detection_name="Failed Login Burst",
                description=(
                    f"{len(best_window)} failed logins for user '{user}' on host "
                    f"'{host}' within {FAILED_LOGIN_BURST_WINDOW_MINUTES} minutes."
                ),
                severity="high" if len(best_window) >= FAILED_LOGIN_BURST_THRESHOLD + 2 else "medium",
                confidence=confidence,
                event_ids=[e.event_id for e in best_window],
                events=list(best_window),
                first_seen=best_window[0].timestamp,
                last_seen=best_window[-1].timestamp,
                user=user,
                src_ip=best_window[0].src_ip,
                host=host,
                risk_score=confidence * 60,
                tags=["brute_force", "credential_access"],
            )
            results.append(det)

    return results
