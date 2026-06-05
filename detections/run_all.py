from typing import List

from detections.agentic_detector import detect_with_agentic_ai
from detections.failed_login_burst import detect_failed_login_burst
from detections.success_after_failures import detect_success_after_failures
from detections.suspicious_outbound import detect_suspicious_outbound
from utils.schema import DetectionResult, Event


def run_all_detections(events: List[Event], mode: str = "agentic") -> List[DetectionResult]:
    """Detection pipeline: agentic-first, with deterministic rules when AI yields nothing."""

    if not events:
        return []

    def _mark_rules(results: List[DetectionResult]) -> List[DetectionResult]:
        for det in results:
            det.metadata = dict(det.metadata or {})
            det.metadata["generator"] = "rules_fallback"
        return results

    if mode == "rules":
        first_pass = detect_failed_login_burst(events)
        second_pass = detect_success_after_failures(events)
        return _mark_rules(first_pass + second_pass + detect_suspicious_outbound(events, second_pass))

    agentic = detect_with_agentic_ai(events)
    if agentic:
        return agentic

    first_pass = detect_failed_login_burst(events)
    second_pass = detect_success_after_failures(events)
    return _mark_rules(first_pass + second_pass + detect_suspicious_outbound(events, second_pass))
