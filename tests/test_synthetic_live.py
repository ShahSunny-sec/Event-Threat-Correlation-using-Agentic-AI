import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detections.failed_login_burst import detect_failed_login_burst
from detections.run_all import run_all_detections
from detections.success_after_failures import detect_success_after_failures
from detections.suspicious_outbound import detect_suspicious_outbound
from correlation.correlator import correlate_detections
from generators.synthetic_live import generate_live_synthetic


def _mock_agentic(events):
    out = []
    out.extend(detect_failed_login_burst(events))
    out.extend(detect_success_after_failures(events))
    out.extend(detect_suspicious_outbound(events, out))
    return out


def test_multi_stage_produces_incident():
    events = generate_live_synthetic(
        scenario="multi_stage_attack",
        window_minutes=60,
        noise_events=4,
        seed=42,
    )
    assert len(events) >= 10
    with patch("detections.run_all.detect_with_agentic_ai", side_effect=_mock_agentic):
        detections = run_all_detections(events)
    assert len(detections) >= 3
    incidents = correlate_detections(detections)
    assert len(incidents) >= 1


def test_random_mixed_runs():
    events = generate_live_synthetic(
        scenario="random_mixed",
        noise_events=12,
        seed=1,
    )
    assert len(events) >= 3
