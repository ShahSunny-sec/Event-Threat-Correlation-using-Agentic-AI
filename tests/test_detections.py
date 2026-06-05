import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.parser_router import parse_auth_file, parse_network_file
from detections.failed_login_burst import detect_failed_login_burst
from detections.success_after_failures import detect_success_after_failures
from detections.suspicious_outbound import detect_suspicious_outbound
from detections.run_all import run_all_detections
from utils.constants import (
    DETECTION_FAILED_LOGIN_BURST,
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
)

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def _load_all_events():
    with open(os.path.join(SAMPLE_DIR, "auth_linux_sample.csv")) as f:
        auth_events, _ = parse_auth_file(f.read())
    with open(os.path.join(SAMPLE_DIR, "network_ids_sample.csv")) as f:
        net_events = parse_network_file(f.read())
    return auth_events + net_events


def _mock_agentic(events):
    """Deterministic stand-in for agentic detector in unit tests."""
    out = []
    out.extend(detect_failed_login_burst(events))
    out.extend(detect_success_after_failures(events))
    out.extend(detect_suspicious_outbound(events, out))
    return out


def test_failed_login_burst_detected():
    events = _load_all_events()
    results = detect_failed_login_burst(events)
    assert len(results) >= 1
    assert results[0].detection_type == DETECTION_FAILED_LOGIN_BURST
    assert results[0].user == "admin"


def test_success_after_failures_detected():
    events = _load_all_events()
    results = detect_success_after_failures(events)
    assert len(results) >= 1
    assert results[0].detection_type == DETECTION_SUCCESS_AFTER_FAILURES
    assert results[0].user == "admin"


def test_suspicious_outbound_detected():
    events = _load_all_events()
    prior = detect_failed_login_burst(events) + detect_success_after_failures(events)
    results = detect_suspicious_outbound(events, prior)
    assert len(results) >= 1
    assert results[0].detection_type == DETECTION_SUSPICIOUS_OUTBOUND


def test_run_all_returns_all_types():
    events = _load_all_events()
    with patch("detections.run_all.detect_with_agentic_ai", side_effect=_mock_agentic):
        detections = run_all_detections(events)
    types = {d.detection_type for d in detections}
    assert DETECTION_FAILED_LOGIN_BURST in types
    assert DETECTION_SUCCESS_AFTER_FAILURES in types
    assert DETECTION_SUSPICIOUS_OUTBOUND in types


def test_detections_have_confidence():
    events = _load_all_events()
    with patch("detections.run_all.detect_with_agentic_ai", side_effect=_mock_agentic):
        detections = run_all_detections(events)
    for d in detections:
        assert 0.0 < d.confidence <= 1.0
