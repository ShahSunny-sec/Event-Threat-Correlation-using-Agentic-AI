import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.parser_router import parse_auth_file, parse_network_file
from correlation.correlator import correlate_detections
from utils.schema import DetectionResult

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def _load_and_detect():
    with open(os.path.join(SAMPLE_DIR, "auth_linux_sample.csv")) as f:
        auth_events, _ = parse_auth_file(f.read())
    with open(os.path.join(SAMPLE_DIR, "network_ids_sample.csv")) as f:
        net_events = parse_network_file(f.read())
    all_events = auth_events + net_events
    # Keep tests deterministic/offline in agentic-only runtime mode.
    now = datetime.now(timezone.utc)
    d = DetectionResult(
        detection_type="agentic_ai",
        detection_name="Mocked Correlation Detection",
        description="Test detection for correlation.",
        severity="high",
        confidence=0.9,
        events=all_events[:12],
        event_ids=[e.event_id for e in all_events[:12]],
        first_seen=now - timedelta(minutes=10),
        last_seen=now - timedelta(minutes=2),
        user="admin",
        host="linux-web-01",
        src_ip="192.168.1.100",
        dst_ip="203.0.113.50",
        risk_score=82.0,
        tags=["agentic", "test"],
    )
    return [d]


def test_incident_created():
    detections = _load_and_detect()
    incidents = correlate_detections(detections)
    assert len(incidents) >= 1


def test_incident_has_three_detections():
    detections = _load_and_detect()
    incidents = correlate_detections(detections)
    for inc in incidents:
        assert len(inc.detections) >= 1


def test_incident_entities_populated():
    detections = _load_and_detect()
    incidents = correlate_detections(detections)
    inc = incidents[0]
    assert inc.affected_user is not None
    assert inc.affected_host is not None
    assert inc.primary_src_ip is not None


def test_incident_time_range():
    detections = _load_and_detect()
    incidents = correlate_detections(detections)
    inc = incidents[0]
    assert inc.first_seen is not None
    assert inc.last_seen is not None
    assert inc.first_seen <= inc.last_seen
