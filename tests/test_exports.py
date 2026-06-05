import json
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.parser_router import parse_auth_file, parse_network_file
from detections.failed_login_burst import detect_failed_login_burst
from detections.run_all import run_all_detections
from detections.success_after_failures import detect_success_after_failures
from detections.suspicious_outbound import detect_suspicious_outbound
from correlation.correlator import correlate_detections
from triage.incident_builder import enrich_all_incidents
from utils.exporters import export_incident_json, export_incident_csv, export_incidents_json

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def _mock_agentic(events):
    out = []
    out.extend(detect_failed_login_burst(events))
    out.extend(detect_success_after_failures(events))
    out.extend(detect_suspicious_outbound(events, out))
    return out


def _full_pipeline():
    with open(os.path.join(SAMPLE_DIR, "auth_linux_sample.csv")) as f:
        auth_events, _ = parse_auth_file(f.read())
    with open(os.path.join(SAMPLE_DIR, "network_ids_sample.csv")) as f:
        net_events = parse_network_file(f.read())
    with patch("detections.run_all.detect_with_agentic_ai", side_effect=_mock_agentic):
        detections = run_all_detections(auth_events + net_events)
    incidents = correlate_detections(detections)
    return enrich_all_incidents(incidents)


def test_json_export_valid():
    incidents = _full_pipeline()
    data = export_incident_json(incidents[0])
    parsed = json.loads(data)
    assert "incident_id" in parsed
    assert "detections" in parsed


def test_csv_export_has_header():
    incidents = _full_pipeline()
    csv_data = export_incident_csv(incidents[0])
    lines = csv_data.strip().split("\n")
    assert len(lines) == 2
    assert "incident_id" in lines[0]


def test_multi_incident_json():
    incidents = _full_pipeline()
    data = export_incidents_json(incidents)
    parsed = json.loads(data)
    assert isinstance(parsed, list)
    assert len(parsed) >= 1
