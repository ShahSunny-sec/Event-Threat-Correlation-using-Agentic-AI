import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.parser_router import parse_auth_file, parse_network_file
from detections.failed_login_burst import detect_failed_login_burst
from detections.success_after_failures import detect_success_after_failures
from detections.suspicious_outbound import detect_suspicious_outbound
from correlation.correlator import correlate_detections
from triage.incident_builder import enrich_all_incidents
from triage.report_context_builder import build_incident_context
from agent.fallback_report import build_fallback_report
from utils.schema import DetectionResult, Incident

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def _full_pipeline():
    # Keep tests deterministic/offline even with strict agentic-only runtime mode.
    with patch("triage.incident_builder.VIRUSTOTAL_API_KEY", ""), patch(
        "triage.incident_builder.ABUSEIPDB_API_KEY", ""
    ):
        with open(os.path.join(SAMPLE_DIR, "auth_linux_sample.csv")) as f:
            auth_events, _ = parse_auth_file(f.read())
        with open(os.path.join(SAMPLE_DIR, "network_ids_sample.csv")) as f:
            net_events = parse_network_file(f.read())
        all_events = auth_events + net_events
        detections = []
        detections.extend(detect_failed_login_burst(all_events))
        detections.extend(detect_success_after_failures(all_events))
        detections.extend(detect_suspicious_outbound(all_events, detections))
        incidents = correlate_detections(detections)
        return enrich_all_incidents(incidents)


def test_severity_assigned():
    incidents = _full_pipeline()
    for inc in incidents:
        assert inc.severity in ("low", "medium", "high", "critical")


def test_criticality_score_range():
    incidents = _full_pipeline()
    for inc in incidents:
        assert 0 <= inc.criticality_score <= 100


def test_mitre_populated():
    incidents = _full_pipeline()
    inc = incidents[0]
    assert len(inc.mitre_tactics) > 0
    assert len(inc.mitre_techniques) > 0


def test_mitre_populated_for_agentic_detection_labels():
    inc = Incident(
        detections=[
            DetectionResult(
                detection_type="credential_compromise",
                detection_name="Successful login after brute force",
                description="Valid account use after repeated failed password attempts.",
                tags=["agentic-ai", "brute-force"],
            ),
            DetectionResult(
                detection_type="c2_activity",
                detection_name="Outbound callback beacon",
                description="Host made suspicious outbound C2 connection.",
                tags=["command-and-control"],
            ),
        ]
    )
    enriched = enrich_all_incidents([inc])[0]
    assert "Credential Access" in enriched.mitre_tactics
    assert "Command and Control" in enriched.mitre_tactics
    assert any("T1110" in technique for technique in enriched.mitre_techniques)
    assert any("T1071" in technique for technique in enriched.mitre_techniques)


def test_recommendations_populated():
    incidents = _full_pipeline()
    inc = incidents[0]
    assert len(inc.recommended_actions) > 0
    assert len(inc.next_steps) > 0


def test_enrichment_links():
    incidents = _full_pipeline()
    inc = incidents[0]
    assert len(inc.enrichment_links) > 0


def test_incident_context_fields():
    incidents = _full_pipeline()
    ctx = build_incident_context(incidents[0])
    required = [
        "incident_id", "title", "summary", "severity",
        "criticality_score", "affected_user", "affected_host",
        "timeline", "detections", "mitre_tactics", "mitre_techniques",
    ]
    for field in required:
        assert field in ctx


def test_fallback_report_generated():
    incidents = _full_pipeline()
    ctx = build_incident_context(incidents[0])
    report = build_fallback_report(ctx)
    assert "INCIDENT INVESTIGATION REPORT" in report
    assert ctx["affected_user"] in report


def test_timeline_has_entries():
    incidents = _full_pipeline()
    ctx = build_incident_context(incidents[0])
    assert len(ctx["timeline"]) > 0
