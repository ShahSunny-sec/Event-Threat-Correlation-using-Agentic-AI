import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch

from correlation.correlator import correlate_detections
from detections.failed_login_burst import detect_failed_login_burst
from detections.success_after_failures import detect_success_after_failures
from detections.suspicious_outbound import detect_suspicious_outbound
from evaluation.baselines import rule_baseline_decision
from evaluation.runner import run_evidence_triage_workflow
from evidence.evidence_pack_builder import build_evidence_pack
from evidence.evidence_models import Claim, TriageOutput
from parsers.parser_router import parse_auth_file, parse_network_file
from triage.incident_builder import enrich_all_incidents
from verification.verifier import verify_triage

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def _one_incident():
    with patch("triage.incident_builder.VIRUSTOTAL_API_KEY", ""), patch(
        "triage.incident_builder.ABUSEIPDB_API_KEY", ""
    ):
        with open(os.path.join(SAMPLE_DIR, "auth_linux_sample.csv")) as f:
            auth_events, _ = parse_auth_file(f.read())
        with open(os.path.join(SAMPLE_DIR, "network_ids_sample.csv")) as f:
            net_events = parse_network_file(f.read())
        all_events = auth_events + net_events
        dets = []
        dets.extend(detect_failed_login_burst(all_events))
        dets.extend(detect_success_after_failures(all_events))
        dets.extend(detect_suspicious_outbound(all_events, dets))
        incs = correlate_detections(dets)
        incs = enrich_all_incidents(incs)
        return incs[0]


def test_build_evidence_pack_has_ids_and_coverage():
    inc = _one_incident()
    pack = build_evidence_pack(inc)
    assert pack.incident_id == inc.incident_id
    assert "coverage_score" in pack.coverage_summary
    assert any("evidence_id" in t for t in pack.timeline)
    assert pack.detections and pack.detections[0].get("evidence_id", "").startswith("E-DT-")


def test_rule_baseline_returns_decision():
    inc = _one_incident()
    pack = build_evidence_pack(inc)
    r = rule_baseline_decision(pack)
    assert r["decision"] in ("close", "escalate", "defer")
    assert r["method"] == "rule_baseline"


def test_verifier_flags_unknown_evidence():
    inc = _one_incident()
    pack = build_evidence_pack(inc)
    bad = TriageOutput(
        incident_id=pack.incident_id,
        decision="escalate",
        confidence=0.99,
        rationale="E-TL-0001 shows issues",
        evidence_ids=["E-INVALID-9999"],
        claims=[Claim(text="Something bad happened for sure.", evidence_ids=[])],
        missing_information=[],
        uncertainty_reasons=[],
    )
    v = verify_triage(pack, bad)
    assert v.is_valid is False
    assert v.unsupported_claims


def test_workflow_no_llm_defers():
    inc = _one_incident()
    out = run_evidence_triage_workflow(inc, run_llm=False, run_vanilla_baseline=False)
    assert out["final_decision"]["final_decision"] == "defer"
    assert out["triage"] is None
