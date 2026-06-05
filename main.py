"""CLI smoke-test runner for the SOC triage pipeline."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Iterable, List, Tuple

from parsers.parser_router import parse_auth_file, parse_network_file
from detections.run_all import run_all_detections
from correlation.correlator import correlate_detections
from triage.incident_builder import enrich_all_incidents
from triage.report_context_builder import build_incident_context
from agent.report_generator import generate_report
from agent.fallback_report import build_fallback_report
from utils.exporters import export_incident_json
from utils.schema import DetectionResult, Event, Incident
from utils.config import LLM_API_KEY

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "data", "sample")


def _top(items: Iterable[str], n: int = 5) -> List[Tuple[str, int]]:
    return Counter([i for i in items if i]).most_common(n)


def _trace_events(events: List[Event]) -> None:
    print("\n[TRACE] PARSE → normalized events")
    print(f"  total_events={len(events)}")
    print(f"  top_sources={_top([e.log_source for e in events])}")
    print(f"  top_types={_top([e.event_type for e in events])}")
    print(f"  top_users={_top([e.user or '' for e in events])}")
    print(f"  top_hosts={_top([e.host or '' for e in events])}")
    print(f"  top_src_ips={_top([e.src_ip or '' for e in events])}")
    print(f"  top_dst_ips={_top([e.dst_ip or '' for e in events])}")


def _trace_detections(dets: List[DetectionResult]) -> None:
    print("\n[TRACE] DETECT → rule hits")
    print(f"  detections={len(dets)}")
    print(f"  by_name={_top([d.detection_name for d in dets], n=20)}")
    print(f"  by_severity={_top([d.severity for d in dets], n=10)}")


def _trace_incidents(incs: List[Incident]) -> None:
    print("\n[TRACE] CORRELATE → incidents")
    print(f"  incidents={len(incs)}")
    print(f"  severities={_top([i.severity for i in incs], n=10)}")
    for i in incs[:5]:
        print(
            f"  - {i.incident_id} sev={i.severity} score={i.criticality_score:.0f} "
            f"detections={len(i.detections)} events={len(i.events)} "
            f"user={i.affected_user} host={i.affected_host} "
            f"src={i.primary_src_ip} dst={i.primary_dst_ip}"
        )


def _trace_triage(inc: Incident) -> None:
    intel = inc.metadata.get("enrichment_intel") or {}
    intel_ips = (intel.get("ips") or {}) if isinstance(intel, dict) else {}
    print("\n[TRACE] TRIAGE → enrich_incident output")
    print(f"  title={inc.title}")
    print(f"  severity={inc.severity} score={inc.criticality_score:.0f} confidence={inc.confidence}")
    print(f"  mitre_tactics={inc.mitre_tactics}")
    print(f"  mitre_techniques={inc.mitre_techniques}")
    print(f"  rec_actions={len(inc.recommended_actions)} next_steps={len(inc.next_steps)}")
    print(f"  timeline_entries={len((inc.metadata.get('timeline') or []))}")
    print(f"  enrichment_links={len(inc.enrichment_links)}")
    print(f"  enrichment_intel_ips={len(intel_ips)}")


def run_pipeline(auth_path: str, network_path: str, trace: bool = False) -> None:
    with open(auth_path) as f:
        auth_content = f.read()
    with open(network_path) as f:
        net_content = f.read()

    auth_events, fmt = parse_auth_file(auth_content)
    net_events = parse_network_file(net_content)
    all_events = auth_events + net_events
    print(f"Parsed {len(auth_events)} auth events ({fmt}) + {len(net_events)} network events = {len(all_events)} total")
    if trace:
        _trace_events(all_events)

    detections = run_all_detections(all_events)
    print(f"Detections: {len(detections)}")
    for d in detections:
        print(f"  [{d.severity.upper()}] {d.detection_name}: {d.description}")
    if trace:
        _trace_detections(detections)

    incidents = correlate_detections(detections)
    incidents = enrich_all_incidents(incidents)
    print(f"\nIncidents: {len(incidents)}")
    if trace:
        _trace_incidents(incidents)

    for inc in incidents:
        ctx = build_incident_context(inc)
        print(f"\n{'='*60}")
        print(f"Incident: {inc.title}")
        print(f"Severity: {inc.severity.upper()} (score {inc.criticality_score})")
        print(f"User: {inc.affected_user} | Host: {inc.affected_host}")
        print(f"MITRE: {', '.join(inc.mitre_tactics)}")
        if trace:
            _trace_triage(inc)

        if LLM_API_KEY:
            print("\nAI Report:\n")
            report = generate_report(ctx)
            if report:
                print(report)
            else:
                print("(AI report failed; falling back)\n")
                print(build_fallback_report(ctx))
        else:
            print(f"\nFallback Report:\n")
            print(build_fallback_report(ctx))

        out_path = os.path.join(
            os.path.dirname(__file__), "data", "processed", f"{inc.incident_id}.json"
        )
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            f.write(export_incident_json(inc))
        print(f"\nExported to {out_path}")


def run_evidence_triage_cli(auth_path: str, network_path: str, *, run_llm: bool) -> None:
    """Correlate + enrich, then evidence pack → triage → verifier → defer (prints JSON summary)."""
    from evaluation.runner import run_evidence_triage_workflow

    with open(auth_path) as f:
        auth_content = f.read()
    with open(network_path) as f:
        net_content = f.read()
    auth_events, _ = parse_auth_file(auth_content)
    net_events = parse_network_file(net_content)
    all_events = auth_events + net_events
    detections = run_all_detections(all_events)
    incidents = correlate_detections(detections)
    incidents = enrich_all_incidents(incidents)
    for inc in incidents:
        out = run_evidence_triage_workflow(inc, run_llm=run_llm, run_vanilla_baseline=False)
        print(json.dumps(out["final_decision"], indent=2))
        print(json.dumps(out["verifier"], indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Run the SOC pipeline end-to-end.")
    p.add_argument("--auth", default=os.path.join(SAMPLE_DIR, "auth_linux_sample.csv"))
    p.add_argument("--net", default=os.path.join(SAMPLE_DIR, "network_ids_sample.csv"))
    p.add_argument("--trace", action="store_true", help="Print end-of-step debug summaries.")
    p.add_argument(
        "--evidence-triage",
        action="store_true",
        help="After correlate+enrich, run evidence pack → triage → verifier → defer (prints JSON).",
    )
    p.add_argument(
        "--no-llm",
        action="store_true",
        help="With --evidence-triage, skip LLM (triage defers; verifier still runs).",
    )
    args = p.parse_args()

    if args.evidence_triage:
        run_evidence_triage_cli(args.auth, args.net, run_llm=not args.no_llm)
    else:
        run_pipeline(args.auth, args.net, trace=args.trace)
