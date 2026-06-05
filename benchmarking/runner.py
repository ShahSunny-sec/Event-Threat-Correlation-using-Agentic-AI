from __future__ import annotations

import json
import os
import time
import tracemalloc
from typing import Any, Dict, List

from parsers.parser_router import parse_auth_file, parse_network_file
from detections.run_all import run_all_detections
from correlation.correlator import correlate_detections
from triage.incident_builder import enrich_all_incidents
from triage.report_context_builder import build_incident_context
from agent.report_generator import generate_report
from agent.fallback_report import build_fallback_report
from utils.config import LLM_API_KEY

from benchmarking.performance import (
    RunResult,
    StageTiming,
    aggregate_stage_times,
    timed_stage,
)

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample")


def one_pipeline_run(
    auth_path: str,
    network_path: str,
    *,
    with_llm_report: bool = False,
    track_memory: bool = False,
    local_enrichment_only: bool = False,
) -> RunResult:
    if local_enrichment_only:
        os.environ["BENCHMARK_LOCAL_ENRICHMENT_ONLY"] = "1"
    else:
        os.environ.pop("BENCHMARK_LOCAL_ENRICHMENT_ONLY", None)

    stages: List[StageTiming] = []
    peak_mem: int | None = None

    if track_memory:
        tracemalloc.start()

    with open(auth_path) as f:
        auth_content = f.read()
    with open(network_path) as f:
        net_content = f.read()

    with timed_stage("parse_auth", stages):
        auth_events, _fmt = parse_auth_file(auth_content)

    with timed_stage("parse_network", stages):
        net_events = parse_network_file(net_content)

    all_events = auth_events + net_events

    with timed_stage("detection", stages):
        detections = run_all_detections(all_events)

    with timed_stage("correlation", stages):
        incidents = correlate_detections(detections)

    with timed_stage("triage_enrich", stages):
        incidents = enrich_all_incidents(incidents)

    with timed_stage("build_context", stages):
        contexts = [build_incident_context(inc) for inc in incidents]

    if with_llm_report and LLM_API_KEY and contexts:
        with timed_stage("llm_report_first_incident", stages):
            generate_report(contexts[0])
    elif contexts:
        with timed_stage("fallback_report_first_incident", stages):
            build_fallback_report(contexts[0])

    if track_memory:
        _cur, peak = tracemalloc.get_traced_memory()
        peak_mem = peak
        tracemalloc.stop()

    return RunResult(
        stages=stages,
        peak_memory_bytes=peak_mem,
        event_count=len(all_events),
        detection_count=len(detections),
        incident_count=len(incidents),
    )


def collect_benchmark_payload(
    auth_path: str,
    network_path: str,
    *,
    runs: int = 10,
    warmup: int = 1,
    with_llm: bool = False,
    memory: bool = False,
    local_only: bool = False,
) -> Dict[str, Any]:
    for _ in range(warmup):
        one_pipeline_run(
            auth_path,
            network_path,
            with_llm_report=False,
            track_memory=False,
            local_enrichment_only=local_only,
        )

    measured: List[RunResult] = []
    wall_start = time.perf_counter()
    for _ in range(runs):
        measured.append(
            one_pipeline_run(
                auth_path,
                network_path,
                with_llm_report=with_llm,
                track_memory=memory,
                local_enrichment_only=local_only,
            )
        )
    wall_total = time.perf_counter() - wall_start

    agg = aggregate_stage_times(measured)
    last = measured[-1]
    ev = last.event_count
    throughput = float(ev) / wall_total if ev and wall_total > 0 else 0.0

    payload: Dict[str, Any] = {
        "auth": auth_path,
        "network": network_path,
        "warmup": warmup,
        "runs": runs,
        "wall_seconds_all_measured": wall_total,
        "aggregate_stage_seconds": agg,
        "last_run_event_count": ev,
        "last_run_detection_count": last.detection_count,
        "last_run_incident_count": last.incident_count,
        "throughput_events_per_sec": throughput,
    }
    if memory:
        payload["peak_traced_memory_bytes_max"] = max(
            (r.peak_memory_bytes or 0) for r in measured
        )
    return payload


def save_payload(path: str, payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
