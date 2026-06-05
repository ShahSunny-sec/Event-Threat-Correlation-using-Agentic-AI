"""HTTP API wrapper for the SOC triage pipeline."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.openai_client import is_llm_configured
from agent.incident_chat import chat_about_incident
from agent.fallback_report import build_fallback_report
from agent.report_generator import generate_report
from connectors import neo4j_graph
from connectors.macos_logs_connector import MacOSLogsConnector, MacOSLogsConnectorError
from connectors.windows_event_logs_connector import WindowsEventLogsConnector, WindowsEventLogsConnectorError
from correlation.correlator import correlate_detections
from detections.agentic_detector import get_last_agentic_status
from detections.run_all import run_all_detections
from evaluation.runner import run_evidence_triage_workflow
from generators.flog_runner import FlogNotFoundError, FlogRunError, run_flog
from generators.synthetic_live import generate_live_synthetic
from parsers.flog_router import parse_flog_output
from parsers.parser_router import parse_auth_file, parse_network_file
from triage.incident_builder import enrich_all_incidents
from triage.report_context_builder import build_incident_context
from utils.config import ABUSEIPDB_API_KEY, NEO4J_URI, NEO4J_USER, VIRUSTOTAL_API_KEY
from utils.schema import Event, Incident

app = FastAPI(title="SOC Triage API", version="1.0.0")
WEB_DIR = Path(__file__).resolve().parent / "web-ui"
SAMPLE_DIR = Path(__file__).resolve().parent / "data" / "sample"
app.mount("/web-ui", StaticFiles(directory=str(WEB_DIR)), name="web-ui")

_LAST_INCIDENTS: Dict[str, Incident] = {}


class AnalyzeRequest(BaseModel):
    auth_csv: str
    network_csv: str
    include_reports: bool = False


class SyntheticAnalyzeRequest(BaseModel):
    scenario: str = "demo_reliable_attack"
    window_minutes: int = 60
    noise_events: int = 8
    seed: Optional[int] = 4
    include_reports: bool = False


class AnalyzeSourceRequest(BaseModel):
    source_id: str = "demo_reliable_attack"
    window_minutes: int = 60
    noise_events: int = 8
    seed: Optional[int] = 4
    include_reports: bool = False
    flog_lines: int = 400
    flog_format: str = "apache_combined"
    mac_minutes: int = 60


class ReportRequest(BaseModel):
    incident_context: Dict[str, Any]
    mode: str = "fallback"  # "ai" | "fallback"


class ChatRequest(BaseModel):
    incident_context: Dict[str, Any]
    history: List[Dict[str, str]] = []
    prompt: str


@app.get("/")
def web_ui() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/llm-health")
def llm_health() -> Dict[str, Any]:
    return {"configured": is_llm_configured()}


@app.get("/neo4j/status")
def neo4j_status() -> Dict[str, Any]:
    status = neo4j_graph.connectivity_status()
    return {
        "configured": status["configured"],
        "connected": status["connected"],
        "message": status["message"],
        "uri": NEO4J_URI,
        "user": NEO4J_USER,
        "browser_url": neo4j_graph.browser_url(),
    }


@app.get("/data-sources")
def data_sources() -> Dict[str, Any]:
    return {
        "recommended": "demo_reliable_attack",
        "integrations": {
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "macos_logs": True,
            "windows_event_logs": True,
        },
        "sources": [
            {
                "id": "demo_reliable_attack",
                "label": "Reliable synthetic attack chain",
                "kind": "synthetic",
                "runnable": True,
                "quality": "recommended",
                "notes": "Strong auth burst, suspicious success, outbound callbacks, and IDS corroboration. Best for demos.",
            },
            {
                "id": "multi_stage_attack",
                "label": "Synthetic multi-stage attack",
                "kind": "synthetic",
                "runnable": True,
                "quality": "good",
                "notes": "Similar attack chain with more variability.",
            },
            {
                "id": "random_mixed",
                "label": "Random mixed synthetic traffic",
                "kind": "synthetic",
                "runnable": True,
                "quality": "negative/noisy",
                "notes": "Mostly benign/noisy events. It can legitimately produce few or no detections.",
            },
            {
                "id": "sample_csv",
                "label": "Bundled Linux auth + network CSV",
                "kind": "sample",
                "runnable": True,
                "quality": "stable",
                "notes": "Good for repeatable CLI/API validation.",
            },
            {
                "id": "sample_windows_logs",
                "label": "Bundled Windows auth + network CSV",
                "kind": "sample",
                "runnable": True,
                "quality": "stable",
                "notes": "Uses the bundled Windows authentication sample plus network IDS sample.",
            },
            {
                "id": "local_system_logs",
                "label": "Local macOS system logs",
                "kind": "live",
                "runnable": True,
                "quality": "variable",
                "notes": "Real local telemetry, but detection quality depends on recent activity volume.",
            },
            {
                "id": "windows_event_logs",
                "label": "Windows Event Logs",
                "kind": "live",
                "runnable": True,
                "quality": "host-dependent",
                "notes": "Uses PowerShell Get-WinEvent when the API runs on Windows.",
            },
            {
                "id": "flog_access_logs",
                "label": "flog web access logs",
                "kind": "oss-generator",
                "runnable": True,
                "quality": "web-only",
                "notes": "Good for web/access-log demos, weaker for auth+network attack-chain triage unless blended with synthetic events.",
            },
        ],
    }


def _event_summary(events: List[Event]) -> Dict[str, Any]:
    return {
        "count": len(events),
        "log_sources": dict(Counter(e.log_source for e in events)),
        "event_types": dict(Counter(e.event_type for e in events)),
    }


def _detection_payload(detections: List[Any]) -> List[Dict[str, Any]]:
    return [
        {
            "id": d.detection_id,
            "name": d.detection_name,
            "type": d.detection_type,
            "severity": d.severity,
            "confidence": d.confidence,
            "risk_score": d.risk_score,
            "description": d.description,
            "event_count": len(d.events),
            "user": d.user,
            "host": d.host,
            "src_ip": d.src_ip,
            "dst_ip": d.dst_ip,
        }
        for d in detections
    ]


def _incident_payload(incidents: List[Incident], include_reports: bool = False) -> List[Dict[str, Any]]:
    payload: List[Dict[str, Any]] = []
    for inc in incidents:
        ctx = build_incident_context(inc)
        kg = inc.metadata.get("knowledge_graph") or {}
        intel = inc.metadata.get("enrichment_intel")
        data: Dict[str, Any] = {
            "incident_id": inc.incident_id,
            "title": inc.title,
            "summary": inc.summary,
            "severity": inc.severity,
            "criticality_score": inc.criticality_score,
            "confidence": inc.confidence,
            "affected_user": inc.affected_user,
            "affected_host": inc.affected_host,
            "primary_src_ip": inc.primary_src_ip,
            "primary_dst_ip": inc.primary_dst_ip,
            "mitre_tactics": inc.mitre_tactics,
            "mitre_techniques": inc.mitre_techniques,
            "recommended_actions": inc.recommended_actions,
            "next_steps": inc.next_steps,
            "timeline": ctx.get("timeline", []),
            "timeline_count": len(ctx.get("timeline", [])),
            "detections_count": len(inc.detections),
            "events_count": len(inc.events),
            "enrichment_intel": intel,
            "knowledge_graph": kg,
            "knowledge_graph_counts": {
                "nodes": len(kg.get("nodes", []) or []),
                "edges": len(kg.get("edges", []) or []),
            },
            "context": ctx,
        }
        if include_reports:
            data["fallback_report"] = build_fallback_report(ctx)
        payload.append(data)
    return payload


def _analyze_events(events: List[Event], source_label: str, include_reports: bool = False) -> Dict[str, Any]:
    global _LAST_INCIDENTS
    detections = run_all_detections(events, mode="agentic")
    incidents = enrich_all_incidents(correlate_detections(detections))
    _LAST_INCIDENTS = {inc.incident_id: inc for inc in incidents}
    return jsonable_encoder(
        {
            "summary": {
                "source": source_label,
                "events": len(events),
                "detections": len(detections),
                "incidents": len(incidents),
                "detection_engine": "agentic_only",
                "llm_configured": is_llm_configured(),
                "detector_status": get_last_agentic_status(),
                "event_summary": _event_summary(events),
            },
            "detections": _detection_payload(detections),
            "incidents": _incident_payload(incidents, include_reports=include_reports),
        }
    )


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> Dict[str, Any]:
    auth_events, auth_fmt = parse_auth_file(req.auth_csv)
    net_events = parse_network_file(req.network_csv)
    return _analyze_events(auth_events + net_events, f"uploaded_csv:{auth_fmt}", req.include_reports)


@app.post("/analyze-synthetic")
def analyze_synthetic(req: SyntheticAnalyzeRequest) -> Dict[str, Any]:
    events = generate_live_synthetic(
        scenario=req.scenario,
        window_minutes=req.window_minutes,
        noise_events=req.noise_events,
        seed=req.seed,
    )
    return _analyze_events(events, f"synthetic:{req.scenario}", req.include_reports)


@app.post("/analyze-source")
def analyze_source(req: AnalyzeSourceRequest) -> Dict[str, Any]:
    source_id = req.source_id
    if source_id in {"demo_reliable_attack", "multi_stage_attack", "random_mixed"}:
        events = generate_live_synthetic(
            scenario=source_id,
            window_minutes=req.window_minutes,
            noise_events=req.noise_events,
            seed=req.seed,
        )
        return _analyze_events(events, f"synthetic:{source_id}", req.include_reports)

    if source_id == "sample_csv":
        auth_events, auth_fmt = parse_auth_file((SAMPLE_DIR / "auth_linux_sample.csv").read_text())
        net_events = parse_network_file((SAMPLE_DIR / "network_ids_sample.csv").read_text())
        return _analyze_events(auth_events + net_events, f"sample_csv:{auth_fmt}", req.include_reports)

    if source_id == "sample_windows_logs":
        auth_events, auth_fmt = parse_auth_file((SAMPLE_DIR / "auth_windows_sample.csv").read_text())
        net_events = parse_network_file((SAMPLE_DIR / "network_ids_sample.csv").read_text())
        return _analyze_events(auth_events + net_events, f"sample_windows_logs:{auth_fmt}", req.include_reports)

    if source_id == "local_system_logs":
        try:
            events = MacOSLogsConnector().fetch_recent(
                minutes_back=max(5, min(req.mac_minutes, 240)),
                limit=1800,
                signal_only=True,
            )
        except MacOSLogsConnectorError as exc:
            return {"error": "local_system_logs_failed", "message": str(exc)}
        return _analyze_events(events, "local_system_logs:macos", req.include_reports)

    if source_id == "windows_event_logs":
        try:
            events = WindowsEventLogsConnector().fetch_recent(
                minutes_back=max(5, min(req.window_minutes, 240)),
                limit=1200,
            )
        except WindowsEventLogsConnectorError as exc:
            return {"error": "windows_event_logs_failed", "message": str(exc)}
        return _analyze_events(events, "windows_event_logs:security", req.include_reports)

    if source_id == "flog_access_logs":
        try:
            raw = run_flog(number=max(50, min(req.flog_lines, 20000)), fmt=req.flog_format)
        except (FlogNotFoundError, FlogRunError) as exc:
            return {"error": "flog_failed", "message": str(exc)}
        flog_events = parse_flog_output(raw, req.flog_format)
        attack_context = generate_live_synthetic(
            scenario="demo_reliable_attack",
            window_minutes=req.window_minutes,
            noise_events=4,
            seed=req.seed,
        )
        return _analyze_events(flog_events + attack_context, "flog_access_logs:blended", req.include_reports)

    return {"error": "unknown_source", "message": f"Unknown source_id: {source_id}"}


@app.post("/evidence-triage/{incident_id}")
def evidence_triage(incident_id: str) -> Dict[str, Any]:
    inc = _LAST_INCIDENTS.get(incident_id)
    if inc is None:
        return {
            "error": "incident_not_found",
            "message": "Run analysis first, then choose an incident from the latest result set.",
        }
    return jsonable_encoder(run_evidence_triage_workflow(inc, run_llm=True, run_vanilla_baseline=False))


@app.post("/neo4j/sync/{incident_id}")
def sync_neo4j_incident(incident_id: str) -> Dict[str, Any]:
    inc = _LAST_INCIDENTS.get(incident_id)
    if inc is None:
        return {
            "ok": False,
            "message": "Run analysis first, then choose an incident from the latest result set.",
        }
    kg = inc.metadata.get("knowledge_graph")
    if not isinstance(kg, dict):
        return {"ok": False, "message": "Incident has no knowledge graph metadata."}
    ok, message = neo4j_graph.sync_incident_knowledge_graph(incident_id, kg)
    fetched_ok, graph, fetch_message = (
        neo4j_graph.fetch_incident_knowledge_graph(incident_id)
        if ok
        else (False, {"nodes": [], "edges": []}, "Sync did not complete.")
    )
    return {
        "ok": ok,
        "message": message,
        "fetched_ok": fetched_ok,
        "fetch_message": fetch_message,
        "graph": graph,
        "browser_url": neo4j_graph.browser_url(),
        "cypher": neo4j_graph.cypher_subgraph_query(incident_id),
    }


@app.get("/neo4j/graph/{incident_id}")
def get_neo4j_graph(incident_id: str) -> Dict[str, Any]:
    ok, graph, message = neo4j_graph.fetch_incident_knowledge_graph(incident_id)
    return {
        "ok": ok,
        "message": message,
        "graph": graph,
        "browser_url": neo4j_graph.browser_url(),
        "cypher": neo4j_graph.cypher_subgraph_query(incident_id),
    }


@app.post("/report")
def report(req: ReportRequest) -> Dict[str, Any]:
    mode = req.mode.lower()
    if mode == "ai":
        ai_report = generate_report(req.incident_context)
        if ai_report:
            return {"mode": "ai", "report": ai_report}
    return {"mode": "fallback", "report": build_fallback_report(req.incident_context)}


@app.post("/chat")
def chat(req: ChatRequest) -> Dict[str, Any]:
    response = chat_about_incident(req.incident_context, req.history, req.prompt)
    return {"response": response}
