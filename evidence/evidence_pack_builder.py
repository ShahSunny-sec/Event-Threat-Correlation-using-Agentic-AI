"""Build a structured EvidencePack from an enriched Incident (evidence IDs + coverage + conflicts)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from evidence.evidence_models import EvidencePack
from triage.timeline_builder import build_timeline
from utils.constants import (
    DETECTION_FAILED_LOGIN_BURST,
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
    EVENT_TYPE_ACCOUNT_MANIPULATION,
    EVENT_TYPE_AUTH_FAILURE,
    EVENT_TYPE_AUTH_SUCCESS,
    EVENT_TYPE_DATA_STAGING,
    EVENT_TYPE_IDS_ALERT,
    EVENT_TYPE_LATERAL_MOVEMENT,
    EVENT_TYPE_NETWORK_OUTBOUND,
    EVENT_TYPE_PRIVILEGE_ESCALATION,
    EVENT_TYPE_PROCESS_EXEC,
    EVENT_TYPE_RANSOMWARE,
    EVENT_TYPE_WEB_ATTACK,
)
from utils.schema import DetectionResult, Event, Incident


def _eid(prefix: str, n: int) -> str:
    return f"E-{prefix}-{n:04d}"


def _entity_block(incident: Incident) -> Dict[str, Any]:
    return {
        "affected_user": incident.affected_user,
        "affected_host": incident.affected_host,
        "primary_src_ip": incident.primary_src_ip,
        "primary_dst_ip": incident.primary_dst_ip,
    }


def _entity_completeness(inc: Incident) -> float:
    fields = [inc.affected_user, inc.affected_host, inc.primary_src_ip, inc.primary_dst_ip]
    filled = sum(1 for f in fields if f)
    return filled / max(len(fields), 1)


def _sorted_events(incident: Incident) -> List[Event]:
    ev = [e for e in incident.events if e.timestamp]
    return sorted(ev, key=lambda e: e.timestamp or "")


def _temporal_coherent(incident: Incident) -> float:
    ev = _sorted_events(incident)
    if len(ev) < 2:
        return 1.0
    ok = 0
    for a, b in zip(ev, ev[1:]):
        if a.timestamp and b.timestamp and a.timestamp <= b.timestamp:
            ok += 1
    return ok / (len(ev) - 1)


def _detection_types(dets: List[DetectionResult]) -> Set[str]:
    return {d.detection_type for d in dets}


_THREAT_EVENT_TYPES = {
    EVENT_TYPE_IDS_ALERT,
    EVENT_TYPE_PROCESS_EXEC,
    EVENT_TYPE_WEB_ATTACK,
    EVENT_TYPE_RANSOMWARE,
    EVENT_TYPE_LATERAL_MOVEMENT,
    EVENT_TYPE_PRIVILEGE_ESCALATION,
    EVENT_TYPE_DATA_STAGING,
    EVENT_TYPE_ACCOUNT_MANIPULATION,
}


def _event_signals(events: List[Event]) -> Tuple[bool, bool, bool]:
    has_fail = any(e.event_type == EVENT_TYPE_AUTH_FAILURE for e in events)
    has_succ = any(e.event_type == EVENT_TYPE_AUTH_SUCCESS for e in events)
    has_out  = any(e.event_type == EVENT_TYPE_NETWORK_OUTBOUND for e in events)
    has_ids  = any(e.event_type == EVENT_TYPE_IDS_ALERT for e in events)
    has_threat = any(e.event_type in _THREAT_EVENT_TYPES for e in events)
    return has_fail or has_succ, has_out or has_threat, has_ids or has_threat


def _intel_summary(incident: Incident) -> Dict[str, Any]:
    intel = incident.metadata.get("enrichment_intel")
    if not isinstance(intel, dict) or not intel.get("ips"):
        return {"available": False, "items": []}
    items: List[Dict[str, Any]] = []
    for ip, entry in sorted((intel.get("ips") or {}).items()):
        vt = entry.get("virustotal") or {}
        ab = entry.get("abuseipdb") or {}
        benign_hint = False
        if isinstance(ab, dict) and ab.get("abuse_confidence_score") is not None:
            try:
                benign_hint = int(ab["abuse_confidence_score"]) < 15
            except (TypeError, ValueError):
                pass
        items.append(
            {
                "ip": ip,
                "abuse_score": ab.get("abuse_confidence_score"),
                "vt_malicious": (vt.get("last_analysis_stats") or {}).get("malicious"),
                "benign_hint": benign_hint,
            }
        )
    return {"available": True, "items": items[:20]}


def _conflict_flags(incident: Incident, dets: List[DetectionResult], intel: Dict[str, Any]) -> List[str]:
    flags: List[str] = []
    users = {d.user for d in dets if d.user}
    # Only flag user mismatch if there are 3+ distinct users (2 is common in lateral movement)
    if len(users) > 2:
        flags.append("user_mismatch_across_detections")
    hosts = {d.host for d in dets if d.host}
    # Multi-host is expected in lateral movement / ransomware; only flag when 3+ distinct hosts
    if len(hosts) > 2:
        flags.append("host_mismatch_across_detections")

    has_bruteforce = DETECTION_FAILED_LOGIN_BURST in {d.detection_type for d in dets}
    if has_bruteforce and intel.get("available"):
        for it in intel.get("items") or []:
            if it.get("benign_hint") and it.get("ip") == incident.primary_src_ip:
                flags.append("intel_benign_vs_bruteforce_context")
                break

    ev = _sorted_events(incident)
    if len(ev) >= 2:
        for a, b in zip(ev, ev[1:]):
            if a.timestamp and b.timestamp and a.timestamp > b.timestamp:
                flags.append("timeline_order_inversion")
                break

    if incident.metadata.get("has_ids_alert") and not any(
        e.event_type == EVENT_TYPE_NETWORK_OUTBOUND for e in incident.events
    ):
        flags.append("ids_alert_without_outbound_events")

    return flags


def _coverage_components(incident: Incident, dets: List[DetectionResult], events: List[Event]) -> Dict[str, float]:
    dt = _detection_types(dets)
    # Build a single lowercased text blob from all detection metadata for keyword matching
    det_text = " ".join(dt).lower().replace("-", "_").replace(" ", "_")
    for d in dets:
        det_text += " " + (d.detection_name or "").lower().replace("-", "_").replace(" ", "_")
        det_text += " " + " ".join(d.tags or []).lower().replace("-", "_").replace(" ", "_")

    # ── auth anomaly: brute force / credential-related signals ──────────────
    auth_anomaly = (
        DETECTION_FAILED_LOGIN_BURST in dt
        or any(tok in det_text for tok in (
            "brute", "login_burst", "credential_stuf", "failed_login",
            "password_spray", "stuffing",
        ))
        or sum(1 for e in events if e.event_type == EVENT_TYPE_AUTH_FAILURE) >= 3
    )

    # ── post-auth / account compromise: success after failures, ATO ─────────
    post_auth = (
        DETECTION_SUCCESS_AFTER_FAILURES in dt
        or any(tok in det_text for tok in (
            "success_after", "valid_account", "account_takeover",
            "compromised_account", "ato",
        ))
        or (
            any(e.event_type == EVENT_TYPE_AUTH_FAILURE for e in events)
            and any(e.event_type == EVENT_TYPE_AUTH_SUCCESS for e in events)
        )
    )

    # ── outbound / IDS / any high-signal threat event ────────────────────────
    outbound_ids = (
        DETECTION_SUSPICIOUS_OUTBOUND in dt
        or incident.metadata.get("has_ids_alert", False)
        or any(tok in det_text for tok in (
            "c2", "ransomware", "exfil", "lateral", "web_attack",
            "rce", "reverse_shell", "beacon", "outbound",
        ))
        or any(e.event_type in _THREAT_EVENT_TYPES for e in events)
    )

    ent  = _entity_completeness(incident)
    tcoh = _temporal_coherent(incident)

    return {
        "auth_anomaly":          1.0 if auth_anomaly else 0.0,
        "post_auth_correlation": 1.0 if post_auth else 0.0,
        "outbound_or_ids":       1.0 if outbound_ids else 0.0,
        "entity_completeness":   ent,
        "temporal_coherence":    tcoh,
    }


_HIGH_SIGNAL_EVENT_TYPES = {
    EVENT_TYPE_RANSOMWARE,
    EVENT_TYPE_PRIVILEGE_ESCALATION,
    EVENT_TYPE_PROCESS_EXEC,
    EVENT_TYPE_WEB_ATTACK,
    EVENT_TYPE_LATERAL_MOVEMENT,
    EVENT_TYPE_ACCOUNT_MANIPULATION,
}


def _strong_evidence_count(
    components: Dict[str, float],
    dets: List[DetectionResult],
    events: Optional[List[Event]] = None,
) -> int:
    strong = 0
    if components["auth_anomaly"] >= 1.0:
        strong += 1
    if components["post_auth_correlation"] >= 1.0:
        strong += 1
    if components["outbound_or_ids"] >= 1.0:
        strong += 1
    if components["entity_completeness"] >= 0.75:
        strong += 1
    if len(dets) >= 2:
        strong += 1
    # Extra point when high-signal threat events are present (ransomware, privesc, RCE…)
    if events and any(e.event_type in _HIGH_SIGNAL_EVENT_TYPES for e in events):
        strong += 1
    return strong


def build_evidence_pack(incident: Incident) -> EvidencePack:
    timeline_raw = incident.metadata.get("timeline") or build_timeline(incident)
    timeline: List[Dict[str, Any]] = []
    evidence_index: Dict[str, str] = {}

    for i, row in enumerate(timeline_raw):
        eid = _eid("TL", i + 1)
        desc = row.get("description") or ""
        timeline.append(
            {
                "evidence_id": eid,
                "timestamp": row.get("timestamp"),
                "event_type": row.get("event_type"),
                "source": row.get("source"),
                "summary": desc[:500],
            }
        )
        evidence_index[eid] = f"timeline:{row.get('timestamp')}:{row.get('event_type')}"

    detections: List[Dict[str, Any]] = []
    for j, d in enumerate(incident.detections):
        eid = _eid("DT", j + 1)
        detections.append(
            {
                "evidence_id": eid,
                "detection_id": d.detection_id,
                "detection_type": d.detection_type,
                "detection_name": d.detection_name,
                "description": (d.description or "")[:800],
                "severity": d.severity,
                "confidence": d.confidence,
                "user": d.user,
                "host": d.host,
                "src_ip": d.src_ip,
                "dst_ip": d.dst_ip,
                "event_count": len(d.events),
            }
        )
        evidence_index[eid] = f"detection:{d.detection_type}:{d.detection_name}"

    e_meta = _eid("MD", 1)
    evidence_index[e_meta] = "incident:metadata_summary"

    intel = _intel_summary(incident)
    enrichment_items: List[Dict[str, Any]] = []
    if intel.get("available"):
        for k, it in enumerate(intel.get("items") or []):
            eid = _eid("EN", k + 1)
            enrichment_items.append({"evidence_id": eid, **it})
            evidence_index[eid] = f"enrichment:ip:{it.get('ip')}"

    mitre_items: List[Dict[str, Any]] = []
    for m, tac in enumerate(incident.mitre_tactics or []):
        eid = _eid("MT", m + 1)
        mitre_items.append({"evidence_id": eid, "kind": "tactic", "value": tac})
        evidence_index[eid] = f"mitre:tactic:{tac}"
    base = len(mitre_items)
    for n, tech in enumerate(incident.mitre_techniques or []):
        eid = _eid("MT", base + n + 1)
        mitre_items.append({"evidence_id": eid, "kind": "technique", "value": tech})
        evidence_index[eid] = f"mitre:technique:{tech}"

    enrichment_block = {
        "summary": incident.metadata.get("enrichment_intel") is not None
        and bool((incident.metadata.get("enrichment_intel") or {}).get("ips")),
        "links": incident.enrichment_links or {},
        "intel_evidence": enrichment_items,
    }

    mitre_block = {
        "tactics": incident.mitre_tactics,
        "techniques": incident.mitre_techniques,
        "evidence_items": mitre_items,
    }

    components = _coverage_components(incident, incident.detections, incident.events)
    coverage_score = sum(components.values()) / max(len(components), 1)
    conflicts = _conflict_flags(incident, incident.detections, intel)

    triage_features = {
        "num_detections": len(incident.detections),
        "num_timeline_entries": len(timeline),
        "num_events": len(incident.events),
        "criticality_score": incident.criticality_score,
        "pipeline_confidence": incident.confidence,
        "severity": incident.severity,
        "has_enrichment_intel": enrichment_block["summary"],
        "metadata_evidence_id": e_meta,
        "metadata_summary": {
            "title": incident.title,
            "summary": (incident.summary or "")[:1200],
            "first_seen": str(incident.first_seen) if incident.first_seen else None,
            "last_seen": str(incident.last_seen) if incident.last_seen else None,
        },
    }

    coverage_summary = {
        "coverage_score": round(coverage_score, 4),
        "components": {k: round(v, 4) for k, v in components.items()},
        "strong_evidence_count": _strong_evidence_count(components, incident.detections, incident.events),
        "has_auth_signals": _event_signals(incident.events)[0],
        "has_outbound_or_ids": _event_signals(incident.events)[1] or _event_signals(incident.events)[2],
    }

    conflict_summary = {
        "flags": conflicts,
        "has_conflict": len(conflicts) > 0,
    }

    return EvidencePack(
        incident_id=incident.incident_id,
        incident_type=incident.incident_type,
        candidate_decision_space=["close", "escalate", "defer"],
        entities=_entity_block(incident),
        timeline=timeline,
        detections=detections,
        enrichment=enrichment_block,
        mitre=mitre_block,
        triage_features=triage_features,
        coverage_summary=coverage_summary,
        conflict_summary=conflict_summary,
        evidence_index=evidence_index,
    )


def all_pack_evidence_ids(pack: EvidencePack) -> Set[str]:
    ids: Set[str] = set(pack.evidence_index.keys())
    for row in pack.timeline:
        if row.get("evidence_id"):
            ids.add(str(row["evidence_id"]))
    for d in pack.detections:
        if d.get("evidence_id"):
            ids.add(str(d["evidence_id"]))
    for it in pack.enrichment.get("intel_evidence") or []:
        if isinstance(it, dict) and it.get("evidence_id"):
            ids.add(str(it["evidence_id"]))
    for it in pack.mitre.get("evidence_items") or []:
        if isinstance(it, dict) and it.get("evidence_id"):
            ids.add(str(it["evidence_id"]))
    tf = pack.triage_features.get("metadata_evidence_id")
    if tf:
        ids.add(str(tf))
    return ids
