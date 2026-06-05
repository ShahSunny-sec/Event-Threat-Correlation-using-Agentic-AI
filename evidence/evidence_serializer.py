"""JSON serialization for EvidencePack."""
from __future__ import annotations

import json
from typing import Any, Dict

from evidence.evidence_models import EvidencePack


def pack_to_json(pack: EvidencePack, indent: int = 2) -> str:
    return json.dumps(pack.to_dict(), indent=indent, default=str)


def pack_from_dict(d: Dict[str, Any]) -> EvidencePack:
    return EvidencePack(
        incident_id=str(d["incident_id"]),
        incident_type=str(d.get("incident_type") or ""),
        candidate_decision_space=list(d.get("candidate_decision_space") or ["close", "escalate", "defer"]),
        entities=dict(d.get("entities") or {}),
        timeline=list(d.get("timeline") or []),
        detections=list(d.get("detections") or []),
        enrichment=dict(d.get("enrichment") or {}),
        mitre=dict(d.get("mitre") or {}),
        triage_features=dict(d.get("triage_features") or {}),
        coverage_summary=dict(d.get("coverage_summary") or {}),
        conflict_summary=dict(d.get("conflict_summary") or {}),
        evidence_index=dict(d.get("evidence_index") or {}),
    )
