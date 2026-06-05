from typing import Any, Dict

from triage.timeline_builder import build_timeline
from utils.schema import Incident


def build_incident_context(incident: Incident) -> Dict[str, Any]:
    """Convert an enriched Incident into a plain dictionary for AI consumption."""
    timeline = incident.metadata.get("timeline") or build_timeline(incident)

    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "criticality_score": incident.criticality_score,
        "confidence": incident.confidence,
        "affected_user": incident.affected_user,
        "affected_host": incident.affected_host,
        "primary_src_ip": incident.primary_src_ip,
        "primary_dst_ip": incident.primary_dst_ip,
        "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
        "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
        "timeline": timeline,
        "detections": [
            {
                "name": d.detection_name,
                "type": d.detection_type,
                "description": d.description,
                "severity": d.severity,
                "confidence": d.confidence,
            }
            for d in incident.detections
        ],
        "mitre_tactics": incident.mitre_tactics,
        "mitre_techniques": incident.mitre_techniques,
        "recommended_actions": incident.recommended_actions,
        "next_steps": incident.next_steps,
        "enrichment_links": incident.enrichment_links,
        "enrichment_intel": incident.metadata.get("enrichment_intel"),
        "num_events": len(incident.events),
        "has_ids_alert": incident.metadata.get("has_ids_alert", False),
    }
