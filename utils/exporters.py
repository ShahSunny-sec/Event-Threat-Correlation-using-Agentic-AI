import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List

from utils.schema import Incident


def _serialize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialize(v) for k, v in obj.__dict__.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


def incident_to_dict(incident: Incident) -> Dict[str, Any]:
    return _serialize(incident)


def export_incident_json(incident: Incident) -> str:
    return json.dumps(incident_to_dict(incident), indent=2)


def export_incidents_json(incidents: List[Incident]) -> str:
    return json.dumps([incident_to_dict(i) for i in incidents], indent=2)


def export_incident_csv(incident: Incident) -> str:
    d = incident_to_dict(incident)
    flat = {
        "incident_id": d.get("incident_id", ""),
        "title": d.get("title", ""),
        "summary": d.get("summary", ""),
        "severity": d.get("severity", ""),
        "criticality_score": d.get("criticality_score", 0),
        "confidence": d.get("confidence", 0),
        "affected_user": d.get("affected_user", ""),
        "affected_host": d.get("affected_host", ""),
        "primary_src_ip": d.get("primary_src_ip", ""),
        "primary_dst_ip": d.get("primary_dst_ip", ""),
        "first_seen": d.get("first_seen", ""),
        "last_seen": d.get("last_seen", ""),
        "num_detections": len(d.get("detections", [])),
        "num_events": len(d.get("events", [])),
        "mitre_tactics": "; ".join(d.get("mitre_tactics", [])),
        "mitre_techniques": "; ".join(d.get("mitre_techniques", [])),
        "recommended_actions": "; ".join(d.get("recommended_actions", [])),
    }
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=flat.keys())
    writer.writeheader()
    writer.writerow(flat)
    return buf.getvalue()
