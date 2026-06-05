import os
from typing import List

from triage.enrichment_intel import fetch_enrichment_intel
from triage.enrichment_links import generate_enrichment_links
from triage.entity_identifier import identify_entities
from triage.mitre_mapper import map_to_mitre
from triage.knowledge_graph import build_knowledge_graph
from triage.recommendation_engine import generate_recommendations
from triage.severity_engine import calculate_criticality
from triage.timeline_builder import build_timeline
from utils.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
from utils.schema import Incident


def enrich_incident(incident: Incident) -> Incident:
    """Run all triage modules to fully enrich an incident."""
    entities = identify_entities(incident)
    incident.affected_user = entities.get("affected_user") or incident.affected_user
    incident.affected_host = entities.get("affected_host") or incident.affected_host
    incident.primary_src_ip = entities.get("primary_src_ip") or incident.primary_src_ip
    incident.primary_dst_ip = entities.get("primary_dst_ip") or incident.primary_dst_ip

    tactics, techniques = map_to_mitre(incident)
    incident.mitre_tactics = tactics
    incident.mitre_techniques = techniques

    score, severity = calculate_criticality(incident)
    incident.criticality_score = score
    incident.severity = severity

    actions, next_steps = generate_recommendations(incident)
    incident.recommended_actions = actions
    incident.next_steps = next_steps

    _local_only = os.getenv("BENCHMARK_LOCAL_ENRICHMENT_ONLY", "").lower() in ("1", "true", "yes")
    if not _local_only and (VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY):
        # API-backed intel only — no redundant VT/Abuse/Shodan URL pills.
        incident.enrichment_links = {}
        incident.metadata["enrichment_intel"] = fetch_enrichment_intel(incident)
    else:
        incident.enrichment_links = generate_enrichment_links(incident)

    timeline = build_timeline(incident)
    incident.metadata["timeline"] = timeline
    incident.metadata["entities"] = entities
    kg = build_knowledge_graph(incident)
    incident.metadata["knowledge_graph"] = kg

    from connectors import neo4j_graph as _neo4j

    if _neo4j.neo4j_configured():
        try:
            ok, msg = _neo4j.sync_incident_knowledge_graph(incident.incident_id, kg)
        except Exception as e:
            ok, msg = False, str(e)
        incident.metadata["neo4j_last_sync"] = {"ok": ok, "message": msg}

    return incident


def enrich_all_incidents(incidents: List[Incident]) -> List[Incident]:
    return [enrich_incident(inc) for inc in incidents]
