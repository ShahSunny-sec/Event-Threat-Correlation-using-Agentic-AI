from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from utils.schema import Incident


def build_knowledge_graph(incident: Incident) -> Dict[str, List[Dict[str, Any]]]:
    """Build a simple entity-event graph for an incident."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: Set[Tuple[str, str]] = set()
    seen_edges: Set[Tuple[str, str, str]] = set()

    def add_node(kind: str, value) -> str:
        # Guard against list/None values that would break set hashing
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value) if value else ""
        elif value is None:
            value = ""
        else:
            value = str(value)
        key = (kind, value)
        if key not in seen_nodes:
            seen_nodes.add(key)
            nodes.append({"id": f"{kind}:{value}", "type": kind, "label": value})
        return f"{kind}:{value}"

    def add_edge(src: str, relation: str, dst: str) -> None:
        key = (src, relation, dst)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({"source": src, "relation": relation, "target": dst})

    inc_id = add_node("incident", incident.incident_id)
    for d in incident.detections:
        det_id = add_node("detection", d.detection_name or d.detection_id)
        add_edge(inc_id, "contains_detection", det_id)
        if d.user:
            u = add_node("user", d.user)
            add_edge(det_id, "targets_user", u)
        if d.host:
            h = add_node("host", d.host)
            add_edge(det_id, "targets_host", h)
        if d.src_ip:
            s = add_node("ip", d.src_ip)
            add_edge(det_id, "source_ip", s)
        if d.dst_ip:
            t = add_node("ip", d.dst_ip)
            add_edge(det_id, "destination_ip", t)
        for e in d.events:
            if e.event_type:
                et = add_node("event_type", e.event_type)
                add_edge(det_id, "derived_from", et)

    return {"nodes": nodes, "edges": edges}
