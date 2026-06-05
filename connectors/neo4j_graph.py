"""Optional Neo4j sync for incident knowledge graphs (Bolt)."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from utils.config import NEO4J_BROWSER_URL, NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER


def neo4j_configured() -> bool:
    return bool(NEO4J_URI and NEO4J_PASSWORD)


def connectivity_status() -> Dict[str, Any]:
    """Return configuration and live connectivity state for the Neo4j graph memory."""
    if not neo4j_configured():
        return {
            "configured": False,
            "connected": False,
            "message": "Neo4j is not configured. Set NEO4J_URI and NEO4J_PASSWORD in .env.",
        }

    try:
        driver = _driver()
        driver.verify_connectivity()
        driver.close()
    except Exception as e:
        return {
            "configured": True,
            "connected": False,
            "message": f"Neo4j configured but not connected: {e}",
        }

    return {
        "configured": True,
        "connected": True,
        "message": "Neo4j connection verified.",
    }


def scoped_node_id(incident_id: str, raw_id: str) -> str:
    return f"{incident_id}||{raw_id}"


def _driver():
    from neo4j import GraphDatabase  # type: ignore

    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def sync_incident_knowledge_graph(incident_id: str, kg: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Replace the Neo4j subgraph for this incident with nodes/edges from ``kg``.
    Uses scoped node ids so incidents stay isolated and re-sync is safe.
    """
    if not neo4j_configured():
        return False, "Neo4j is not configured (set NEO4J_URI and NEO4J_PASSWORD in .env)."

    nodes: List[Dict[str, Any]] = list(kg.get("nodes") or [])
    edges: List[Dict[str, Any]] = list(kg.get("edges") or [])

    try:
        driver = _driver()
    except Exception as e:  # pragma: no cover - import / driver init
        return False, f"Neo4j driver error: {e}"

    delete_cypher = """
    MATCH (n:KnowledgeNode {incident_id: $iid})
    DETACH DELETE n
    """

    merge_node_cypher = """
    MERGE (n:KnowledgeNode {gid: $gid})
    SET n.incident_id = $iid,
        n.graph_id = $graph_id,
        n.ntype = $ntype,
        n.label = $label
    """

    merge_edge_cypher = """
    MATCH (a:KnowledgeNode {gid: $src}), (b:KnowledgeNode {gid: $dst})
    MERGE (a)-[r:RELATED {incident_id: $iid, name: $rel_name}]->(b)
    """

    try:
        with driver.session() as session:
            session.run(delete_cypher, iid=incident_id)
            for node in nodes:
                raw = str(node.get("id") or "")
                gid = scoped_node_id(incident_id, raw)
                session.run(
                    merge_node_cypher,
                    gid=gid,
                    iid=incident_id,
                    graph_id=raw,
                    ntype=str(node.get("type") or ""),
                    label=str(node.get("label") or ""),
                )
            for edge in edges:
                s = str(edge.get("source") or "")
                t = str(edge.get("target") or "")
                rel = str(edge.get("relation") or "related")
                session.run(
                    merge_edge_cypher,
                    src=scoped_node_id(incident_id, s),
                    dst=scoped_node_id(incident_id, t),
                    iid=incident_id,
                    rel_name=rel,
                )
        driver.close()
    except Exception as e:
        try:
            driver.close()
        except Exception:
            pass
        return False, str(e)

    return True, f"Synced {len(nodes)} nodes, {len(edges)} edges for {incident_id}."


def fetch_incident_knowledge_graph(incident_id: str) -> Tuple[bool, Dict[str, Any], str]:
    """Read an incident subgraph back from Neo4j in the same shape used by the UI."""
    if not neo4j_configured():
        return False, {"nodes": [], "edges": []}, "Neo4j is not configured."

    cypher = """
    MATCH (n:KnowledgeNode {incident_id: $iid})
    OPTIONAL MATCH (n)-[r:RELATED {incident_id: $iid}]->(m:KnowledgeNode {incident_id: $iid})
    RETURN n, r, m
    LIMIT 500
    """

    try:
        driver = _driver()
    except Exception as e:  # pragma: no cover - import / driver init
        return False, {"nodes": [], "edges": []}, f"Neo4j driver error: {e}"

    nodes_by_gid: Dict[str, Dict[str, Any]] = {}
    edge_keys = set()
    edges: List[Dict[str, Any]] = []
    try:
        with driver.session() as session:
            for record in session.run(cypher, iid=incident_id):
                for key in ("n", "m"):
                    node = record.get(key)
                    if node is None:
                        continue
                    props = dict(node)
                    gid = str(props.get("gid") or "")
                    if not gid:
                        continue
                    graph_id = str(props.get("graph_id") or gid.split("||", 1)[-1])
                    nodes_by_gid[gid] = {
                        "id": graph_id,
                        "type": str(props.get("ntype") or "node"),
                        "label": str(props.get("label") or graph_id),
                    }
                rel = record.get("r")
                src = record.get("n")
                dst = record.get("m")
                if rel is None or src is None or dst is None:
                    continue
                src_props = dict(src)
                dst_props = dict(dst)
                src_id = str(src_props.get("graph_id") or "").strip()
                dst_id = str(dst_props.get("graph_id") or "").strip()
                rel_name = str(dict(rel).get("name") or "related")
                edge_key = (src_id, rel_name, dst_id)
                if src_id and dst_id and edge_key not in edge_keys:
                    edge_keys.add(edge_key)
                    edges.append({"source": src_id, "relation": rel_name, "target": dst_id})
        driver.close()
    except Exception as e:
        try:
            driver.close()
        except Exception:
            pass
        return False, {"nodes": [], "edges": []}, str(e)

    graph = {"nodes": list(nodes_by_gid.values()), "edges": edges}
    return True, graph, f"Fetched {len(graph['nodes'])} nodes, {len(edges)} edges from Neo4j."


def cypher_subgraph_query(incident_id: str) -> str:
    safe = incident_id.replace("\\", "\\\\").replace("'", "\\'")
    return (
        f"MATCH (n:KnowledgeNode {{incident_id: '{safe}'}})-[r:RELATED]->(m)\n"
        f"WHERE m.incident_id = '{safe}'\n"
        "RETURN n, r, m\n"
        "LIMIT 500"
    )


def browser_url() -> str:
    return NEO4J_BROWSER_URL.rstrip("/")
