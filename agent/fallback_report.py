from typing import Any, Dict


def build_fallback_report(ctx: Dict[str, Any]) -> str:
    """Generate a deterministic analyst report from structured incident fields."""
    lines = [
        "=" * 60,
        "INCIDENT INVESTIGATION REPORT",
        "=" * 60,
        "",
        f"Incident ID:      {ctx.get('incident_id', 'N/A')}",
        f"Title:            {ctx.get('title', 'N/A')}",
        f"Severity:         {ctx.get('severity', 'N/A').upper()}",
        f"Criticality Score: {ctx.get('criticality_score', 'N/A')} / 100",
        f"Confidence:       {ctx.get('confidence', 'N/A')}",
        f"First Seen:       {ctx.get('first_seen', 'N/A')}",
        f"Last Seen:        {ctx.get('last_seen', 'N/A')}",
        "",
        "-" * 60,
        "SUMMARY",
        "-" * 60,
        ctx.get("summary", "No summary available."),
        "",
        "-" * 60,
        "AFFECTED ENTITIES",
        "-" * 60,
        f"  User:           {ctx.get('affected_user', 'N/A')}",
        f"  Host:           {ctx.get('affected_host', 'N/A')}",
        f"  Source IP:      {ctx.get('primary_src_ip', 'N/A')}",
        f"  Destination IP: {ctx.get('primary_dst_ip', 'N/A')}",
        "",
    ]

    lines.extend(["-" * 60, "DETECTIONS", "-" * 60])
    for det in ctx.get("detections", []):
        lines.append(f"  [{det.get('severity', '').upper()}] {det.get('name', 'Unknown')}")
        lines.append(f"    {det.get('description', '')}")
        lines.append(f"    Confidence: {det.get('confidence', 'N/A')}")
        lines.append("")

    lines.extend(["-" * 60, "EVENT TIMELINE", "-" * 60])
    for entry in ctx.get("timeline", []):
        lines.append(
            f"  {entry.get('timestamp', '')}  "
            f"[{entry.get('event_type', '')}]  "
            f"{entry.get('description', '')}"
        )
    lines.append("")

    lines.extend(["-" * 60, "MITRE ATT&CK MAPPING", "-" * 60])
    for tactic in ctx.get("mitre_tactics", []):
        lines.append(f"  Tactic:    {tactic}")
    for technique in ctx.get("mitre_techniques", []):
        lines.append(f"  Technique: {technique}")
    lines.append("")

    lines.extend(["-" * 60, "RECOMMENDED ACTIONS", "-" * 60])
    for i, action in enumerate(ctx.get("recommended_actions", []), 1):
        lines.append(f"  {i}. {action}")
    lines.append("")

    lines.extend(["-" * 60, "NEXT STEPS", "-" * 60])
    for i, step in enumerate(ctx.get("next_steps", []), 1):
        lines.append(f"  {i}. {step}")
    lines.append("")

    lines.extend(["-" * 60, "ENRICHMENT LINKS", "-" * 60])
    for label, url in ctx.get("enrichment_links", {}).items():
        lines.append(f"  {label}: {url}")
    lines.append("")

    if ctx.get("has_ids_alert"):
        lines.extend([
            "-" * 60,
            "NOTE: IDS alert evidence is present for this incident,",
            "increasing confidence in malicious activity.",
            "-" * 60,
        ])

    lines.extend(["", "=" * 60, "END OF REPORT", "=" * 60])
    return "\n".join(lines)
