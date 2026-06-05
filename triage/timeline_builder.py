from typing import Dict, List

from utils.schema import Event, Incident


def build_timeline(incident: Incident) -> List[Dict[str, str]]:
    """Build a chronological timeline of events from an incident."""
    entries: List[Dict[str, str]] = []

    sorted_events = sorted(
        [e for e in incident.events if e.timestamp],
        key=lambda e: e.timestamp,
    )

    for event in sorted_events:
        entry = {
            "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event.event_type,
            "source": event.log_source,
            "description": _describe_event(event),
        }
        entries.append(entry)

    return entries


def _describe_event(event: Event) -> str:
    parts = []
    if event.user:
        parts.append(f"User: {event.user}")
    if event.src_ip:
        parts.append(f"Source: {event.src_ip}")
    if event.dst_ip:
        parts.append(f"Dest: {event.dst_ip}")
    if event.host:
        parts.append(f"Host: {event.host}")
    if event.alert_name:
        parts.append(f"Alert: {event.alert_name}")
    if event.action:
        parts.append(f"Action: {event.action}")
    return " | ".join(parts) if parts else event.raw_log[:100]
