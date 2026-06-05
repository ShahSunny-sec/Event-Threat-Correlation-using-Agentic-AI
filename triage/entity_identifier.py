from typing import Dict, List, Optional
from collections import Counter

from utils.schema import Incident


def identify_entities(incident: Incident) -> Dict[str, Optional[str]]:
    """Extract the primary affected entities from an incident."""
    users = [e.user for e in incident.events if e.user]
    hosts = [e.host for e in incident.events if e.host]
    src_ips = [e.src_ip for e in incident.events if e.src_ip]
    dst_ips = [e.dst_ip for e in incident.events if e.dst_ip]

    return {
        "affected_user": _most_common(users) or incident.affected_user,
        "affected_host": _most_common(hosts) or incident.affected_host,
        "primary_src_ip": _most_common(src_ips) or incident.primary_src_ip,
        "primary_dst_ip": _most_common(dst_ips) or incident.primary_dst_ip,
        "all_users": list(set(users)),
        "all_hosts": list(set(hosts)),
        "all_src_ips": list(set(src_ips)),
        "all_dst_ips": list(set(dst_ips)),
    }


def _most_common(items: List[str]) -> Optional[str]:
    if not items:
        return None
    counter = Counter(items)
    return counter.most_common(1)[0][0]
