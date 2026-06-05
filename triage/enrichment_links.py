from typing import Dict

from utils.schema import Incident


def generate_enrichment_links(incident: Incident) -> Dict[str, str]:
    """Generate clickable enrichment/investigation links for incident IPs."""
    links: Dict[str, str] = {}

    ips = set()
    if incident.primary_src_ip:
        ips.add(incident.primary_src_ip)
    if incident.primary_dst_ip:
        ips.add(incident.primary_dst_ip)
    for event in incident.events:
        if event.src_ip:
            ips.add(event.src_ip)
        if event.dst_ip:
            ips.add(event.dst_ip)

    for ip in ips:
        if _is_private_ip(ip):
            continue
        links[f"VirusTotal ({ip})"] = f"https://www.virustotal.com/gui/ip-address/{ip}"
        links[f"AbuseIPDB ({ip})"] = f"https://www.abuseipdb.com/check/{ip}"
        links[f"Shodan ({ip})"] = f"https://www.shodan.io/host/{ip}"
        links[f"GreyNoise ({ip})"] = f"https://viz.greynoise.io/ip/{ip}"

    return links


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False
