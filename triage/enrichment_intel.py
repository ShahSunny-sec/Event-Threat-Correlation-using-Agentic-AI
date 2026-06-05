"""Optional live enrichment via VirusTotal and AbuseIPDB APIs.

Uses API keys from environment only (never commit real keys).
Respects AbuseIPDB ~1 req/s guidance when querying multiple IPs.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Set

import requests

from utils.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
from utils.schema import Incident


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False


def _public_ips(incident: Incident) -> List[str]:
    found: Set[str] = set()
    for ip in (
        incident.primary_src_ip,
        incident.primary_dst_ip,
    ):
        if ip and not _is_private_ip(ip):
            found.add(ip)
    for e in incident.events:
        if e.src_ip and not _is_private_ip(e.src_ip):
            found.add(e.src_ip)
        if e.dst_ip and not _is_private_ip(e.dst_ip):
            found.add(e.dst_ip)
    return sorted(found)


def _vt_lookup(ip: str) -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {"skipped": True, "reason": "no API key"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(
            url,
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)[:200]}

    if r.status_code == 404:
        return {"error": "not found in VT"}
    if r.status_code == 401:
        return {"error": "invalid VirusTotal API key"}
    if r.status_code == 429:
        return {"error": "VirusTotal rate limit — try again later"}
    if r.status_code >= 400:
        return {"error": f"HTTP {r.status_code}"}

    try:
        data = r.json()
    except ValueError:
        return {"error": "invalid JSON response"}

    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "last_analysis_stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        },
        "reputation": attrs.get("reputation"),
        "country": (attrs.get("country") or "")[:2] or None,
    }


def _abuse_lookup(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {"skipped": True, "reason": "no API key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        r = requests.get(
            url,
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)[:200]}

    if r.status_code == 401:
        return {"error": "invalid AbuseIPDB API key"}
    if r.status_code == 429:
        return {"error": "AbuseIPDB rate limit — wait and retry"}
    if r.status_code >= 400:
        return {"error": f"HTTP {r.status_code}"}

    try:
        payload = r.json()
    except ValueError:
        return {"error": "invalid JSON response"}

    d = payload.get("data") or {}
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "num_distinct_users": d.get("numDistinctUsers"),
        "country_code": d.get("countryCode"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
    }


def fetch_enrichment_intel(incident: Incident) -> Dict[str, Any]:
    """Return per–public-IP summaries from VT and AbuseIPDB when keys are set."""
    ips = _public_ips(incident)
    if not ips:
        return {"note": "No public IPs on this incident — API enrichment skipped."}

    out: Dict[str, Any] = {"ips": {}, "queried_at_utc": None}
    from datetime import datetime, timezone

    out["queried_at_utc"] = datetime.now(timezone.utc).isoformat()

    abuse_used = False
    for ip in ips:
        entry: Dict[str, Any] = {}
        entry["virustotal"] = _vt_lookup(ip)
        if ABUSEIPDB_API_KEY:
            if abuse_used:
                time.sleep(1.15)
            entry["abuseipdb"] = _abuse_lookup(ip)
            abuse_used = True
        else:
            entry["abuseipdb"] = {"skipped": True, "reason": "no API key"}
        out["ips"][ip] = entry

    return out
