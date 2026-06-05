"""Parse Apache common / combined lines from flog into normalized Events."""
from __future__ import annotations

import re
from typing import List, Optional

from dateutil import parser as dateutil_parser

from utils.constants import (
    DIRECTION_INBOUND,
    EVENT_TYPE_NETWORK_INBOUND,
)
from utils.helpers import safe_int
from utils.schema import Event

# Apache common / combined (loose)
_APACHE_LINE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)',
)


def _parse_apache_time(s: str):
    try:
        return dateutil_parser.parse(s.replace(":", " ", 1))
    except Exception:
        return dateutil_parser.parse(s)


def parse_apache_lines(content: str, format_hint: str = "apache_common") -> List[Event]:
    """Parse multi-line Apache access log text into Events."""
    events: List[Event] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _APACHE_LINE.match(line)
        if not m:
            continue
        ts_raw = m.group("ts")
        ts = _parse_apache_time(ts_raw)
        req = m.group("req") or ""
        parts = req.split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"
        status = safe_int(m.group("status"), 200)
        src_ip = m.group("src_ip")

        sev = "info"
        if status >= 500:
            sev = "high"
        elif status >= 400:
            sev = "medium"

        events.append(
            Event(
                timestamp=ts,
                log_source="apache_flog",
                event_type=EVENT_TYPE_NETWORK_INBOUND,
                raw_log=line,
                src_ip=src_ip,
                dst_ip=None,
                host=None,
                protocol="http",
                direction=DIRECTION_INBOUND,
                action=method.lower(),
                severity=sev,
                tags=["flog", "apache", format_hint],
                extra={"path": path, "status": status, "request": req},
            )
        )
    return events
