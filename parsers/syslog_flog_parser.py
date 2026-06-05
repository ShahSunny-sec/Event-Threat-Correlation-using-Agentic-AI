"""Parse RFC3164 / RFC5424-ish syslog lines from flog into normalized Events."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List

from dateutil import parser as dateutil_parser

from utils.constants import EVENT_TYPE_IDS_ALERT, EVENT_TYPE_NETWORK_INBOUND
from utils.schema import Event

# Very loose syslog patterns (flog output varies)
_RFC3164 = re.compile(
    r"^<\d+>(?P<ts>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.+)$"
)
_RFC5424 = re.compile(
    r"^<\d+>1\s+(?P<ts_iso>\S+)\s+(?P<host>\S+)\s+(?P<msg>.+)$"
)


def parse_syslog_lines(content: str, fmt: str = "rfc3164") -> List[Event]:
    events: List[Event] = []
    year = datetime.now(timezone.utc).year

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        host = None
        msg = line
        ts = None

        m = _RFC5424.match(line)
        if m:
            try:
                ts = dateutil_parser.parse(m.group("ts_iso"))
            except Exception:
                ts = None
            host = m.group("host")
            msg = m.group("msg")
        else:
            m2 = _RFC3164.match(line)
            if m2:
                try:
                    ts = dateutil_parser.parse(
                        f"{year} {m2.group('ts')}",
                    )
                except Exception:
                    ts = None
                host = m2.group("host")
                msg = m2.group("msg")

        et = EVENT_TYPE_IDS_ALERT if any(
            k in msg.lower() for k in ("error", "fail", "denied", "attack", "alert")
        ) else EVENT_TYPE_NETWORK_INBOUND

        events.append(
            Event(
                timestamp=ts,
                log_source="syslog_flog",
                event_type=et,
                raw_log=line,
                host=host,
                alert_name=msg[:120] if et == EVENT_TYPE_IDS_ALERT else None,
                severity="high" if et == EVENT_TYPE_IDS_ALERT else "info",
                tags=["flog", fmt],
                extra={"message": msg[:500]},
            )
        )
    return events
