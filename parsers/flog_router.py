"""Route flog stdout to the right parser for normalized Events."""
from __future__ import annotations

import json
from typing import List

from parsers.apache_flog_parser import parse_apache_lines
from parsers.syslog_flog_parser import parse_syslog_lines
from utils.constants import EVENT_TYPE_NETWORK_INBOUND
from utils.schema import Event


def parse_flog_output(text: str, fmt: str) -> List[Event]:
    fmt = (fmt or "apache_common").lower()
    if fmt in ("apache_common", "apache_combined"):
        return parse_apache_lines(text, format_hint=fmt)
    if fmt in ("rfc3164", "rfc5424"):
        return parse_syslog_lines(text, fmt=fmt)
    if fmt == "apache_error":
        return _parse_generic_lines(text, log_source="apache_error_flog", tag="apache_error")
    if fmt == "json":
        return _parse_json_lines(text)
    return _parse_generic_lines(text, log_source="flog_unknown", tag=fmt)


def _parse_generic_lines(text: str, log_source: str, tag: str) -> List[Event]:
    out: List[Event] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(
            Event(
                log_source=log_source,
                event_type=EVENT_TYPE_NETWORK_INBOUND,
                raw_log=line,
                severity="info",
                tags=["flog", tag],
            )
        )
    return out


def _parse_json_lines(text: str) -> List[Event]:
    out: List[Event] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            out.append(
                Event(
                    log_source="flog_json",
                    event_type=EVENT_TYPE_NETWORK_INBOUND,
                    raw_log=line,
                    tags=["flog", "json"],
                )
            )
            continue
        out.append(
            Event(
                log_source="flog_json",
                event_type=EVENT_TYPE_NETWORK_INBOUND,
                raw_log=line,
                host=obj.get("host"),
                severity="info",
                tags=["flog", "json"],
                extra=obj if isinstance(obj, dict) else {},
            )
        )
    return out
