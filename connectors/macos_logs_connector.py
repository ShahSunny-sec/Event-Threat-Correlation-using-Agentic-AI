from __future__ import annotations

import re
import socket
import subprocess
from datetime import datetime
from typing import List, Optional, Sequence

from dateutil import parser as dt_parser

from utils.schema import Event


class MacOSLogsConnectorError(Exception):
    pass


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"\buser\s+([A-Za-z0-9._-]+)\b", re.IGNORECASE)
DEFAULT_SIGNAL_KEYWORDS = [
    "sshd",
    "sudo",
    "securityd",
    "networkextension",
    "loginwindow",
    "failed password",
    "authentication",
    "denied",
    "blocked",
    "firewall",
]


def _parse_ts(line: str) -> Optional[datetime]:
    # syslog style often starts with "YYYY-MM-DD HH:MM:SS.ssssss±zzzz"
    tokens = line.split(" ", 2)
    if len(tokens) < 2:
        return None
    try:
        return dt_parser.parse(f"{tokens[0]} {tokens[1]}")
    except Exception:
        return None


def _etype(line_lower: str) -> str:
    if "failed" in line_lower and ("auth" in line_lower or "login" in line_lower or "ssh" in line_lower):
        return "authentication_failure"
    if "accepted" in line_lower or "successful" in line_lower or "login succeeded" in line_lower:
        return "authentication_success"
    if "deny" in line_lower or "blocked" in line_lower:
        return "ids_alert"
    if "connect" in line_lower or "outbound" in line_lower or "destination" in line_lower:
        return "network_outbound"
    return "system_event"


def _to_event(line: str) -> Event:
    ips = _IP_RE.findall(line)
    src_ip = ips[0] if ips else None
    dst_ip = ips[1] if len(ips) > 1 else None
    m_user = _USER_RE.search(line)
    line_lower = line.lower()
    et = _etype(line_lower)
    sev = "warning" if "failed" in line_lower or "error" in line_lower else "info"
    if "denied" in line_lower or "blocked" in line_lower:
        sev = "high"
    return Event(
        timestamp=_parse_ts(line),
        log_source="macos_unified",
        event_type=et,
        raw_log=line[:1200],
        user=m_user.group(1) if m_user else None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        host=socket.gethostname(),
        severity=sev,
        action="allow" if "accepted" in line_lower else None,
        direction="outbound" if et == "network_outbound" else None,
        tags=["macos", "live_log"],
    )


def _filter_lines(lines: List[str], keywords: Sequence[str]) -> List[str]:
    if not keywords:
        return lines
    keys = [k.lower().strip() for k in keywords if k and k.strip()]
    if not keys:
        return lines
    out: List[str] = []
    for ln in lines:
        ll = ln.lower()
        if any(k in ll for k in keys):
            out.append(ln)
    return out


class MacOSLogsConnector:
    def fetch_recent(
        self,
        minutes_back: int = 60,
        limit: int = 1500,
        signal_only: bool = True,
        keywords: Optional[Sequence[str]] = None,
    ) -> List[Event]:
        cmd = ["log", "show", "--last", f"{minutes_back}m", "--style", "syslog"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        except Exception as exc:
            raise MacOSLogsConnectorError(f"log show failed: {exc}") from exc
        if proc.returncode != 0:
            raise MacOSLogsConnectorError(proc.stderr.strip() or "log show command failed")
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if signal_only:
            lines = _filter_lines(lines, keywords or DEFAULT_SIGNAL_KEYWORDS)
        lines = lines[-limit:]
        return [_to_event(ln) for ln in lines]

    def fetch_live_window(
        self,
        poll_seconds: int = 12,
        limit: int = 1000,
        signal_only: bool = True,
        keywords: Optional[Sequence[str]] = None,
    ) -> List[Event]:
        # Short live stream capture, then parse captured lines.
        cmd = ["log", "stream", "--style", "syslog"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                out, _err = proc.communicate(timeout=max(4, poll_seconds))
            except subprocess.TimeoutExpired:
                proc.terminate()
                out, _err = proc.communicate(timeout=4)
        except Exception as exc:
            raise MacOSLogsConnectorError(f"log stream failed: {exc}") from exc
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if signal_only:
            lines = _filter_lines(lines, keywords or DEFAULT_SIGNAL_KEYWORDS)
        lines = lines[-limit:]
        return [_to_event(ln) for ln in lines]
