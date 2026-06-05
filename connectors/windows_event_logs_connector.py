from __future__ import annotations

import json
import platform
import re
import socket
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

from dateutil import parser as dt_parser

from utils.schema import Event


class WindowsEventLogsConnectorError(Exception):
    pass


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ACCOUNT_RE = re.compile(r"Account Name:\s*([A-Za-z0-9._$-]+)", re.IGNORECASE)


def _parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return dt_parser.parse(str(value))
    except Exception:
        return None


def _event_type(event_id: int, message: str) -> str:
    lower = message.lower()
    if event_id == 4625 or "failed" in lower and "logon" in lower:
        return "authentication_failure"
    if event_id == 4624 or "successful" in lower and "logon" in lower:
        return "authentication_success"
    if event_id in {5156, 5157} or "connection" in lower or "network" in lower:
        return "network_outbound"
    return "windows_event"


def _to_event(item: Dict[str, Any]) -> Event:
    message = str(item.get("Message") or "")
    event_id = int(item.get("Id") or 0)
    ips = _IP_RE.findall(message)
    account = _ACCOUNT_RE.search(message)
    level = str(item.get("LevelDisplayName") or "Information").lower()
    event_type = _event_type(event_id, message)
    severity = "high" if event_type == "authentication_failure" else "info"
    if "error" in level or "warning" in level:
        severity = "warning"
    return Event(
        timestamp=_parse_time(item.get("TimeCreated")),
        log_source="windows_event_log",
        event_type=event_type,
        raw_log=message[:1200] or json.dumps(item)[:1200],
        user=account.group(1) if account else None,
        src_ip=ips[0] if ips else None,
        dst_ip=ips[1] if len(ips) > 1 else None,
        host=socket.gethostname(),
        severity=severity,
        tags=["windows", "event_log", f"event_id:{event_id}"],
        extra={"event_id": event_id, "provider": item.get("ProviderName")},
    )


class WindowsEventLogsConnector:
    def fetch_recent(self, minutes_back: int = 60, limit: int = 800) -> List[Event]:
        if platform.system().lower() != "windows":
            raise WindowsEventLogsConnectorError(
                "Windows Event Log collection requires running the API on Windows."
            )

        minutes = max(5, min(int(minutes_back), 240))
        max_events = max(50, min(int(limit), 3000))
        script = (
            "$start=(Get-Date).AddMinutes(-"
            f"{minutes}); "
            "Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start} "
            f"-MaxEvents {max_events} | "
            "Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message | "
            "ConvertTo-Json -Depth 4"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except Exception as exc:
            raise WindowsEventLogsConnectorError(f"PowerShell log query failed: {exc}") from exc

        if proc.returncode != 0:
            raise WindowsEventLogsConnectorError(proc.stderr.strip() or "Get-WinEvent failed")

        text = (proc.stdout or "").strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise WindowsEventLogsConnectorError("PowerShell returned invalid JSON") from exc
        items = parsed if isinstance(parsed, list) else [parsed]
        return [_to_event(item) for item in items if isinstance(item, dict)]
