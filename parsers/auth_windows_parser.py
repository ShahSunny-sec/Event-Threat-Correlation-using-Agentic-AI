import csv
import io
from typing import List

from utils.constants import (
    EVENT_TYPE_AUTH_FAILURE,
    EVENT_TYPE_AUTH_SUCCESS,
    LOG_SOURCE_WINDOWS_AUTH,
)
from utils.helpers import parse_timestamp, safe_int
from utils.schema import Event


def parse_windows_auth(content: str) -> List[Event]:
    """Parse Windows-style auth CSV logs into normalized Event objects."""
    events: List[Event] = []
    reader = csv.DictReader(io.StringIO(content))

    for row in reader:
        status = (row.get("status") or "").strip().lower()
        if status == "failure":
            event_type = EVENT_TYPE_AUTH_FAILURE
        elif status == "success":
            event_type = EVENT_TYPE_AUTH_SUCCESS
        else:
            event_type = f"auth_{status}" if status else "auth_unknown"

        raw_log = ",".join(f"{k}={v}" for k, v in row.items())
        ts = parse_timestamp(row.get("timestamp", ""))
        event_id_code = safe_int(row.get("event_id_code", 0))

        event = Event(
            timestamp=ts,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=event_type,
            raw_log=raw_log,
            user=row.get("user", "").strip() or None,
            src_ip=row.get("src_ip", "").strip() or None,
            host=row.get("host", "").strip() or None,
            action=status,
            severity="medium" if event_type == EVENT_TYPE_AUTH_FAILURE else "info",
            extra={
                "logon_type": row.get("logon_type", "").strip(),
                "event_id_code": event_id_code,
            },
        )
        events.append(event)

    return events
