import csv
import io
from typing import List

from utils.constants import (
    DIRECTION_OUTBOUND,
    EVENT_TYPE_IDS_ALERT,
    EVENT_TYPE_NETWORK_INBOUND,
    EVENT_TYPE_NETWORK_OUTBOUND,
    LOG_SOURCE_NETWORK_IDS,
)
from utils.helpers import parse_timestamp, safe_int
from utils.schema import Event


def parse_network_ids(content: str) -> List[Event]:
    """Parse network/IDS CSV logs into normalized Event objects."""
    events: List[Event] = []
    reader = csv.DictReader(io.StringIO(content))

    for row in reader:
        direction = (row.get("direction") or "").strip().lower()
        alert_name = (row.get("alert_name") or "").strip()

        if alert_name:
            event_type = EVENT_TYPE_IDS_ALERT
        elif direction == DIRECTION_OUTBOUND:
            event_type = EVENT_TYPE_NETWORK_OUTBOUND
        else:
            event_type = EVENT_TYPE_NETWORK_INBOUND

        raw_log = ",".join(f"{k}={v}" for k, v in row.items())
        ts = parse_timestamp(row.get("timestamp", ""))

        event = Event(
            timestamp=ts,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=event_type,
            raw_log=raw_log,
            src_ip=row.get("src_ip", "").strip() or None,
            dst_ip=row.get("dst_ip", "").strip() or None,
            src_port=safe_int(row.get("src_port")) or None,
            dst_port=safe_int(row.get("dst_port")) or None,
            host=row.get("host", "").strip() or None,
            alert_name=alert_name or None,
            protocol=row.get("protocol", "").strip() or None,
            direction=direction or None,
            action=(row.get("action") or "").strip().lower() or None,
            severity="high" if alert_name else "info",
        )
        events.append(event)

    return events
