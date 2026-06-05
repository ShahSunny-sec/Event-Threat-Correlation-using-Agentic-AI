from datetime import datetime
from typing import Optional

from dateutil import parser as dateutil_parser


def parse_timestamp(value: str) -> Optional[datetime]:
    """Attempt to parse a timestamp string into a datetime object."""
    if not value or not isinstance(value, str):
        return None
    try:
        return dateutil_parser.parse(value)
    except (ValueError, TypeError):
        return None


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def minutes_between(dt1: datetime, dt2: datetime) -> float:
    """Return absolute minutes between two datetimes."""
    return abs((dt2 - dt1).total_seconds()) / 60.0
