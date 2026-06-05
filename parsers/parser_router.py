from typing import List, Tuple

from parsers.auth_linux_parser import parse_linux_auth
from parsers.auth_windows_parser import parse_windows_auth
from parsers.network_parser import parse_network_ids
from utils.schema import Event


def _detect_auth_format(content: str) -> str:
    """Heuristic to determine auth log format from CSV header."""
    first_line = content.strip().split("\n")[0].lower()
    if "logon_type" in first_line or "event_id_code" in first_line:
        return "windows"
    return "linux"


def parse_auth_file(content: str) -> Tuple[List[Event], str]:
    """Parse an auth log file, auto-detecting Linux vs Windows format.

    Returns (events, detected_format).
    """
    fmt = _detect_auth_format(content)
    if fmt == "windows":
        return parse_windows_auth(content), "windows"
    return parse_linux_auth(content), "linux"


def parse_network_file(content: str) -> List[Event]:
    """Parse a network/IDS log file."""
    return parse_network_ids(content)
