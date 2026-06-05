import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.auth_linux_parser import parse_linux_auth
from parsers.auth_windows_parser import parse_windows_auth
from parsers.network_parser import parse_network_ids
from parsers.parser_router import parse_auth_file
from utils.constants import EVENT_TYPE_AUTH_FAILURE, EVENT_TYPE_AUTH_SUCCESS


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def _read(filename):
    with open(os.path.join(SAMPLE_DIR, filename)) as f:
        return f.read()


def test_linux_auth_parser():
    events = parse_linux_auth(_read("auth_linux_sample.csv"))
    assert len(events) == 12
    failures = [e for e in events if e.event_type == EVENT_TYPE_AUTH_FAILURE]
    successes = [e for e in events if e.event_type == EVENT_TYPE_AUTH_SUCCESS]
    assert len(failures) == 8
    assert len(successes) == 4


def test_windows_auth_parser():
    events = parse_windows_auth(_read("auth_windows_sample.csv"))
    assert len(events) == 10
    failures = [e for e in events if e.event_type == EVENT_TYPE_AUTH_FAILURE]
    assert len(failures) == 6


def test_network_parser():
    events = parse_network_ids(_read("network_ids_sample.csv"))
    assert len(events) == 10
    ids_alerts = [e for e in events if e.alert_name]
    assert len(ids_alerts) == 2


def test_parser_router_linux():
    events, fmt = parse_auth_file(_read("auth_linux_sample.csv"))
    assert fmt == "linux"
    assert len(events) == 12


def test_parser_router_windows():
    events, fmt = parse_auth_file(_read("auth_windows_sample.csv"))
    assert fmt == "windows"
    assert len(events) == 10


def test_all_events_have_ids():
    events = parse_linux_auth(_read("auth_linux_sample.csv"))
    for e in events:
        assert e.event_id.startswith("EVT-")


def test_all_events_have_timestamps():
    events = parse_linux_auth(_read("auth_linux_sample.csv"))
    for e in events:
        assert e.timestamp is not None
