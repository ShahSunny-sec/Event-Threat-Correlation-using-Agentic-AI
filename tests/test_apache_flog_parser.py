import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.apache_flog_parser import parse_apache_lines
from parsers.flog_router import parse_flog_output


def test_parse_apache_common_line():
    line = (
        '192.168.1.50 - - [15/Mar/2024:10:00:12 +0000] '
        '"GET /index.html HTTP/1.0" 200 2326'
    )
    events = parse_apache_lines(line)
    assert len(events) == 1
    assert events[0].src_ip == "192.168.1.50"
    assert events[0].event_type == "network_inbound"


def test_flog_router_apache():
    text = (
        '10.0.0.1 - - [15/Mar/2024:10:00:12 +0000] "GET /a HTTP/1.0" 404 100\n'
    )
    ev = parse_flog_output(text, "apache_common")
    assert len(ev) == 1
