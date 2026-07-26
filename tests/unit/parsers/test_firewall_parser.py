from src.parsers.firewall_parser import parse_firewall_log


def test_parse_firewall_log_returns_events():
    events = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )

    assert len(events) == 10


def test_first_event():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[0]

    assert event.source == "Firewall"
    assert event.event_type == "ALLOW"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.77"
    assert event.dst_port == 3389
    assert event.protocol == "TCP"


def test_second_event():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[1]

    assert event.event_type == "DENY"
    assert event.dst_port == 3389


def test_last_event():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[-1]

    assert event.event_type == "DENY"
    assert event.dst_port == 1433


def test_timestamp():
    event = parse_firewall_log(
        "data/raw/firewall/firewall.log"
    )[0]

    assert event.timestamp == "2026-06-27 09:00:15"