from src.parsers.nmap_parser import parse_nmap_xml
from src.detection.unknown_ip_detector import (
    detect_unknown_ips,
    load_known_ips,
)


def test_load_known_ips():
    known_ips = load_known_ips("config/whitelist.json")

    assert "192.168.1.10" in known_ips
    assert "192.168.1.20" in known_ips
    assert "192.168.1.30" in known_ips


def test_detect_unknown_ip():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    unknown_events = detect_unknown_ips(
        events,
        "config/whitelist.json"
    )

    assert len(unknown_events) == 1
    assert unknown_events[0].src_ip == "192.168.1.77"


def test_unknown_ip_severity():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    unknown_events = detect_unknown_ips(
        events,
        "config/whitelist.json"
    )

    assert unknown_events[0].severity == "high"