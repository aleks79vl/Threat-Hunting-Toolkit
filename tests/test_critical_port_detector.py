from src.parsers.nmap_parser import parse_nmap_xml
from src.detection.critical_port_detector import (
    load_critical_ports,
    detect_critical_ports,
)


def test_load_critical_ports():
    ports = load_critical_ports("config/critical_ports.json")

    assert 22 in ports
    assert 445 in ports
    assert 3389 in ports


def test_detect_critical_ports():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    alerts = detect_critical_ports(
        events,
        "config/critical_ports.json"
    )

    assert len(alerts) == 3


def test_critical_port_severity():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    alerts = detect_critical_ports(
        events,
        "config/critical_ports.json"
    )

    severities = [event.severity for event in alerts]

    assert "high" in severities
    assert "critical" in severities


def test_service_name_added():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    alerts = detect_critical_ports(
        events,
        "config/critical_ports.json"
    )

    assert "Critical Service" in alerts[0].raw_event