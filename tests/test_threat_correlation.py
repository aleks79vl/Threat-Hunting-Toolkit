from src.parsers.nmap_parser import parse_nmap_xml
from src.detection.nmap.unknown_ip_detector import detect_unknown_ips
from src.detection.nmap.critical_port_detector import detect_critical_ports
from src.correlation.threat_correlation import correlate_threats
from src.models.threat_finding import ThreatFinding


def test_correlate_unknown_ip_with_critical_port():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    unknown_events = detect_unknown_ips(
        events,
        "config/whitelist.json"
    )

    critical_events = detect_critical_ports(
        events,
        "config/critical_ports.json"
    )

    correlated = correlate_threats(
        unknown_events,
        critical_events
    )

    assert len(correlated) == 1
    assert isinstance(correlated[0], ThreatFinding)
    assert correlated[0].ip == "192.168.1.77"
    assert correlated[0].port == 3389
    assert correlated[0].severity == "critical"


def test_correlation_title_and_recommendation_exist():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    unknown_events = detect_unknown_ips(
        events,
        "config/whitelist.json"
    )

    critical_events = detect_critical_ports(
        events,
        "config/critical_ports.json"
    )

    correlated = correlate_threats(
        unknown_events,
        critical_events
    )

    assert "Unknown host" in correlated[0].title
    assert correlated[0].recommendation != ""