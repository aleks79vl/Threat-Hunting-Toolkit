import pytest

from src.utils.event_utils import SecurityEvent
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


@pytest.mark.parametrize(
    "scope,start,end",
    [
        (
            "host",
            "2026-06-29T09:02:00+00:00",
            "2026-06-29T09:03:00+00:00",
        ),
        (
            "scan",
            "2026-06-29T09:00:00+00:00",
            "2026-06-29T09:10:00+00:00",
        ),
        (
            None,
            None,
            None,
        ),
    ],
)


def test_nmap_correlation_preserves_observation_provenance(
    scope,
    start,
    end,
):
    event = SecurityEvent(
        timestamp="",
        source="nmap",
        event_type="open_port",
        src_ip="192.0.2.17",
        dst_port=3389,
        hostname="unknown-host",
        observation_start=start,
        observation_end=end,
        observation_scope=scope,
    )

    findings = correlate_threats(
        unknown_events=[event],
        critical_events=[event],
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.observation_start == start
    assert finding.observation_end == end
    assert finding.observation_scope == scope

    # A scan interval is not an exact event timestamp.
    assert finding.first_seen is None
    assert finding.last_seen is None


@pytest.mark.parametrize(
    "critical_scope,critical_start,critical_end",
    [
        (
            "scan",
            "2026-06-29T09:02:00+00:00",
            "2026-06-29T09:03:00+00:00",
        ),
        (
            "host",
            "2026-06-29T09:02:00+00:00",
            "2026-06-29T09:04:00+00:00",
        ),
        (
            None,
            None,
            None,
        ),
    ],
)


def test_nmap_correlation_rejects_conflicting_observation_metadata(
    critical_scope,
    critical_start,
    critical_end,
):
    unknown = SecurityEvent(
        timestamp="",
        source="nmap",
        event_type="open_port",
        src_ip="192.0.2.17",
        dst_port=3389,
        observation_start="2026-06-29T09:02:00+00:00",
        observation_end="2026-06-29T09:03:00+00:00",
        observation_scope="host",
    )

    critical = SecurityEvent(
        timestamp="",
        source="nmap",
        event_type="open_port",
        src_ip="192.0.2.17",
        dst_port=3389,
        observation_start=critical_start,
        observation_end=critical_end,
        observation_scope=critical_scope,
    )

    findings = correlate_threats(
        unknown_events=[unknown],
        critical_events=[critical],
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.observation_start is None
    assert finding.observation_end is None
    assert finding.observation_scope is None

    assert finding.first_seen is None
    assert finding.last_seen is None
