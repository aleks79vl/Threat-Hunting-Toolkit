import pytest

from src.intelligence.ioc_matcher import match_ioc
from src.detection.network.network_ioc_detector import (
    detect_network_iocs,
)
from src.models.ioc import IOC
from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


@pytest.mark.parametrize(
    "ioc_type,ioc_value,description",
    [
        (
            "domain",
            "evil-example.com",
            "DNS query: not-evil-example.com",
        ),
        (
            "domain",
            "evil-example.com",
            "DNS query: evil-example.com.attacker.test",
        ),
        (
            "url",
            "/shell.php",
            "Request to /shell.php.backup detected",
        ),
        (
            "hash",
            "44d88612fea8a8f36de82e1278abb02f",
            "Hash: 44d88612fea8a8f36de82e1278abb02f0",
        ),
    ],
)
def test_finding_rejects_partial_ioc_matches(
    monkeypatch,
    ioc_type,
    ioc_value,
    description,
):
    ioc = IOC(
        value=ioc_value,
        ioc_type=ioc_type,
        source="CORE-08 Test",
    )

    monkeypatch.setattr(
        "src.intelligence.ioc_matcher.get_iocs",
        lambda: [ioc],
    )

    finding = ThreatFinding(
        title="Security observation",
        severity="medium",
        description=description,
        source="CORE-08 Test",
        ip="198.51.100.10",
        hostname="normal.example",
    )

    assert match_ioc(finding) is None


def test_recommendation_is_not_ioc_evidence(monkeypatch):
    ioc = IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Test",
    )

    monkeypatch.setattr(
        "src.intelligence.ioc_matcher.get_iocs",
        lambda: [ioc],
    )

    finding = ThreatFinding(
        title="Security observation",
        severity="medium",
        description="No IOC observed in the event",
        source="CORE-08 Test",
        recommendation="Investigate evil-example.com",
    )

    assert match_ioc(finding) is None


@pytest.mark.parametrize(
    "ioc_type,ioc_value,event_fields",
    [
        (
            "ip",
            "185.220.101.1",
            {"dst_ip": "185.220.101.100"},
        ),
        (
            "domain",
            "evil-example.com",
            {"dns_query": "not-evil-example.com"},
        ),
        (
            "domain",
            "evil-example.com",
            {"http_host": "evil-example.com.attacker.test"},
        ),
        (
            "url",
            "/shell.php",
            {"http_uri": "/shell.php.backup"},
        ),
    ],
)
def test_network_rejects_partial_ioc_matches(
    monkeypatch,
    ioc_type,
    ioc_value,
    event_fields,
):
    ioc = IOC(
        value=ioc_value,
        ioc_type=ioc_type,
        source="CORE-08 Test",
    )

    monkeypatch.setattr(
        "src.detection.network.network_ioc_detector.get_iocs",
        lambda: [ioc],
    )

    event = NetworkEvent(
        timestamp="1385452028.038401000",
        **event_fields,
    )

    assert detect_network_iocs([event]) == []
