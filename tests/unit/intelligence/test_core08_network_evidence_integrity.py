from src.detection.network import network_ioc_detector
from src.intelligence import ioc_matcher
from src.intelligence.ioc_risk_scoring import apply_ioc_risk_score
from src.models.ioc import IOC
from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


def _indicator():
    return IOC(
        value="203.0.113.99",
        ioc_type="ip",
        confidence="high",
        source="CORE-08 Test Feed",
        description="Synthetic test IP",
    )


def test_source_ip_ioc_remains_scoreable_when_destination_differs(
    monkeypatch,
):
    indicator = _indicator()

    monkeypatch.setattr(
        network_ioc_detector,
        "get_iocs",
        lambda: [indicator],
    )
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [indicator],
    )

    event = NetworkEvent(
        timestamp="2026-11-23T06:00:00Z",
        src_ip="203.0.113.99",
        dst_ip="198.51.100.25",
        protocol="TCP",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [event]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.ip == "198.51.100.25"
    assert finding.ioc_value == "203.0.113.99"
    assert finding.ioc_observation == {
        "field": "src_ip",
        "value": "203.0.113.99",
    }
    assert len(ioc_matcher.match_iocs(finding)) == 1

    apply_ioc_risk_score(finding)

    assert finding.risk_factors["ioc"] == 30


def test_feed_membership_without_observed_ip_is_not_evidence(
    monkeypatch,
):
    indicator = _indicator()

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [indicator],
    )

    finding = ThreatFinding(
        title="Unverified Network Observation",
        severity="medium",
        description="Normal network traffic",
        source="External Detector",
        ip="198.51.100.25",
        risk_score=40,
        ioc_match=True,
        ioc_type="ip",
        ioc_value="203.0.113.99",
        ioc_confidence="high",
        ioc_source="External Source",
    )

    assert ioc_matcher.match_iocs(finding) == []

    apply_ioc_risk_score(finding)

    assert finding.risk_score == 40
    assert "ioc" not in finding.risk_factors
