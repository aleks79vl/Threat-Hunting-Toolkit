from src.intelligence.ioc_matcher import (match_ioc,enrich_finding_with_ioc,)
from src.models.threat_finding import ThreatFinding


def test_match_existing_ip():

    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Test",
        source="Unit Test",
        ip="185.220.101.1",
        hostname="host",
        port=80,
        risk_score=90,
        recommendation="Investigate"
    )

    result = match_ioc(finding)

    assert result is not None
    assert result.ioc_type == "ip"


def test_match_unknown_ip():

    finding = ThreatFinding(
        title="Unknown IP",
        severity="low",
        description="Test",
        source="Unit Test",
        ip="192.168.1.200",
        hostname="host",
        port=80,
        risk_score=10,
        recommendation="None"
    )

    result = match_ioc(finding)

    assert result is None


def test_enrich_finding_with_ioc_match():

    finding = ThreatFinding(
        title="Known malicious IP",
        severity="high",
        description="Test",
        source="Unit Test",
        ip="185.220.101.1",
        hostname="host",
        port=80,
        risk_score=90,
        recommendation="Investigate"
    )

    enriched = enrich_finding_with_ioc(finding)

    assert enriched.ioc_match is True
    assert enriched.ioc_type == "ip"
    assert enriched.ioc_value == "185.220.101.1"
    assert enriched.ioc_confidence == "high"
    assert enriched.ioc_source == "Local IOC Database"
    assert enriched.ioc_description == "Known Tor exit node"


def test_enrich_finding_without_ioc_match():

    finding = ThreatFinding(
        title="Unknown IP",
        severity="low",
        description="Test",
        source="Unit Test",
        ip="192.168.1.200",
        hostname="host",
        port=80,
        risk_score=10,
        recommendation="None"
    )

    enriched = enrich_finding_with_ioc(finding)

    assert enriched.ioc_match is False
    assert enriched.ioc_type == ""
    assert enriched.ioc_value == ""
    assert enriched.ioc_confidence == ""
    assert enriched.ioc_source == ""
    assert enriched.ioc_description == ""