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


def test_match_existing_domain():

    finding = ThreatFinding(
        title="Suspicious domain detected",
        severity="high",
        description="Connection to evil-example.com was detected",
        source="Unit Test",
        ip="192.168.1.50",
        hostname="host",
        port=80,
        risk_score=80,
        recommendation="Investigate domain activity"
    )

    result = match_ioc(finding)

    assert result is not None
    assert result.ioc_type == "domain"
    assert result.value == "evil-example.com"


def test_enrich_finding_with_domain_ioc():

    finding = ThreatFinding(
        title="Suspicious domain detected",
        severity="high",
        description="Connection to evil-example.com was detected",
        source="Unit Test",
        ip="192.168.1.50",
        hostname="host",
        port=80,
        risk_score=80,
        recommendation="Investigate domain activity"
    )

    enriched = enrich_finding_with_ioc(finding)

    assert enriched.ioc_match is True
    assert enriched.ioc_type == "domain"
    assert enriched.ioc_value == "evil-example.com"
    assert enriched.ioc_confidence == "high"   


def test_match_existing_url():

    finding = ThreatFinding(
        title="Suspicious URL detected",
        severity="high",
        description="Request to /shell.php detected",
        source="Unit Test",
        ip="192.168.1.10",
        hostname="web-server",
        port=80,
        risk_score=85,
        recommendation="Investigate web server"
    )

    result = match_ioc(finding)

    assert result is not None
    assert result.ioc_type == "url"
    assert result.value == "/shell.php"


def test_enrich_finding_with_url_ioc():

    finding = ThreatFinding(
        title="Suspicious URL detected",
        severity="high",
        description="Request to /shell.php detected",
        source="Unit Test",
        ip="192.168.1.10",
        hostname="web-server",
        port=80,
        risk_score=85,
        recommendation="Investigate web server"
    )

    enriched = enrich_finding_with_ioc(finding)

    assert enriched.ioc_match is True
    assert enriched.ioc_type == "url"
    assert enriched.ioc_value == "/shell.php"
    assert enriched.ioc_confidence == "high"  


def test_match_existing_hash():

    finding = ThreatFinding(
        title="Malware hash detected",
        severity="critical",
        description="Detected file hash 44d88612fea8a8f36de82e1278abb02f",
        source="Unit Test",
        ip="192.168.1.10",
        hostname="host",
        port=0,
        risk_score=95,
        recommendation="Investigate malware sample"
    )

    result = match_ioc(finding)

    assert result is not None
    assert result.ioc_type == "hash"
    assert result.value == "44d88612fea8a8f36de82e1278abb02f"


def test_enrich_finding_with_hash_ioc():

    finding = ThreatFinding(
        title="Malware hash detected",
        severity="critical",
        description="Detected file hash 44d88612fea8a8f36de82e1278abb02f",
        source="Unit Test",
        ip="192.168.1.10",
        hostname="host",
        port=0,
        risk_score=95,
        recommendation="Investigate malware sample"
    )

    enriched = enrich_finding_with_ioc(finding)

    assert enriched.ioc_match is True
    assert enriched.ioc_type == "hash"
    assert enriched.ioc_value == "44d88612fea8a8f36de82e1278abb02f"
    assert enriched.ioc_confidence == "high"