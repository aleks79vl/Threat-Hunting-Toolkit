from src.correlation.network_correlation import (
    correlate_network_findings,
)
from src.models.threat_finding import ThreatFinding


def create_finding(
    title: str,
    ip: str,
    severity: str = "medium",
) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity=severity,
        description="test",
        source="Unit Test",
        ip=ip,
        recommendation="Investigate",
    )


def test_correlate_unknown_ip_and_critical_port():
    findings = [
        create_finding(
            "Unknown Network IP Detected",
            "10.0.0.50",
        ),
        create_finding(
            "Critical Network Port Detected",
            "10.0.0.50",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == "Correlated Network Threat Detected"
    assert correlated[0].severity == "critical"
    assert correlated[0].ip == "10.0.0.50"


def test_correlate_ioc_match():
    findings = [
        create_finding(
            "Network IOC Match Detected",
            "185.220.101.1",
            severity="high",
        )
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == "Correlated Network Threat Detected"


def test_correlate_arp_and_dns_activity():
    findings = [
        create_finding(
            "Possible ARP Spoofing Detected",
            "10.0.0.1",
            severity="high",
        ),
        create_finding(
            "Repeated DNS Query Activity Detected",
            "10.0.0.1",
            severity="medium",
        ),
    ]

    correlated = correlate_network_findings(findings)

    assert len(correlated) == 1
    assert correlated[0].title == "Possible MITM Activity Correlated"
    assert correlated[0].severity == "critical"


def test_do_not_correlate_single_unknown_ip():
    findings = [
        create_finding(
            "Unknown Network IP Detected",
            "10.0.0.50",
        )
    ]

    correlated = correlate_network_findings(findings)

    assert correlated == []


def test_ignore_findings_without_ip():
    findings = [
        ThreatFinding(
            title="Unknown Network IP Detected",
            severity="medium",
            description="test",
            source="Unit Test",
            recommendation="Investigate",
        )
    ]

    correlated = correlate_network_findings(findings)

    assert correlated == []