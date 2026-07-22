from src.correlation.firewall_web_correlation import (
    correlate_firewall_and_web_findings,
)
from src.models.threat_finding import ThreatFinding


def make_finding(
    *,
    source: str,
    ip: str,
    severity: str = "medium",
) -> ThreatFinding:
    return ThreatFinding(
        title="Test finding",
        severity=severity,
        description="Test description",
        source=source,
        ip=ip,
    )


def test_correlates_firewall_and_web_findings_by_ip():
    findings = correlate_firewall_and_web_findings(
        [
            make_finding(
                source="Firewall Detector",
                ip="203.0.113.44",
            ),
            make_finding(
                source="Nginx Directory Traversal Detector",
                ip="203.0.113.44",
                severity="high",
            ),
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Correlated Firewall and Web Attack Activity"
    )
    assert findings[0].severity == "high"
    assert findings[0].ip == "203.0.113.44"


def test_does_not_correlate_different_ips():
    findings = correlate_firewall_and_web_findings(
        [
            make_finding(
                source="Firewall Detector",
                ip="203.0.113.44",
            ),
            make_finding(
                source="Nginx Directory Traversal Detector",
                ip="203.0.113.45",
            ),
        ]
    )

    assert findings == []


def test_ignores_non_web_findings():
    findings = correlate_firewall_and_web_findings(
        [
            make_finding(
                source="Firewall Detector",
                ip="203.0.113.44",
            ),
            make_finding(
                source="Linux SSH Detector",
                ip="203.0.113.44",
            ),
        ]
    )

    assert findings == []