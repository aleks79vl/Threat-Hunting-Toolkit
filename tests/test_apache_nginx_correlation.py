from src.correlation.apache_nginx_correlation import (
    correlate_apache_nginx_findings,
)
from src.models.threat_finding import ThreatFinding


def make_finding(
    *,
    source: str,
    ip: str,
    hostname: str,
    severity: str = "medium",
) -> ThreatFinding:
    return ThreatFinding(
        title="Test finding",
        severity=severity,
        description="Test description",
        source=source,
        ip=ip,
        hostname=hostname,
    )


def test_correlates_apache_and_nginx_findings_by_ip():
    findings = correlate_apache_nginx_findings(
        [
            make_finding(
                source="Apache Web Shell Detector",
                ip="203.0.113.44",
                hostname="api.example.com",
                severity="high",
            ),
            make_finding(
                source="Nginx PHP Attack Detector",
                ip="203.0.113.44",
                hostname="api.example.com",
            ),
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Correlated Web Attack Across Apache and Nginx"
    )
    assert findings[0].severity == "high"
    assert findings[0].ip == "203.0.113.44"


def test_does_not_correlate_different_ips():
    findings = correlate_apache_nginx_findings(
        [
            make_finding(
                source="Apache Web Shell Detector",
                ip="203.0.113.44",
                hostname="api.example.com",
            ),
            make_finding(
                source="Nginx PHP Attack Detector",
                ip="203.0.113.45",
                hostname="api.example.com",
            ),
        ]
    )

    assert findings == []


def test_does_not_correlate_different_hostnames():
    findings = correlate_apache_nginx_findings(
        [
            make_finding(
                source="Apache Web Shell Detector",
                ip="203.0.113.44",
                hostname="admin.example.com",
            ),
            make_finding(
                source="Nginx PHP Attack Detector",
                ip="203.0.113.44",
                hostname="api.example.com",
            ),
        ]
    )

    assert findings == []