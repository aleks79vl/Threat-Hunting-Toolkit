from src.correlation.ioc_web_correlation import (
    correlate_ioc_and_web_findings,
)
from src.models.threat_finding import ThreatFinding


def make_finding(
    *,
    source: str,
    ip: str,
    ioc_match: bool,
    ioc_type: str = "",
    ioc_value: str = "",
    severity: str = "medium",
) -> ThreatFinding:
    return ThreatFinding(
        title="Test finding",
        severity=severity,
        description="Test description",
        source=source,
        ip=ip,
        ioc_match=ioc_match,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        ioc_confidence="high",
        ioc_source="local-test-feed",
    )


def test_correlates_matched_ioc_with_web_activity():
    findings = correlate_ioc_and_web_findings(
        [
            make_finding(
                source="WAF Security Detector",
                ip="203.0.113.44",
                ioc_match=True,
                ioc_type="ip",
                ioc_value="203.0.113.44",
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Known Malicious IOC Observed in Web Activity"
    )
    assert findings[0].severity == "high"
    assert findings[0].ioc_match is True
    assert findings[0].ioc_value == "203.0.113.44"


def test_groups_same_ioc_without_duplicate_correlation():
    findings = correlate_ioc_and_web_findings(
        [
            make_finding(
                source="Nginx PHP Attack Detector",
                ip="203.0.113.44",
                ioc_match=True,
                ioc_type="ip",
                ioc_value="203.0.113.44",
            ),
            make_finding(
                source="WAF Security Detector",
                ip="203.0.113.44",
                ioc_match=True,
                ioc_type="ip",
                ioc_value="203.0.113.44",
            ),
        ]
    )

    assert len(findings) == 1
    assert "2 web finding(s)" in findings[0].description


def test_ignores_unmatched_or_non_web_findings():
    findings = correlate_ioc_and_web_findings(
        [
            make_finding(
                source="Nginx PHP Attack Detector",
                ip="203.0.113.44",
                ioc_match=False,
                ioc_type="ip",
                ioc_value="203.0.113.44",
            ),
            make_finding(
                source="Linux SSH Detector",
                ip="203.0.113.45",
                ioc_match=True,
                ioc_type="ip",
                ioc_value="203.0.113.45",
            ),
        ]
    )

    assert findings == []