from src.models.threat_finding import ThreatFinding
from src.reporting.ioc_statistics import generate_ioc_statistics


def test_generate_ioc_statistics():

    findings = [

        ThreatFinding(
            title="IP",
            severity="high",
            description="",
            source="test",
            ip="1.1.1.1",
            hostname="host",
            port=80,
            risk_score=90,
            recommendation="",
            ioc_match=True,
            ioc_type="ip",
        ),

        ThreatFinding(
            title="Domain",
            severity="high",
            description="",
            source="test",
            ip="1.1.1.2",
            hostname="host",
            port=80,
            risk_score=90,
            recommendation="",
            ioc_match=True,
            ioc_type="domain",
        ),

        ThreatFinding(
            title="URL",
            severity="high",
            description="",
            source="test",
            ip="1.1.1.3",
            hostname="host",
            port=80,
            risk_score=90,
            recommendation="",
            ioc_match=True,
            ioc_type="url",
        ),

        ThreatFinding(
            title="Hash",
            severity="high",
            description="",
            source="test",
            ip="1.1.1.4",
            hostname="host",
            port=80,
            risk_score=90,
            recommendation="",
            ioc_match=True,
            ioc_type="hash",
        ),
    ]

    stats = generate_ioc_statistics(findings)

    assert stats["total_matches"] == 4
    assert stats["ip"] == 1
    assert stats["domain"] == 1
    assert stats["url"] == 1
    assert stats["hash"] == 1