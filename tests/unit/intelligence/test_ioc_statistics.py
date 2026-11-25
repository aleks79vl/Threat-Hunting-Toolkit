from src.intelligence import ioc_matcher
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding
from src.reporting.ioc_statistics import generate_ioc_statistics


def test_generate_ioc_statistics(monkeypatch):
    hash_value = "44d88612fea8a8f36de82e1278abb02f"

    indicators = [
        IOC(
            value="203.0.113.11",
            ioc_type="ip",
            source="Statistics Test Feed",
        ),
        IOC(
            value="evil-example.com",
            ioc_type="domain",
            source="Statistics Test Feed",
        ),
        IOC(
            value="/shell.php",
            ioc_type="url",
            source="Statistics Test Feed",
        ),
        IOC(
            value=hash_value,
            ioc_type="hash",
            source="Statistics Test Feed",
        ),
    ]

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: indicators,
    )

    findings = [
        ThreatFinding(
            title="IP",
            severity="high",
            description="",
            source="test",
            ip="203.0.113.11",
            ioc_match=True,
            ioc_type="ip",
            ioc_value="203.0.113.11",
        ),
        ThreatFinding(
            title="Domain",
            severity="high",
            description="",
            source="test",
            hostname="test.evil-example.com",
            ioc_match=True,
            ioc_type="domain",
            ioc_value="evil-example.com",
        ),
        ThreatFinding(
            title="URL",
            severity="high",
            description="Request to /shell.php",
            source="test",
            ioc_match=True,
            ioc_type="url",
            ioc_value="/shell.php",
        ),
        ThreatFinding(
            title="Hash",
            severity="high",
            description=f"Observed hash {hash_value}",
            source="test",
            ioc_match=True,
            ioc_type="hash",
            ioc_value=hash_value,
        ),
    ]

    stats = generate_ioc_statistics(findings)

    assert stats["total_matches"] == 4
    assert stats["ip"] == 1
    assert stats["domain"] == 1
    assert stats["url"] == 1
    assert stats["hash"] == 1
