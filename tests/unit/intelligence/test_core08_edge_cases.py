import pytest

from src.intelligence.ioc_comparison import ioc_matches
from src.detection.network.network_ioc_detector import (
    detect_network_iocs,
)
from src.models.ioc import IOC
from src.models.network_event import NetworkEvent


@pytest.mark.parametrize(
    "indicator,observed,expected",
    [
        ("/shell%GG.php", "/shell%GG.php", False),
        ("/shell%.php", "/shell%.php", False),
        ("/shell%2F.php", "/shell%2f.php", True),
        ("/shell.php", "/shell%2F.php", False),
        ("/shell.php", "/%2573hell.php", False),
        (
            "/shell.php?mode=1",
            "/shell.php?mode=1&extra=2",
            False,
        ),
        (
            "https://example.test:8443/shell.php",
            "https://example.test/shell.php",
            False,
        ),
        (
            "https://example.test/shell.php",
            "https://example.test:443/shell.php",
            True,
        ),
    ],
)
def test_url_edge_cases(indicator, observed, expected):
    assert ioc_matches(
        "url",
        indicator,
        observed,
    ) is expected


def test_network_preserves_independent_ioc_matches(
    monkeypatch,
):
    iocs = [
        IOC(
            value="185.220.101.1",
            ioc_type="ip",
            source="CORE-08 Test",
        ),
        IOC(
            value="evil-example.com",
            ioc_type="domain",
            source="CORE-08 Test",
        ),
        IOC(
            value="/shell.php",
            ioc_type="url",
            source="CORE-08 Test",
        ),
    ]

    monkeypatch.setattr(
        "src.detection.network.network_ioc_detector.get_iocs",
        lambda: iocs,
    )

    event = NetworkEvent(
        timestamp="1385452028.038401000",
        src_ip="10.0.0.3",
        dst_ip="185.220.101.1",
        dns_query="evil-example.com",
        http_uri="/shell.php",
        protocol="TCP",
    )

    findings = detect_network_iocs([event])

    matches = {
        (finding.ioc_type, finding.ioc_value)
        for finding in findings
    }

    assert matches == {
        ("ip", "185.220.101.1"),
        ("domain", "evil-example.com"),
        ("url", "/shell.php"),
    }

    assert len(findings) == 3
