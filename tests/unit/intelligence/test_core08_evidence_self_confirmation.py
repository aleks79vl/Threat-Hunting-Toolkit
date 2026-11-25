from src.detection.network import network_ioc_detector
from src.intelligence import ioc_matcher
from src.models.ioc import IOC
from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


def _indicator():
    return IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic domain IOC",
    )


def test_generated_ioc_description_is_not_independent_evidence(
    monkeypatch,
):
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [_indicator()],
    )

    finding = ThreatFinding(
        title="Network IOC Match Detected",
        severity="high",
        description=(
            "Network traffic matched IOC evil-example.com "
            "of type domain. Context: Synthetic domain IOC"
        ),
        source="PCAP Network Detection",
        ip="198.51.100.25",
        hostname="",
        ioc_match=True,
        ioc_type="domain",
        ioc_value="evil-example.com",
        ioc_confidence="high",
    )

    # No structured network observation is available.
    assert finding.ioc_observation == {}

    # A generated narrative must not independently
    # revalidate an IOC claim.
    assert ioc_matcher.match_iocs(finding) == []


def test_real_dns_ioc_preserves_original_observation(
    monkeypatch,
):
    monkeypatch.setattr(
        network_ioc_detector,
        "get_iocs",
        lambda: [_indicator()],
    )

    event = NetworkEvent(
        timestamp="2026-11-25T07:00:00Z",
        src_ip="198.51.100.10",
        dst_ip="198.51.100.25",
        protocol="DNS",
        dns_query="evil-example.com",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [event]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.ioc_type == "domain"
    assert finding.ioc_value == "evil-example.com"

    # Preserve the actual observed DNS value,
    # not just its generated textual description.
    assert finding.ioc_observation == {
        "field": "dns_query",
        "value": "evil-example.com",
    }
