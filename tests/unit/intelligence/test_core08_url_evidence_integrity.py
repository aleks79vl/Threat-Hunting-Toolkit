import json

from src.detection.network import network_ioc_detector
from src.intelligence import ioc_matcher
from src.models.ioc import IOC
from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


SECRET = "CORE08_SYNTHETIC_API_KEY_7139"


def _indicator():
    return IOC(
        value="/shell.php",
        ioc_type="url",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic URL IOC",
    )


def _install_feed(monkeypatch):
    monkeypatch.setattr(
        network_ioc_detector,
        "get_iocs",
        lambda: [_indicator()],
    )
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [_indicator()],
    )


def test_generated_url_narrative_is_not_independent_evidence(
    monkeypatch,
):
    _install_feed(monkeypatch)

    finding = ThreatFinding(
        title="Network IOC Match Detected",
        severity="high",
        description=(
            "Network traffic matched IOC /shell.php "
            "of type url."
        ),
        source="PCAP Network Detection",
        ip="198.51.100.25",
        ioc_match=True,
        ioc_type="url",
        ioc_value="/shell.php",
        ioc_confidence="high",
    )

    assert finding.ioc_observation == {}
    assert ioc_matcher.match_iocs(finding) == []


def test_real_url_evidence_survives_narrative_change(
    monkeypatch,
):
    _install_feed(monkeypatch)

    event = NetworkEvent(
        timestamp="2026-11-25T07:00:00Z",
        src_ip="198.51.100.10",
        dst_ip="198.51.100.25",
        protocol="HTTP",
        http_host="example.test",
        http_uri="/shell.php",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [event]
    )

    assert len(findings) == 1

    finding = findings[0]

    # Remove the generated IOC narrative.
    finding.description = "HTTP security observation"

    # The underlying observation must still support matching.
    assert len(ioc_matcher.match_iocs(finding)) == 1


def test_url_evidence_does_not_export_sensitive_query(
    monkeypatch,
):
    _install_feed(monkeypatch)

    event = NetworkEvent(
        timestamp="2026-11-25T07:01:00Z",
        src_ip="198.51.100.10",
        dst_ip="198.51.100.25",
        protocol="HTTP",
        http_host="example.test",
        http_uri=f"/shell.php?api_key={SECRET}",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [event]
    )

    assert len(findings) == 1

    finding = findings[0]

    # The match must remain verifiable without the narrative.
    finding.description = "HTTP security observation"
    assert len(ioc_matcher.match_iocs(finding)) == 1

    serialized = json.dumps(finding.to_dict())

    assert SECRET not in serialized
