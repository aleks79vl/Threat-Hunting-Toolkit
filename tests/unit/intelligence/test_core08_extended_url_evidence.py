from src.detection.network import network_ioc_detector
from src.intelligence import ioc_matcher
from src.models.ioc import IOC
from src.models.network_event import NetworkEvent


def _install_feed(monkeypatch, value):
    indicator = IOC(
        value=value,
        ioc_type="url",
        source="CORE-08 Test Feed",
        confidence="high",
        description="Synthetic URL indicator",
    )

    monkeypatch.setattr(
        network_ioc_detector,
        "get_iocs",
        lambda: [indicator],
    )
    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [indicator],
    )


def _event(uri):
    return NetworkEvent(
        timestamp="2026-11-25T07:00:00Z",
        src_ip="198.51.100.10",
        dst_ip="198.51.100.25",
        protocol="HTTP",
        http_host="example.test",
        http_uri=uri,
    )


def test_query_dependent_url_survives_narrative_change(
    monkeypatch,
):
    _install_feed(
        monkeypatch,
        "/shell.php?mode=debug",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [_event("/shell.php?mode=debug")]
    )

    assert len(findings) == 1

    finding = findings[0]
    finding.description = "HTTP security observation"

    assert len(ioc_matcher.match_iocs(finding)) == 1


def test_different_query_does_not_match(
    monkeypatch,
):
    _install_feed(
        monkeypatch,
        "/shell.php?mode=debug",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [_event("/shell.php?mode=production")]
    )

    assert findings == []


def test_full_absolute_url_survives_narrative_change(
    monkeypatch,
):
    _install_feed(
        monkeypatch,
        "https://example.test/shell.php",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [_event("https://example.test/shell.php")]
    )

    assert len(findings) == 1

    finding = findings[0]
    finding.description = "HTTP security observation"

    assert len(ioc_matcher.match_iocs(finding)) == 1


def test_relative_uri_does_not_prove_https_scheme(
    monkeypatch,
):
    _install_feed(
        monkeypatch,
        "https://example.test/shell.php",
    )

    # HTTP host and relative URI do not establish
    # the original request scheme.
    findings = network_ioc_detector.detect_network_iocs(
        [_event("/shell.php")]
    )

    assert findings == []


def test_runtime_url_confirmation_is_not_serialized(monkeypatch):
    from src.models.threat_finding import ThreatFinding

    _install_feed(
        monkeypatch,
        "/shell.php?mode=debug",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [_event("/shell.php?mode=debug")]
    )

    assert len(findings) == 1

    finding = findings[0]
    finding.description = "HTTP security observation"

    assert len(ioc_matcher.match_iocs(finding)) == 1

    payload = finding.to_dict()

    assert "_core08_verified_url_ioc" not in payload
    assert payload["ioc_observation"] == {}

    restored = ThreatFinding(**payload)

    # Without the original trusted detector execution,
    # the reconstructed object must fail closed.
    assert ioc_matcher.match_iocs(restored) == []


def test_runtime_url_confirmation_respects_feed_revocation(
    monkeypatch,
):
    _install_feed(
        monkeypatch,
        "https://example.test/shell.php",
    )

    findings = network_ioc_detector.detect_network_iocs(
        [_event("https://example.test/shell.php")]
    )

    assert len(findings) == 1

    finding = findings[0]
    finding.description = "HTTP security observation"

    assert len(ioc_matcher.match_iocs(finding)) == 1

    monkeypatch.setattr(
        ioc_matcher,
        "get_iocs",
        lambda: [],
    )

    assert ioc_matcher.match_iocs(finding) == []
