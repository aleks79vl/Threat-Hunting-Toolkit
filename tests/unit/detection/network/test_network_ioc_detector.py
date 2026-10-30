from src.detection.network.network_ioc_detector import detect_network_iocs
from src.models.network_event import NetworkEvent
from datetime import datetime, timezone


def create_network_event(
    src_ip: str = "10.0.0.3",
    dst_ip: str = "8.8.8.8",
    protocol: str = "TCP",
    dns_query: str = "",
    http_host: str = "",
    http_uri: str = "",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port="51514",
        dst_port="443",
        dns_query=dns_query,
        http_host=http_host,
        http_uri=http_uri,
    )


def test_detect_network_ip_ioc():
    events = [
        create_network_event(
            dst_ip="185.220.101.1",
        )
    ]

    findings = detect_network_iocs(events)

    assert len(findings) >= 1
    assert findings[0].ioc_match is True
    assert findings[0].ioc_type == "ip"
    assert findings[0].ioc_value == "185.220.101.1"


def test_detect_network_domain_ioc():
    events = [
        create_network_event(
            dns_query="evil-example.com",
        )
    ]

    findings = detect_network_iocs(events)

    assert len(findings) >= 1
    assert any(
        finding.ioc_type == "domain"
        and finding.ioc_value == "evil-example.com"
        for finding in findings
    )


def test_detect_network_url_ioc():
    events = [
        create_network_event(
            http_uri="/shell.php",
        )
    ]

    findings = detect_network_iocs(events)

    assert len(findings) >= 1
    assert any(
        finding.ioc_type == "url"
        and finding.ioc_value == "/shell.php"
        for finding in findings
    )


def test_ignore_network_event_without_ioc():
    events = [
        create_network_event(
            dst_ip="8.8.8.8",
            dns_query="google.com",
            http_uri="/index.html",
        )
    ]

    findings = detect_network_iocs(events)

    assert findings == []


def _packet_timestamp(hour: int, minute: int, fraction="000000000"):
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )
    return f"{int(dt.timestamp())}.{fraction}"


def test_network_ioc_preserves_packet_timestamp():
    event = create_network_event(
        dst_ip="185.220.101.1",
    )
    event.timestamp = _packet_timestamp(
        9, 0, "123456000"
    )

    findings = detect_network_iocs([event])

    matches = [
        finding
        for finding in findings
        if finding.ioc_type == "ip"
        and finding.ioc_value == "185.220.101.1"
    ]

    assert len(matches) == 1
    assert (
        matches[0].first_seen
        == "2026-07-16T09:00:00.123456+00:00"
    )
    assert (
        matches[0].last_seen
        == "2026-07-16T09:00:00.123456+00:00"
    )


def test_network_ioc_deduplication_preserves_time_ranges():
    ip_events = [
        create_network_event(dst_ip="185.220.101.1")
        for _ in range(3)
    ]

    ip_events[0].timestamp = _packet_timestamp(9, 0)
    ip_events[1].timestamp = _packet_timestamp(9, 3)
    ip_events[2].timestamp = _packet_timestamp(9, 7)

    domain_event = create_network_event(
        dns_query="evil-example.com",
    )
    domain_event.timestamp = _packet_timestamp(8, 0)

    findings = detect_network_iocs([
        ip_events[2],
        domain_event,
        ip_events[1],
        ip_events[0],
    ])

    ip_matches = [
        finding
        for finding in findings
        if finding.ioc_type == "ip"
        and finding.ioc_value == "185.220.101.1"
    ]

    domain_matches = [
        finding
        for finding in findings
        if finding.ioc_type == "domain"
        and finding.ioc_value == "evil-example.com"
    ]

    assert len(ip_matches) == 1
    assert len(domain_matches) == 1

    assert ip_matches[0].first_seen == (
        "2026-07-16T09:00:00+00:00"
    )
    assert ip_matches[0].last_seen == (
        "2026-07-16T09:07:00+00:00"
    )

    assert domain_matches[0].first_seen == (
        "2026-07-16T08:00:00+00:00"
    )
    assert domain_matches[0].last_seen == (
        "2026-07-16T08:00:00+00:00"
    )


def test_network_ioc_invalid_timestamp_is_not_invented():
    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        event = create_network_event(
            dst_ip="185.220.101.1",
        )
        event.timestamp = invalid_timestamp

        findings = detect_network_iocs([event])

        matches = [
            finding
            for finding in findings
            if finding.ioc_type == "ip"
            and finding.ioc_value == "185.220.101.1"
        ]

        assert len(matches) == 1
        assert matches[0].first_seen is None
        assert matches[0].last_seen is None


def test_network_ioc_mixed_valid_invalid_timestamp():
    valid_event = create_network_event(
        dst_ip="185.220.101.1",
    )
    valid_event.timestamp = _packet_timestamp(9, 0)

    invalid_event = create_network_event(
        dst_ip="185.220.101.1",
    )
    invalid_event.timestamp = "invalid-timestamp"

    for events in (
        [valid_event, invalid_event],
        [invalid_event, valid_event],
    ):
        findings = detect_network_iocs(events)

        matches = [
            finding
            for finding in findings
            if finding.ioc_type == "ip"
            and finding.ioc_value == "185.220.101.1"
        ]

        assert len(matches) == 1
        assert matches[0].first_seen is None
        assert matches[0].last_seen is None
