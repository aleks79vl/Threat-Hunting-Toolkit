from src.detection.network.network_web_attack_detector import (
    detect_network_web_attacks,
)
from src.models.network_event import NetworkEvent
from datetime import datetime, timezone


def create_http_event(
    http_uri: str,
    http_host: str = "example.com",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip="10.0.0.3",
        dst_ip="93.184.216.34",
        protocol="HTTP",
        src_port="51514",
        dst_port="80",
        dns_query="",
        http_host=http_host,
        http_uri=http_uri,
    )


def test_detect_sql_injection_in_pcap_http_uri():
    events = [
        create_http_event(
            "/login.php?id=' OR 1=1"
        )
    ]

    findings = detect_network_web_attacks(events)

    assert len(findings) == 1
    assert findings[0].title == "SQL Injection Attempt Detected in PCAP"
    assert findings[0].severity == "high"


def test_detect_xss_in_pcap_http_uri():
    events = [
        create_http_event(
            "/search?q=<script>alert(1)</script>"
        )
    ]

    findings = detect_network_web_attacks(events)

    assert len(findings) == 1
    assert findings[0].title == "XSS Attempt Detected in PCAP"


def test_detect_directory_traversal_in_pcap_http_uri():
    events = [
        create_http_event(
            "/download?file=../../../../etc/passwd"
        )
    ]

    findings = detect_network_web_attacks(events)

    assert len(findings) == 1
    assert findings[0].title == (
        "Directory Traversal Attempt Detected in PCAP"
    )


def test_detect_admin_panel_enumeration_in_pcap_http_uri():
    events = [
        create_http_event(
            "/wp-admin/"
        )
    ]

    findings = detect_network_web_attacks(events)

    assert len(findings) == 1
    assert findings[0].title == "Admin Panel Enumeration Detected in PCAP"
    assert findings[0].severity == "medium"


def test_detect_web_shell_uri_in_pcap_http_uri():
    events = [
        create_http_event(
            "/shell.php"
        )
    ]

    findings = detect_network_web_attacks(events)

    assert len(findings) == 1
    assert findings[0].title == "Suspicious Web Shell URI Detected in PCAP"
    assert findings[0].severity == "critical"


def test_ignore_normal_http_request():
    events = [
        create_http_event(
            "/index.html"
        )
    ]

    findings = detect_network_web_attacks(events)

    assert findings == []


def test_duplicate_web_attack_creates_single_finding():
    events = [
        create_http_event(
            "/admin"
        ),
        create_http_event(
            "/admin"
        ),
    ]

    findings = detect_network_web_attacks(events)

    assert len(findings) == 1


def _packet_timestamp(
    hour: int,
    minute: int,
    fraction: str = "000000000",
) -> str:
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )

    return f"{int(dt.timestamp())}.{fraction}"


def test_web_attack_findings_preserve_packet_time():
    cases = [
        (
            "/login.php?id=' OR 1=1",
            "SQL Injection Attempt Detected in PCAP",
        ),
        (
            "/search?q=<script>alert(1)</script>",
            "XSS Attempt Detected in PCAP",
        ),
        (
            "/download?file=../../etc/passwd",
            "Directory Traversal Attempt Detected in PCAP",
        ),
        (
            "/admin",
            "Admin Panel Enumeration Detected in PCAP",
        ),
        (
            "/shell.php",
            "Suspicious Web Shell URI Detected in PCAP",
        ),
    ]

    for uri, expected_title in cases:
        event = create_http_event(uri)

        event.timestamp = _packet_timestamp(
            9, 0, "123456789"
        )

        findings = detect_network_web_attacks([event])

        assert len(findings) == 1
        assert findings[0].title == expected_title

        assert findings[0].first_seen == (
            "2026-07-16T09:00:00.123456789+00:00"
        )
        assert findings[0].last_seen == (
            "2026-07-16T09:00:00.123456789+00:00"
        )


def test_web_attack_deduplication_preserves_time_range():
    admin_events = [
        create_http_event("/admin")
        for _ in range(3)
    ]

    admin_events[0].timestamp = _packet_timestamp(9, 0)
    admin_events[1].timestamp = _packet_timestamp(9, 3)
    admin_events[2].timestamp = _packet_timestamp(9, 7)

    shell_event = create_http_event("/shell.php")
    shell_event.timestamp = _packet_timestamp(8, 0)

    findings = detect_network_web_attacks([
        admin_events[2],
        shell_event,
        admin_events[1],
        admin_events[0],
    ])

    admin_findings = [
        finding
        for finding in findings
        if finding.title
        == "Admin Panel Enumeration Detected in PCAP"
    ]

    shell_findings = [
        finding
        for finding in findings
        if finding.title
        == "Suspicious Web Shell URI Detected in PCAP"
    ]

    assert len(admin_findings) == 1
    assert len(shell_findings) == 1

    assert admin_findings[0].first_seen == (
        "2026-07-16T09:00:00+00:00"
    )
    assert admin_findings[0].last_seen == (
        "2026-07-16T09:07:00+00:00"
    )

    assert shell_findings[0].first_seen == (
        "2026-07-16T08:00:00+00:00"
    )
    assert shell_findings[0].last_seen == (
        "2026-07-16T08:00:00+00:00"
    )


def test_web_attack_invalid_timestamps_are_not_invented():
    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        event = create_http_event("/admin")
        event.timestamp = invalid_timestamp

        findings = detect_network_web_attacks([event])

        assert len(findings) == 1
        assert findings[0].first_seen is None
        assert findings[0].last_seen is None

    valid_event = create_http_event("/admin")
    valid_event.timestamp = _packet_timestamp(9, 0)

    invalid_event = create_http_event("/admin")
    invalid_event.timestamp = "invalid-timestamp"

    for events in (
        [valid_event, invalid_event],
        [invalid_event, valid_event],
    ):
        findings = detect_network_web_attacks(events)

        assert len(findings) == 1
        assert findings[0].first_seen is None
        assert findings[0].last_seen is None
