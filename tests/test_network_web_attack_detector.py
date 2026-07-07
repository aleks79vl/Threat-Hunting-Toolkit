from src.detection.network_web_attack_detector import (
    detect_network_web_attacks,
)
from src.models.network_event import NetworkEvent


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