from src.detection.network.dns_activity_detector import (
    detect_suspicious_dns_activity,
)
from src.models.network_event import NetworkEvent


def create_dns_event(
    dns_query: str,
    src_ip: str = "10.0.0.3",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip="10.0.0.138",
        protocol="DNS",
        src_port="57772",
        dst_port="53",
        dns_query=dns_query,
        http_host="",
        http_uri="",
    )


def test_detect_repeated_dns_queries():
    events = [
        create_dns_event("example.com")
        for _ in range(10)
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "Repeated DNS Query Activity Detected"
        for finding in findings
    )


def test_detect_long_dns_query():
    long_query = (
        "abcdefghijklmnopqrstuvwxyz"
        "abcdefghijklmnopqrstuvwxyz"
        ".example.com"
    )

    events = [
        create_dns_event(long_query)
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "Long DNS Query Detected"
        for finding in findings
    )


def test_detect_suspicious_dns_tld():
    events = [
        create_dns_event("malicious-example.xyz")
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "Suspicious DNS TLD Detected"
        for finding in findings
    )


def test_detect_high_dns_query_volume():
    events = [
        create_dns_event(
            f"domain-{index}.com",
            src_ip="10.0.0.50",
        )
        for index in range(100)
    ]

    findings = detect_suspicious_dns_activity(events)

    assert any(
        finding.title == "High DNS Query Volume Detected"
        and finding.ip == "10.0.0.50"
        for finding in findings
    )


def test_ignore_normal_dns_activity():
    events = [
        create_dns_event("google.com"),
        create_dns_event("example.com"),
        create_dns_event("walla.co.il"),
    ]

    findings = detect_suspicious_dns_activity(events)

    assert findings == []


def test_ignore_events_without_dns_queries():
    events = [
        NetworkEvent(
            timestamp="1385452028.038401000",
            src_ip="10.0.0.3",
            dst_ip="173.194.112.47",
            protocol="TCP",
            src_port="45822",
            dst_port="443",
        )
    ]

    findings = detect_suspicious_dns_activity(events)

    assert findings == []