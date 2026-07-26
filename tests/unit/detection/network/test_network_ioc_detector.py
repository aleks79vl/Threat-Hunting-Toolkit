from src.detection.network.network_ioc_detector import detect_network_iocs
from src.models.network_event import NetworkEvent


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