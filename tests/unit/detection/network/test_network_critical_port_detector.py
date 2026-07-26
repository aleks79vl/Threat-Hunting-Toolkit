import json

from src.detection.nmap.network_critical_port_detector import (
    detect_network_critical_ports,
)
from src.models.network_event import NetworkEvent


def create_network_event(
    src_ip: str = "10.0.0.3",
    dst_ip: str = "10.0.0.10",
    src_port="51514",
    dst_port="80",
    protocol: str = "TCP",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        dns_query="",
        http_host="",
        http_uri="",
    )


def test_detect_critical_destination_port(tmp_path):
    critical_ports_file = tmp_path / "critical_ports.json"

    critical_ports_file.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    events = [
        create_network_event(dst_ip="10.0.0.20",
            dst_port="3389",)
    ]

    findings = detect_network_critical_ports(events,
        str(critical_ports_file),)

    assert len(findings) == 1
    assert findings[0].title == "Critical Network Port Detected"
    assert findings[0].severity == "high"
    assert findings[0].ip == "10.0.0.20"
    assert findings[0].port == 3389


def test_detect_critical_source_port(tmp_path):
    critical_ports_file = tmp_path / "critical_ports.json"

    critical_ports_file.write_text(
        json.dumps({"critical_ports": [53]}),
        encoding="utf-8",
    )

    events = [
        create_network_event(
            src_ip="10.0.0.138",
            src_port="53",
            dst_ip="10.0.0.3",
            dst_port="57772",
            protocol="DNS",
        )
    ]

    findings = detect_network_critical_ports(
        events,
        str(critical_ports_file),
    )

    assert len(findings) == 1
    assert findings[0].port == 53


def test_ignore_non_critical_ports(tmp_path):
    critical_ports_file = tmp_path / "critical_ports.json"

    critical_ports_file.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    events = [
        create_network_event(
            dst_port="443",
        )
    ]

    findings = detect_network_critical_ports(
        events,
        str(critical_ports_file),
    )

    assert findings == []


def test_duplicate_critical_port_creates_single_finding(tmp_path):
    critical_ports_file = tmp_path / "critical_ports.json"

    critical_ports_file.write_text(
        json.dumps({"critical_ports": [443]}),
        encoding="utf-8",
    )

    events = [
        create_network_event(
            src_ip="10.0.0.3",
            dst_ip="173.194.112.47",
            dst_port="443",
        ),
        create_network_event(
            src_ip="10.0.0.3",
            dst_ip="173.194.112.47",
            dst_port="443",
        ),
    ]

    findings = detect_network_critical_ports(
        events,
        str(critical_ports_file),
    )

    assert len(findings) == 1
    assert findings[0].port == 443


def test_invalid_port_values_are_ignored(tmp_path):
    critical_ports_file = tmp_path / "critical_ports.json"

    critical_ports_file.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    events = [
        create_network_event(
            src_port="",
            dst_port="not-a-port",
        )
    ]

    findings = detect_network_critical_ports(
        events,
        str(critical_ports_file),
    )

    assert findings == []