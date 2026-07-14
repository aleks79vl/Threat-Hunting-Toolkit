from src.detection.network.packet_anomaly_detector import (
    detect_packet_anomalies,
)
from src.models.network_event import NetworkEvent


def create_network_event(
    src_ip: str = "10.0.0.3",
    dst_ip: str = "10.0.0.10",
    dst_port: str = "443",
    protocol: str = "TCP",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port="51514",
        dst_port=dst_port,
        dns_query="",
        http_host="",
        http_uri="",
    )


def test_detect_repeated_connections():
    events = [
        create_network_event(
            src_ip="10.0.0.3",
            dst_ip="10.0.0.20",
            dst_port="443",
        )
        for _ in range(20)
    ]

    findings = detect_packet_anomalies(events)

    assert any(
        finding.title == "Repeated Network Connection Detected"
        for finding in findings
    )


def test_detect_one_to_many_communication():
    events = [
        create_network_event(
            src_ip="10.0.0.50",
            dst_ip=f"10.0.0.{index}",
        )
        for index in range(1, 11)
    ]

    findings = detect_packet_anomalies(events)

    assert any(
        finding.title == "One-to-Many Network Communication Detected"
        and finding.ip == "10.0.0.50"
        for finding in findings
    )


def test_detect_unusual_destination_port():
    events = [
        create_network_event(
            dst_ip="10.0.0.20",
            dst_port="4444",
        )
    ]

    findings = detect_packet_anomalies(events)

    assert any(
        finding.title == "Unusual Destination Port Detected"
        and finding.port == "4444"
        for finding in findings
    )


def test_ignore_normal_common_port_activity():
    events = [
        create_network_event(
            dst_port="443",
        ),
        create_network_event(
            dst_port="80",
        ),
        create_network_event(
            dst_port="53",
        ),
    ]

    findings = detect_packet_anomalies(events)

    assert findings == []


def test_ignore_empty_events():
    findings = detect_packet_anomalies([])

    assert findings == []