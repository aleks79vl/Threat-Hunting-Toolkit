from datetime import datetime, timezone

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


def _anomaly_epoch(
    hour: int,
    minute: int,
    fraction: str = "000000000",
) -> str:
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )
    return f"{int(dt.timestamp())}.{fraction}"


def test_repeated_connections_preserve_packet_time_range():
    events = [
        create_network_event(
            src_ip="10.0.0.3",
            dst_ip="10.0.0.20",
            dst_port="443",
        )
        for _ in range(20)
    ]

    for event in events:
        event.timestamp = _anomaly_epoch(9, 3)

    events[0].timestamp = _anomaly_epoch(
        9, 0, "123456789"
    )
    events[-1].timestamp = _anomaly_epoch(
        9, 7, "987654321"
    )

    unrelated = create_network_event(
        src_ip="10.0.0.99",
        dst_ip="10.0.0.30",
        dst_port="443",
    )
    unrelated.timestamp = _anomaly_epoch(7, 0)

    findings = detect_packet_anomalies([
        events[-1],
        unrelated,
        *events[1:-1],
        events[0],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Repeated Network Connection Detected"
        and finding.ip == "10.0.0.20"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )
    assert matching[0].last_seen == (
        "2026-07-16T09:07:00.987654321+00:00"
    )


def test_one_to_many_preserves_source_time_range():
    events = [
        create_network_event(
            src_ip="10.0.0.50",
            dst_ip=f"10.0.1.{index}",
            dst_port="443",
        )
        for index in range(1, 11)
    ]

    for event in events:
        event.timestamp = _anomaly_epoch(9, 3)

    events[0].timestamp = _anomaly_epoch(9, 0)
    events[-1].timestamp = _anomaly_epoch(9, 7)

    unrelated = create_network_event(
        src_ip="10.0.0.51",
        dst_ip="10.0.0.100",
    )
    unrelated.timestamp = _anomaly_epoch(6, 0)

    findings = detect_packet_anomalies([
        events[-1],
        unrelated,
        *events[1:-1],
        events[0],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title
        == "One-to-Many Network Communication Detected"
        and finding.ip == "10.0.0.50"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-07-16T09:00:00+00:00"
    )
    assert matching[0].last_seen == (
        "2026-07-16T09:07:00+00:00"
    )


def test_unusual_port_preserves_connection_time_range():
    events = [
        create_network_event(
            src_ip="10.0.0.3",
            dst_ip="10.0.0.20",
            dst_port="4444",
        )
        for _ in range(3)
    ]

    events[0].timestamp = _anomaly_epoch(9, 0)
    events[1].timestamp = _anomaly_epoch(9, 3)
    events[2].timestamp = _anomaly_epoch(9, 7)

    other_port = create_network_event(
        src_ip="10.0.0.3",
        dst_ip="10.0.0.20",
        dst_port="5555",
    )
    other_port.timestamp = _anomaly_epoch(6, 0)

    findings = detect_packet_anomalies([
        events[2],
        other_port,
        events[1],
        events[0],
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Unusual Destination Port Detected"
        and finding.port == "4444"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-07-16T09:00:00+00:00"
    )
    assert matching[0].last_seen == (
        "2026-07-16T09:07:00+00:00"
    )

    other = [
        finding
        for finding in findings
        if finding.title == "Unusual Destination Port Detected"
        and finding.port == "5555"
    ]

    assert len(other) == 1
    assert other[0].first_seen == (
        "2026-07-16T06:00:00+00:00"
    )
    assert other[0].last_seen == (
        "2026-07-16T06:00:00+00:00"
    )


def test_packet_anomaly_invalid_timestamp_is_not_invented():
    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        valid_event = create_network_event(
            dst_port="4444",
        )
        valid_event.timestamp = _anomaly_epoch(9, 0)

        invalid_event = create_network_event(
            dst_port="4444",
        )
        invalid_event.timestamp = invalid_timestamp

        for events in (
            [valid_event, invalid_event],
            [invalid_event, valid_event],
        ):
            findings = detect_packet_anomalies(events)

            matching = [
                finding
                for finding in findings
                if finding.title
                == "Unusual Destination Port Detected"
                and finding.port == "4444"
            ]

            assert len(matching) == 1
            assert matching[0].first_seen is None
            assert matching[0].last_seen is None
