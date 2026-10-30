import json
from datetime import datetime, timezone

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


def _critical_epoch(
    hour: int,
    minute: int,
    fraction: str = "000000000",
) -> str:
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )
    return f"{int(dt.timestamp())}.{fraction}"


def test_critical_port_preserves_independent_time_ranges(
    tmp_path,
):
    config = tmp_path / "critical_ports.json"
    config.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    first = create_network_event(
        dst_ip="10.0.0.20",
        dst_port="3389",
    )
    first.timestamp = _critical_epoch(
        9, 0, "123456789"
    )

    middle = create_network_event(
        dst_ip="10.0.0.20",
        dst_port="3389",
    )
    middle.timestamp = _critical_epoch(9, 3)

    last = create_network_event(
        dst_ip="10.0.0.20",
        dst_port="3389",
    )
    last.timestamp = _critical_epoch(
        9, 7, "987654321"
    )

    unrelated = create_network_event(
        dst_ip="10.0.0.30",
        dst_port="3389",
    )
    unrelated.timestamp = _critical_epoch(6, 0)

    findings = detect_network_critical_ports(
        [last, unrelated, middle, first],
        str(config),
    )

    assert len(findings) == 2

    by_ip = {
        finding.ip: finding
        for finding in findings
    }

    assert by_ip["10.0.0.20"].first_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )
    assert by_ip["10.0.0.20"].last_seen == (
        "2026-07-16T09:07:00.987654321+00:00"
    )

    assert by_ip["10.0.0.30"].first_seen == (
        "2026-07-16T06:00:00+00:00"
    )
    assert by_ip["10.0.0.30"].last_seen == (
        "2026-07-16T06:00:00+00:00"
    )


def test_critical_port_combines_source_and_destination_matches(
    tmp_path,
):
    config = tmp_path / "critical_ports.json"
    config.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    source_match = create_network_event(
        src_port="3389",
        dst_port="443",
    )
    source_match.timestamp = _critical_epoch(9, 0)

    destination_match = create_network_event(
        src_port="51514",
        dst_port="3389",
    )
    destination_match.timestamp = _critical_epoch(9, 5)

    findings = detect_network_critical_ports(
        [destination_match, source_match],
        str(config),
    )

    assert len(findings) == 1
    assert findings[0].port == 3389
    assert findings[0].first_seen == (
        "2026-07-16T09:00:00+00:00"
    )
    assert findings[0].last_seen == (
        "2026-07-16T09:05:00+00:00"
    )


def test_critical_port_preserves_nanosecond_order(
    tmp_path,
):
    config = tmp_path / "critical_ports.json"
    config.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    earlier = create_network_event(dst_port="3389")
    earlier.timestamp = _critical_epoch(
        9, 0, "123456788"
    )

    later = create_network_event(dst_port="3389")
    later.timestamp = _critical_epoch(
        9, 0, "123456789"
    )

    findings = detect_network_critical_ports(
        [later, earlier],
        str(config),
    )

    assert len(findings) == 1

    assert findings[0].first_seen == (
        "2026-07-16T09:00:00.123456788+00:00"
    )
    assert findings[0].last_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )


def test_critical_port_invalid_timestamp_is_not_invented(
    tmp_path,
):
    config = tmp_path / "critical_ports.json"
    config.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        valid = create_network_event(dst_port="3389")
        valid.timestamp = _critical_epoch(9, 0)

        invalid = create_network_event(dst_port="3389")
        invalid.timestamp = invalid_timestamp

        for events in (
            [valid, invalid],
            [invalid, valid],
        ):
            findings = detect_network_critical_ports(
                events,
                str(config),
            )

            assert len(findings) == 1
            assert findings[0].first_seen is None
            assert findings[0].last_seen is None
