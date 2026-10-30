import json
from datetime import datetime, timezone

from src.detection.nmap.network_unknown_ip_detector import (
    detect_unknown_network_ips,
)
from src.models.network_event import NetworkEvent


def create_network_event(
    src_ip: str = "",
    dst_ip: str = "",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="TCP",
        src_port=45822,
        dst_port=443,
        dns_query="",
        http_host="",
        http_uri="",
    )


def test_detect_unknown_source_ip(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(json.dumps({"allowed_ips": ["10.0.0.3"]}),
        encoding="utf-8",)

    events = [
        create_network_event(src_ip="192.168.1.50",dst_ip="10.0.0.3",)
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert len(findings) == 1
    assert findings[0].ip == "192.168.1.50"
    assert findings[0].source == "PCAP Network Detection"


def test_detect_unknown_destination_ip(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(json.dumps({"allowed_ips": ["10.0.0.3"]}),
        encoding="utf-8",)

    events = [
        create_network_event(src_ip="10.0.0.3",dst_ip="173.194.112.47",)
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert len(findings) == 1
    assert findings[0].ip == "173.194.112.47"


def test_ignore_whitelisted_ips(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(
        json.dumps(
            {
                "allowed_ips": ["10.0.0.3","10.0.0.138",]
            }
        ),
        encoding="utf-8",
    )

    events = [
        create_network_event(src_ip="10.0.0.3",dst_ip="10.0.0.138",)
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert findings == []


def test_duplicate_unknown_ip_creates_single_finding(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(json.dumps({"allowed_ips": []}),
        encoding="utf-8",)

    events = [
        create_network_event(
            src_ip="192.168.1.50",
            dst_ip="",
        ),
        create_network_event(
            src_ip="192.168.1.50",
            dst_ip="",
        ),
        create_network_event(
            src_ip="192.168.1.50",
            dst_ip="",
        ),
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert len(findings) == 1
    assert findings[0].ip == "192.168.1.50"


def _unknown_epoch(
    hour: int,
    minute: int,
    fraction: str = "000000000",
) -> str:
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )
    return f"{int(dt.timestamp())}.{fraction}"


def test_unknown_ip_preserves_source_and_destination_time_range(
    tmp_path,
):
    whitelist_file = tmp_path / "whitelist.json"
    whitelist_file.write_text(
        json.dumps({"allowed_ips": ["10.0.0.3"]}),
        encoding="utf-8",
    )

    first = create_network_event(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.3",
    )
    first.timestamp = _unknown_epoch(
        9, 0, "123456789"
    )

    middle = create_network_event(
        src_ip="10.0.0.3",
        dst_ip="192.168.1.50",
    )
    middle.timestamp = _unknown_epoch(9, 3)

    last = create_network_event(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.3",
    )
    last.timestamp = _unknown_epoch(
        9, 7, "987654321"
    )

    unrelated = create_network_event(
        src_ip="203.0.113.99",
        dst_ip="10.0.0.3",
    )
    unrelated.timestamp = _unknown_epoch(6, 0)

    findings = detect_unknown_network_ips(
        [last, unrelated, middle, first],
        str(whitelist_file),
    )

    by_ip = {
        finding.ip: finding
        for finding in findings
    }

    assert len(findings) == 2

    assert by_ip["192.168.1.50"].first_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )
    assert by_ip["192.168.1.50"].last_seen == (
        "2026-07-16T09:07:00.987654321+00:00"
    )

    assert by_ip["203.0.113.99"].first_seen == (
        "2026-07-16T06:00:00+00:00"
    )
    assert by_ip["203.0.113.99"].last_seen == (
        "2026-07-16T06:00:00+00:00"
    )


def test_unknown_ip_preserves_nanosecond_order(
    tmp_path,
):
    whitelist_file = tmp_path / "whitelist.json"
    whitelist_file.write_text(
        json.dumps({"allowed_ips": []}),
        encoding="utf-8",
    )

    earlier = create_network_event(
        src_ip="192.168.1.50",
        dst_ip="192.168.1.50",
    )
    earlier.timestamp = _unknown_epoch(
        9, 0, "123456788"
    )

    later = create_network_event(
        src_ip="192.168.1.50",
        dst_ip="192.168.1.50",
    )
    later.timestamp = _unknown_epoch(
        9, 0, "123456789"
    )

    findings = detect_unknown_network_ips(
        [later, earlier],
        str(whitelist_file),
    )

    assert len(findings) == 1
    assert findings[0].ip == "192.168.1.50"

    assert findings[0].first_seen == (
        "2026-07-16T09:00:00.123456788+00:00"
    )
    assert findings[0].last_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )


def test_unknown_ip_invalid_timestamp_is_not_invented(
    tmp_path,
):
    whitelist_file = tmp_path / "whitelist.json"
    whitelist_file.write_text(
        json.dumps({"allowed_ips": ["10.0.0.3"]}),
        encoding="utf-8",
    )

    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        valid = create_network_event(
            src_ip="192.168.1.50",
            dst_ip="10.0.0.3",
        )
        valid.timestamp = _unknown_epoch(9, 0)

        invalid = create_network_event(
            src_ip="10.0.0.3",
            dst_ip="192.168.1.50",
        )
        invalid.timestamp = invalid_timestamp

        for events in (
            [valid, invalid],
            [invalid, valid],
        ):
            findings = detect_unknown_network_ips(
                events,
                str(whitelist_file),
            )

            assert len(findings) == 1
            assert findings[0].ip == "192.168.1.50"
            assert findings[0].first_seen is None
            assert findings[0].last_seen is None
