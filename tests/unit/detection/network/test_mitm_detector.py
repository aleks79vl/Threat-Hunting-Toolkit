from datetime import datetime, timezone

from src.detection.network.mitm_detector import detect_arp_spoofing
from src.models.network_event import NetworkEvent


def create_arp_event(
    arp_src_ip: str,
    arp_src_mac: str,
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        protocol="ARP",
        arp_src_ip=arp_src_ip,
        arp_src_mac=arp_src_mac,
    )


def test_detect_arp_spoofing_when_ip_has_multiple_macs():
    events = [
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:aa:aa:aa:aa:aa",
        ),
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="bb:bb:bb:bb:bb:bb",
        ),
    ]

    findings = detect_arp_spoofing(events)

    assert len(findings) == 1
    assert findings[0].title == "Possible ARP Spoofing Detected"
    assert findings[0].severity == "high"
    assert findings[0].ip == "10.0.0.1"


def test_ignore_normal_arp_mapping():
    events = [
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:aa:aa:aa:aa:aa",
        ),
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:aa:aa:aa:aa:aa",
        ),
    ]

    findings = detect_arp_spoofing(events)

    assert findings == []


def test_ignore_empty_events():
    findings = detect_arp_spoofing([])

    assert findings == []


def _arp_epoch(
    hour: int,
    minute: int,
    fraction: str = "000000000",
) -> str:
    dt = datetime(
        2026, 7, 16, hour, minute,
        tzinfo=timezone.utc,
    )
    return f"{int(dt.timestamp())}.{fraction}"


def test_arp_spoofing_preserves_source_time_range():
    first = create_arp_event(
        "10.0.0.1",
        "aa:aa:aa:aa:aa:aa",
    )
    first.timestamp = _arp_epoch(
        9, 0, "123456789"
    )

    second = create_arp_event(
        "10.0.0.1",
        "bb:bb:bb:bb:bb:bb",
    )
    second.timestamp = _arp_epoch(9, 3)

    third = create_arp_event(
        "10.0.0.1",
        "aa:aa:aa:aa:aa:aa",
    )
    third.timestamp = _arp_epoch(
        9, 7, "987654321"
    )

    unrelated = create_arp_event(
        "10.0.0.99",
        "cc:cc:cc:cc:cc:cc",
    )
    unrelated.timestamp = _arp_epoch(6, 0)

    findings = detect_arp_spoofing([
        third,
        unrelated,
        second,
        first,
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Possible ARP Spoofing Detected"
        and finding.ip == "10.0.0.1"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-07-16T09:00:00.123456789+00:00"
    )
    assert matching[0].last_seen == (
        "2026-07-16T09:07:00.987654321+00:00"
    )


def test_arp_spoofing_includes_destination_arp_fields():
    first = create_arp_event(
        "10.0.0.20",
        "dd:dd:dd:dd:dd:dd",
    )
    first.arp_dst_ip = "10.0.0.1"
    first.arp_dst_mac = "aa:aa:aa:aa:aa:aa"
    first.timestamp = _arp_epoch(10, 1)

    second = create_arp_event(
        "10.0.0.1",
        "bb:bb:bb:bb:bb:bb",
    )
    second.timestamp = _arp_epoch(10, 5)

    unrelated = create_arp_event(
        "10.0.0.99",
        "cc:cc:cc:cc:cc:cc",
    )
    unrelated.timestamp = _arp_epoch(6, 0)

    findings = detect_arp_spoofing([
        second,
        unrelated,
        first,
    ])

    matching = [
        finding
        for finding in findings
        if finding.title == "Possible ARP Spoofing Detected"
        and finding.ip == "10.0.0.1"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-07-16T10:01:00+00:00"
    )
    assert matching[0].last_seen == (
        "2026-07-16T10:05:00+00:00"
    )


def test_arp_spoofing_invalid_timestamp_is_not_invented():
    for invalid_timestamp in (
        "",
        "invalid-timestamp",
        "NaN",
        "Infinity",
    ):
        valid_event = create_arp_event(
            "10.0.0.1",
            "aa:aa:aa:aa:aa:aa",
        )
        valid_event.timestamp = _arp_epoch(9, 0)

        invalid_event = create_arp_event(
            "10.0.0.1",
            "bb:bb:bb:bb:bb:bb",
        )
        invalid_event.timestamp = invalid_timestamp

        for events in (
            [valid_event, invalid_event],
            [invalid_event, valid_event],
        ):
            findings = detect_arp_spoofing(events)

            matching = [
                finding
                for finding in findings
                if finding.title
                == "Possible ARP Spoofing Detected"
                and finding.ip == "10.0.0.1"
            ]

            assert len(matching) == 1
            assert matching[0].first_seen is None
            assert matching[0].last_seen is None
