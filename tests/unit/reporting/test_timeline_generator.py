from src.models.threat_finding import ThreatFinding
from src.reporting.timeline_generator import generate_timeline


def test_generate_timeline_returns_list():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        port=3389,
        risk_score=160
    )

    timeline = generate_timeline([finding])

    assert isinstance(timeline, list)
    assert len(timeline) == 1


def test_generate_timeline_contains_event_data():
    finding = ThreatFinding(
        title="Unknown host with exposed RDP",
        severity="critical",
        description="Unknown host exposes RDP.",
        source="correlation",
        ip="192.168.1.77",
        port=3389,
        risk_score=160
    )

    timeline = generate_timeline([finding])

    assert timeline[0]["event"] == "Unknown host with exposed RDP"
    assert timeline[0]["severity"] == "critical"
    assert timeline[0]["ip"] == "192.168.1.77"
    assert timeline[0]["port"] == 3389
    assert timeline[0]["risk_score"] == 160


def test_generate_timeline_contains_time():
    finding = ThreatFinding(
        title="Critical finding",
        severity="critical",
        description="Critical issue.",
        source="test"
    )

    timeline = generate_timeline([finding])

    assert "time" in timeline[0]
    assert timeline[0]["time"] is None


def test_generate_timeline_uses_finding_first_seen():
    finding = ThreatFinding(
        title="Historical security event",
        severity="high",
        description="An event detected in historical logs.",
        source="test",
        first_seen="2026-07-16T10:00:00Z",
        last_seen="2026-07-16T10:00:00Z",
    )

    timeline = generate_timeline([finding])

    assert timeline[0]["time"] == "2026-07-16T10:00:00+00:00"


def test_generate_timeline_sorts_events_chronologically():
    later_finding = ThreatFinding(
        title="Later event",
        severity="high",
        description="Event occurred later.",
        source="test",
        first_seen="2026-07-16T12:00:00Z",
        last_seen="2026-07-16T12:00:00Z",
    )

    earlier_finding = ThreatFinding(
        title="Earlier event",
        severity="medium",
        description="Event occurred earlier.",
        source="test",
        first_seen="2026-07-16T09:00:00Z",
        last_seen="2026-07-16T09:00:00Z",
    )

    timeline = generate_timeline([
        later_finding,
        earlier_finding,
    ])

    assert [item["event"] for item in timeline] == [
        "Earlier event",
        "Later event",
    ]


def test_generate_timeline_normalizes_timezone_to_utc():
    finding = ThreatFinding(
        title="Timezone normalization event",
        severity="high",
        description="An event recorded with UTC+03:00 offset.",
        source="test",
        first_seen="2026-07-16T13:00:00+03:00",
        last_seen="2026-07-16T13:00:00+03:00",
    )

    timeline = generate_timeline([finding])

    assert timeline[0]["time"] == "2026-07-16T10:00:00+00:00"


def test_generate_timeline_rejects_timestamp_without_timezone():
    finding = ThreatFinding(
        title="Event without timezone",
        severity="medium",
        description="Source timestamp has no timezone information.",
        source="test",
        first_seen="2026-07-16T13:00:00",
        last_seen="2026-07-16T13:00:00",
    )

    timeline = generate_timeline([finding])

    assert timeline[0]["time"] is None


def test_generate_timeline_places_unknown_times_last():
    unknown_finding = ThreatFinding(
        title="Unknown time event",
        severity="medium",
        description="Event without a timestamp.",
        source="test",
    )

    later_finding = ThreatFinding(
        title="Later event",
        severity="high",
        description="Event at 12:00 UTC.",
        source="test",
        first_seen="2026-07-16T12:00:00Z",
    )

    delayed_finding = ThreatFinding(
        title="Delayed earlier event",
        severity="critical",
        description="Older event received after newer events.",
        source="test",
        first_seen="2026-07-16T09:00:00Z",
    )

    timeline = generate_timeline([
        unknown_finding,
        later_finding,
        delayed_finding,
    ])

    assert [item["event"] for item in timeline] == [
        "Delayed earlier event",
        "Later event",
        "Unknown time event",
    ]

    assert timeline[-1]["time"] is None


def test_generate_timeline_handles_invalid_timestamp():
    invalid_finding = ThreatFinding(
        title="Invalid timestamp event",
        severity="medium",
        description="Malformed timestamp.",
        source="test",
        first_seen="invalid-timestamp",
    )

    valid_finding = ThreatFinding(
        title="Valid timestamp event",
        severity="high",
        description="Valid event time.",
        source="test",
        first_seen="2026-07-16T09:00:00Z",
    )

    timeline = generate_timeline([
        invalid_finding,
        valid_finding,
    ])

    assert len(timeline) == 2

    assert timeline[0]["event"] == "Valid timestamp event"
    assert timeline[0]["time"] == "2026-07-16T09:00:00+00:00"

    assert timeline[1]["event"] == "Invalid timestamp event"
    assert timeline[1]["time"] is None


def test_timeline_preserves_nanosecond_precision():
    timestamps = [
        (
            "2026-07-16T09:00:00.123456789Z",
            "2026-07-16T09:00:00.123456789+00:00",
        ),
        (
            "2026-07-16T09:00:00.000000001Z",
            "2026-07-16T09:00:00.000000001+00:00",
        ),
        (
            "2026-07-16T09:00:00.123456780Z",
            "2026-07-16T09:00:00.123456780+00:00",
        ),
    ]

    for original, expected in timestamps:
        finding = ThreatFinding(
            title="Nanosecond precision event",
            severity="high",
            description="Timestamp precision test.",
            source="PCAP Network Detection",
            first_seen=original,
            last_seen=original,
        )

        timeline = generate_timeline([finding])

        assert len(timeline) == 1
        assert timeline[0]["time"] == expected


def test_timeline_sorts_events_with_one_nanosecond_difference():
    later = ThreatFinding(
        title="Later nanosecond event",
        severity="high",
        description="Occurred one nanosecond later.",
        source="PCAP Network Detection",
        first_seen="2026-07-16T09:00:00.123456789+00:00",
        last_seen="2026-07-16T09:00:00.123456789+00:00",
    )

    earlier = ThreatFinding(
        title="Earlier nanosecond event",
        severity="medium",
        description="Occurred one nanosecond earlier.",
        source="PCAP Network Detection",
        first_seen="2026-07-16T09:00:00.123456788+00:00",
        last_seen="2026-07-16T09:00:00.123456788+00:00",
    )

    timeline = generate_timeline([
        later,
        earlier,
    ])

    assert len(timeline) == 2

    assert [item["event"] for item in timeline] == [
        "Earlier nanosecond event",
        "Later nanosecond event",
    ]

    assert timeline[0]["time"] == (
        "2026-07-16T09:00:00.123456788+00:00"
    )

    assert timeline[1]["time"] == (
        "2026-07-16T09:00:00.123456789+00:00"
    )


def test_timeline_normalizes_timezone_without_losing_nanoseconds():
    finding = ThreatFinding(
        title="Nanosecond timezone event",
        severity="high",
        description="Timestamp recorded with UTC+03:00.",
        source="PCAP Network Detection",
        first_seen="2026-07-16T13:00:00.987654321+03:00",
        last_seen="2026-07-16T13:00:00.987654321+03:00",
    )

    timeline = generate_timeline([finding])

    assert len(timeline) == 1

    assert timeline[0]["time"] == (
        "2026-07-16T10:00:00.987654321+00:00"
    )
