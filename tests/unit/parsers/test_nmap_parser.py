from src.parsers.nmap_parser import parse_nmap_xml

from datetime import datetime, timezone
import pytest


def test_parse_nmap_xml_returns_events():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    assert len(events) == 3


def test_parse_nmap_xml_detects_host_ip():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    ips = [event.src_ip for event in events]

    assert "192.168.1.10" in ips
    assert "192.168.1.77" in ips


def test_parse_nmap_xml_detects_open_ports():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    ports = [event.dst_port for event in events]

    assert 22 in ports
    assert 445 in ports
    assert 3389 in ports


def test_parse_nmap_xml_returns_security_event_fields():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")
    event = events[0]

    assert event.source == "nmap"
    assert event.event_type == "open_port"
    assert event.protocol == "TCP"


def test_nmap_parser_preserves_host_observation_interval(tmp_path):
    def epoch(hour: int, minute: int) -> int:
        return int(
            datetime(
                2026, 6, 29, hour, minute,
                tzinfo=timezone.utc,
            ).timestamp()
        )

    xml_file = tmp_path / "nmap_with_timestamps.xml"

    xml_file.write_text(
        f"""
<nmaprun scanner="nmap" start="{epoch(9, 0)}">
    <host
        starttime="{epoch(9, 2)}"
        endtime="{epoch(9, 3)}"
    >
        <status state="up"/>
        <address addr="192.0.2.17" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="3389">
                <state state="open"/>
                <service name="ms-wbt-server"/>
            </port>
        </ports>
    </host>
    <runstats>
        <finished time="{epoch(9, 10)}"/>
    </runstats>
</nmaprun>
""",
        encoding="utf-8",
    )

    events = parse_nmap_xml(str(xml_file))

    assert len(events) == 1

    event = events[0]

    assert event.src_ip == "192.0.2.17"
    assert event.dst_port == 3389

    # Nmap scan metadata is not an exact port-event timestamp.
    assert event.timestamp == ""

    # Prefer the host-specific observation interval.
    assert event.observation_start == (
        "2026-06-29T09:02:00+00:00"
    )
    assert event.observation_end == (
        "2026-06-29T09:03:00+00:00"
    )


def test_nmap_parser_does_not_invent_missing_observation_time():
    events = parse_nmap_xml(
        "data/raw/network/nmap_scan.xml"
    )

    assert len(events) == 3

    for event in events:
        assert event.timestamp == ""
        assert event.observation_start is None
        assert event.observation_end is None
        assert event.observation_scope is None


@pytest.mark.parametrize(
    "host_start,host_end,scan_start,scan_end,expected_start,expected_end",
    [
        # No host interval: use scan interval.
        (None, None, 9, 10, 9, 10),

        # Incomplete host interval: use scan interval.
        (9, None, 8, 10, 8, 10),

        # Reversed host interval: use scan interval.
        (11, 10, 8, 12, 8, 12),

        # Incomplete scan interval: unknown.
        (None, None, 9, None, None, None),

        # Reversed scan interval: unknown.
        (None, None, 10, 9, None, None),
    ],
)


def test_nmap_parser_observation_interval_fallback(
    tmp_path,
    host_start,
    host_end,
    scan_start,
    scan_end,
    expected_start,
    expected_end,
):
    def epoch(hour):
        if hour is None:
            return None

        return int(
            datetime(
                2026, 6, 29, hour, 0,
                tzinfo=timezone.utc,
            ).timestamp()
        )

    def iso(hour):
        if hour is None:
            return None

        return f"2026-06-29T{hour:02}:00:00+00:00"

    scan_attrs = f' start="{epoch(scan_start)}"'

    host_attrs = ""

    if host_start is not None:
        host_attrs += f' starttime="{epoch(host_start)}"'

    if host_end is not None:
        host_attrs += f' endtime="{epoch(host_end)}"'

    runstats = ""

    if scan_end is not None:
        runstats = (
            f'<runstats><finished time="{epoch(scan_end)}"/></runstats>'
        )

    xml_file = tmp_path / "nmap_intervals.xml"

    xml_file.write_text(
        f"""
<nmaprun scanner="nmap"{scan_attrs}>
    <host{host_attrs}>
        <status state="up"/>
        <address addr="192.0.2.17" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="3389">
                <state state="open"/>
            </port>
        </ports>
    </host>
    {runstats}
</nmaprun>
""",
        encoding="utf-8",
    )

    events = parse_nmap_xml(str(xml_file))

    assert len(events) == 1

    event = events[0]

    assert event.timestamp == ""
    assert event.observation_start == iso(expected_start)
    assert event.observation_end == iso(expected_end)

    expected_scope = (
        "scan" if expected_start is not None else None
    )

    assert event.observation_scope == expected_scope
