from datetime import datetime, timezone

import pytest

from src.application.traditional_detection_pipeline import (
    run_traditional_detection_pipeline,
)
from src.config.app_config import default_app_config
from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent


def test_traditional_detection_pipeline_runs_default_sources():
    config = default_app_config()

    result = run_traditional_detection_pipeline(
        nmap_file=config.nmap_file,
        windows_events_file=config.windows_events_file,
        firewall_file=config.firewall_file,
        web_log_file=config.web_log_file,
        whitelist_file=config.whitelist_file,
        critical_ports_file=config.critical_ports_file,
    )

    assert result.firewall_events
    assert all(
        isinstance(event, SecurityEvent)
        for event in result.firewall_events
    )
    assert all(
        isinstance(finding, ThreatFinding)
        for finding in result.nmap_findings
        + result.windows_findings
        + result.firewall_findings
        + result.web_findings
    )


def test_traditional_pipeline_preserves_configured_windows_time(
    tmp_path,
):
    config = default_app_config()

    windows_csv = tmp_path / "windows_events.csv"

    windows_csv.write_text(
        "timestamp,event_id,computer,username,src_ip,"
        "logon_type,process_name,message\n"
        "2026-07-16 13:00:00.123456789,4720,"
        "WIN-DC01,temp_admin,192.168.1.20,"
        "0,net.exe,User account created\n",
        encoding="utf-8",
    )

    result = run_traditional_detection_pipeline(
        nmap_file=config.nmap_file,
        windows_events_file=str(windows_csv),
        firewall_file=config.firewall_file,
        web_log_file=config.web_log_file,
        whitelist_file=config.whitelist_file,
        critical_ports_file=config.critical_ports_file,
        windows_source_timezone="Asia/Jerusalem",
    )

    matching = [
        finding
        for finding in result.windows_findings
        if finding.title == "Windows User Account Created"
    ]

    assert len(matching) == 1

    expected_time = (
        "2026-07-16T10:00:00.123456789+00:00"
    )

    assert matching[0].first_seen == expected_time
    assert matching[0].last_seen == expected_time


def test_traditional_pipeline_preserves_configured_firewall_time(
    tmp_path,
):
    config = default_app_config()

    firewall_log = tmp_path / "firewall.log"

    firewall_log.write_text(
        "2026-07-16 13:00:00.123456789 DENY TCP "
        "203.0.113.15 192.168.1.77 22\n",
        encoding="utf-8",
    )

    result = run_traditional_detection_pipeline(
        nmap_file=config.nmap_file,
        windows_events_file=config.windows_events_file,
        firewall_file=str(firewall_log),
        web_log_file=config.web_log_file,
        whitelist_file=config.whitelist_file,
        critical_ports_file=config.critical_ports_file,
        firewall_source_timezone="Asia/Jerusalem",
    )

    matching = [
        finding
        for finding in result.firewall_findings
        if finding.title == "Firewall Blocked Critical Port Access"
        and finding.ip == "203.0.113.15"
    ]

    assert len(matching) == 1

    expected_time = (
        "2026-07-16T10:00:00.123456789+00:00"
    )

    assert matching[0].first_seen == expected_time
    assert matching[0].last_seen == expected_time


def test_traditional_pipeline_preserves_apache_grouped_time(
    tmp_path,
):
    config = default_app_config()
    web_log = tmp_path / "apache_access.log"

    web_log.write_text(
        '203.0.113.15 - - '
        '[29/Jun/2026:12:05:00.123456789 +0300] '
        '"POST /admin/login.php HTTP/1.1" '
        '401 512 "-" "Mozilla/5.0"\n'

        '203.0.113.15 - - '
        '[29/Jun/2026:08:00:00 +0000] '
        '"GET / HTTP/1.1" '
        '200 100 "-" "Mozilla/5.0"\n'

        '203.0.113.15 - - '
        '[29/Jun/2026:09:00:00.123456789 +0000] '
        '"POST /admin/login.php HTTP/1.1" '
        '401 512 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    result = run_traditional_detection_pipeline(
        nmap_file=config.nmap_file,
        windows_events_file=config.windows_events_file,
        firewall_file=config.firewall_file,
        web_log_file=str(web_log),
        whitelist_file=config.whitelist_file,
        critical_ports_file=config.critical_ports_file,
    )

    matching = [
        finding
        for finding in result.web_findings
        if finding.title == "Possible Admin Brute Force Detected"
        and finding.ip == "203.0.113.15"
    ]

    assert len(matching) == 1

    assert matching[0].first_seen == (
        "2026-06-29T09:00:00.123456789+00:00"
    )
    assert matching[0].last_seen == (
        "2026-06-29T09:05:00.123456789+00:00"
    )


@pytest.mark.parametrize(
    "host_has_interval,expected_scope,expected_start,expected_end",
    [
        (
            True,
            "host",
            "2026-06-29T09:02:00+00:00",
            "2026-06-29T09:03:00+00:00",
        ),
        (
            False,
            "scan",
            "2026-06-29T09:00:00+00:00",
            "2026-06-29T09:10:00+00:00",
        ),
    ],
)


def test_traditional_pipeline_preserves_nmap_observation_provenance(
    tmp_path,
    host_has_interval,
    expected_scope,
    expected_start,
    expected_end,
):
    config = default_app_config()

    def epoch(hour, minute):
        return int(
            datetime(
                2026, 6, 29, hour, minute,
                tzinfo=timezone.utc,
            ).timestamp()
        )

    host_interval = ""

    if host_has_interval:
        host_interval = (
            f' starttime="{epoch(9, 2)}"'
            f' endtime="{epoch(9, 3)}"'
        )

    nmap_file = tmp_path / "nmap_with_time.xml"

    nmap_file.write_text(
        f"""
<nmaprun scanner="nmap" start="{epoch(9, 0)}">
    <host{host_interval}>
        <status state="up"/>
        <address addr="192.168.1.77" addrtype="ipv4"/>
        <hostnames>
            <hostname name="unknown-host"/>
        </hostnames>
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

    result = run_traditional_detection_pipeline(
        nmap_file=str(nmap_file),
        windows_events_file=config.windows_events_file,
        firewall_file=config.firewall_file,
        web_log_file=config.web_log_file,
        whitelist_file=config.whitelist_file,
        critical_ports_file=config.critical_ports_file,
    )

    assert len(result.nmap_findings) == 1

    finding = result.nmap_findings[0]

    assert finding.title == (
        "Unknown host with exposed critical service"
    )
    assert finding.ip == "192.168.1.77"
    assert finding.port == 3389

    assert finding.observation_start == expected_start
    assert finding.observation_end == expected_end
    assert finding.observation_scope == expected_scope

    # Scan observations are not exact event timestamps.
    assert finding.first_seen is None
    assert finding.last_seen is None
