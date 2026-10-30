from src.detection.linux.linux_pipeline import (
    run_linux_detection_pipeline,
)


def test_linux_pipeline_returns_empty_result_when_logs_are_missing(
    tmp_path,
):
    result = run_linux_detection_pipeline(
        linux_auth_file=str(tmp_path / "missing-auth.log"),
        linux_syslog_file=str(tmp_path / "missing-syslog.log"),
    )

    assert result.events == []
    assert result.findings == []
    assert result.statistics == {
        "linux_statistics": {
            "total_events": 0,
            "actions": {},
            "statuses": {},
            "users": {},
            "source_ips": {},
        },
        "linux_execution_statistics": {
            "total_executions": 0,
            "suspicious_executions": 0,
            "unique_executables": 0,
            "top_executables": [],
            "top_users": [],
            "mitre_statistics": [],
        },
    }


def test_linux_pipeline_parses_fixture_logs():
    result = run_linux_detection_pipeline(
        linux_auth_file="tests/fixtures/linux/auth_sample.log",
        linux_syslog_file="tests/fixtures/linux/syslog_sample.log",
    )

    assert result.events
    assert (
        result.statistics["linux_statistics"]["total_events"]
        == len(result.events)
    )


def test_linux_pipeline_uses_independent_source_time_contexts(tmp_path):
    auth_file = tmp_path / "auth.log"
    syslog_file = tmp_path / "syslog"

    auth_file.write_text(
        "Jul  7 10:00:01 auth-host sshd[1425]: "
        "Failed password for admin from "
        "203.0.113.50 port 49822 ssh2\n",
        encoding="utf-8",
    )

    syslog_file.write_text(
        "Jul  7 10:00:01 syslog-host CRON[2301]: "
        "(root) CMD (/usr/bin/id)\n",
        encoding="utf-8",
    )

    result = run_linux_detection_pipeline(
        linux_auth_file=str(auth_file),
        linux_syslog_file=str(syslog_file),
        linux_auth_source_year=2026,
        linux_auth_source_timezone="Asia/Jerusalem",
        linux_syslog_source_year=2026,
        linux_syslog_source_timezone="America/New_York",
    )

    assert len(result.events) == 2

    auth_event, syslog_event = result.events

    # Original timestamps must remain unchanged.
    assert auth_event.timestamp == "Jul  7 10:00:01"
    assert syslog_event.timestamp == "Jul  7 10:00:01"

    # Each log uses its own source timezone.
    assert auth_event.timestamp_utc == (
        "2026-07-07T07:00:01+00:00"
    )

    assert syslog_event.timestamp_utc == (
        "2026-07-07T14:00:01+00:00"
    )


def test_linux_pipeline_does_not_invent_unknown_event_time(tmp_path):
    auth_file = tmp_path / "auth.log"

    auth_file.write_text(
        "Jul  7 10:00:01 auth-host sshd[1425]: "
        "Failed password for admin from "
        "203.0.113.50 port 49822 ssh2\n",
        encoding="utf-8",
    )

    result = run_linux_detection_pipeline(
        linux_auth_file=str(auth_file),
        linux_syslog_file=str(tmp_path / "missing-syslog"),
    )

    assert len(result.events) == 1

    event = result.events[0]

    assert event.timestamp == "Jul  7 10:00:01"
    assert event.timestamp_utc is None
