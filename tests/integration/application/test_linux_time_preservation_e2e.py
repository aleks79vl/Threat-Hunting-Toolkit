import json
import pytest

from dataclasses import replace

from src.config.app_config import default_app_config
from src.detection.linux.linux_pipeline import (
    run_linux_detection_pipeline,
)
from src.main import main


def test_linux_time_preserved_through_application_and_json_report(
    tmp_path,
    monkeypatch,
):
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

    json_output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    config = replace(
        default_app_config(),
        linux_auth_file=str(auth_file),
        linux_syslog_file=str(syslog_file),
        linux_auth_source_year=2026,
        linux_auth_source_timezone="Asia/Jerusalem",
        linux_syslog_source_year=2026,
        linux_syslog_source_timezone="America/New_York",
        json_output_file=str(json_output),
        html_output_file=str(html_output),
    )

    observed = {}

    def recording_linux_pipeline(**kwargs):
        result = run_linux_detection_pipeline(**kwargs)
        observed["result"] = result
        return result

    # Observe the real Linux pipeline without replacing
    # its parsing or detection logic.
    monkeypatch.setattr(
        "src.main.run_linux_detection_pipeline",
        recording_linux_pipeline,
    )

    main(config)

    assert json_output.is_file()
    assert html_output.is_file()

    linux_events = observed["result"].events

    assert len(linux_events) == 2

    auth_event, syslog_event = linux_events

    # Raw timestamps must remain unchanged.
    assert auth_event.timestamp == "Jul  7 10:00:01"
    assert syslog_event.timestamp == "Jul  7 10:00:01"

    # Independent source timezone conversion.
    auth_utc = "2026-07-07T07:00:01+00:00"
    syslog_utc = "2026-07-07T14:00:01+00:00"

    assert auth_event.timestamp_utc == auth_utc
    assert syslog_event.timestamp_utc == syslog_utc

    # Real Linux detection must retain event time.
    auth_findings = [
        finding
        for finding in observed["result"].findings
        if finding.hostname == "auth-host"
        and finding.first_seen == auth_utc
        and finding.last_seen == auth_utc
    ]

    assert auth_findings

    # Cross-domain processing and JSON serialization
    # must preserve the same temporal evidence.
    report = json.loads(
        json_output.read_text(encoding="utf-8")
    )

    exported_auth_findings = [
        finding
        for finding in report["findings"]
        if finding.get("hostname") == "auth-host"
        and finding.get("first_seen") == auth_utc
        and finding.get("last_seen") == auth_utc
    ]

    assert exported_auth_findings

    # Timeline must retain the normalized UTC time.
    exported_titles = {
        finding["title"]
        for finding in exported_auth_findings
    }

    assert any(
        entry["event"] in exported_titles
        and entry["time"] == auth_utc
        for entry in report["timeline"]
    )


def test_linux_application_does_not_invent_unknown_event_time(
    tmp_path,
    monkeypatch,
):
    auth_file = tmp_path / "auth.log"

    auth_file.write_text(
        "Jul  7 10:00:01 auth-host sshd[1425]: "
        "Failed password for admin from "
        "203.0.113.50 port 49822 ssh2\n",
        encoding="utf-8",
    )

    json_output = tmp_path / "report.json"

    config = replace(
        default_app_config(),
        linux_auth_file=str(auth_file),
        linux_syslog_file=str(tmp_path / "missing-syslog"),
        linux_auth_source_year=None,
        linux_auth_source_timezone=None,
        json_output_file=str(json_output),
        html_output_file=str(tmp_path / "report.html"),
    )

    observed = {}

    def recording_linux_pipeline(**kwargs):
        result = run_linux_detection_pipeline(**kwargs)
        observed["result"] = result
        return result

    monkeypatch.setattr(
        "src.main.run_linux_detection_pipeline",
        recording_linux_pipeline,
    )

    main(config)

    events = observed["result"].events

    assert len(events) == 1
    assert events[0].timestamp == "Jul  7 10:00:01"
    assert events[0].timestamp_utc is None

    report = json.loads(
        json_output.read_text(encoding="utf-8")
    )

    auth_findings = [
        finding
        for finding in report["findings"]
        if finding.get("hostname") == "auth-host"
        and finding.get("source") == "Linux Log Detection"
    ]

    assert auth_findings

    assert all(
        finding.get("first_seen") is None
        and finding.get("last_seen") is None
        for finding in auth_findings
    )


def test_linux_syslog_time_range_reaches_json_and_html(
    tmp_path,
):
    syslog_file = tmp_path / "syslog"

    # Intentionally out of chronological order.
    syslog_file.write_text(
        "Jul  7 10:05:01 syslog-e2e-host systemd[1]: "
        "Stopped alpha.service.\n"
        "Jul  7 10:00:01 syslog-e2e-host systemd[1]: "
        "Restarted beta.service.\n"
        "Jul  7 10:03:01 syslog-e2e-host systemd[1]: "
        "Stopped gamma.service.\n",
        encoding="utf-8",
    )

    json_output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    config = replace(
        default_app_config(),
        linux_auth_file=str(tmp_path / "missing-auth.log"),
        linux_syslog_file=str(syslog_file),
        linux_syslog_source_year=2026,
        linux_syslog_source_timezone="America/New_York",
        json_output_file=str(json_output),
        html_output_file=str(html_output),
    )

    # Run the real application without mocking the pipeline.
    main(config)

    assert json_output.is_file()
    assert html_output.is_file()

    report = json.loads(
        json_output.read_text(encoding="utf-8")
    )

    expected_title = (
        "Repeated Linux Service Manipulation Detected"
    )
    expected_first = "2026-07-07T14:00:01+00:00"
    expected_last = "2026-07-07T14:05:01+00:00"

    # The three events must produce one repeated finding.
    matching_findings = [
        finding
        for finding in report["findings"]
        if finding.get("title") == expected_title
        and finding.get("hostname") == "syslog-e2e-host"
        and finding.get("source") == "Linux Log Detection"
    ]

    assert len(matching_findings) == 1

    finding = matching_findings[0]

    # Check actual min/max, not file order.
    assert finding["first_seen"] == expected_first
    assert finding["last_seen"] == expected_last

    # Timeline must contain the earliest UTC timestamp.
    matching_timeline = [
        entry
        for entry in report["timeline"]
        if entry.get("event") == expected_title
        and entry.get("source") == "Linux Log Detection"
        and entry.get("time") == expected_first
    ]

    assert len(matching_timeline) == 1

    # HTML must display the detection and its timeline time.
    html_report = html_output.read_text(
        encoding="utf-8"
    )

    assert "Threat Timeline" in html_report
    assert expected_title in html_report
    assert expected_first in html_report


@pytest.mark.parametrize(
    ("source_year", "source_timezone"),
    [
        (None, None),
        (2026, None),
        (None, "America/New_York"),
    ],
)
def test_linux_syslog_incomplete_time_context_does_not_invent_utc(
    tmp_path,
    source_year,
    source_timezone,
):
    syslog_file = tmp_path / "syslog"

    syslog_file.write_text(
        "Jul  7 10:00:01 syslog-unknown-time systemd[1]: "
        "Stopped alpha.service.\n",
        encoding="utf-8",
    )

    json_output = tmp_path / "report.json"

    config = replace(
        default_app_config(),
        linux_auth_file=str(tmp_path / "missing-auth.log"),
        linux_syslog_file=str(syslog_file),
        linux_syslog_source_year=source_year,
        linux_syslog_source_timezone=source_timezone,
        json_output_file=str(json_output),
        html_output_file=str(tmp_path / "report.html"),
    )

    main(config)

    report = json.loads(
        json_output.read_text(encoding="utf-8")
    )

    title = "Linux Service Manipulation Detected"

    matching_findings = [
        finding
        for finding in report["findings"]
        if finding.get("title") == title
        and finding.get("hostname") == "syslog-unknown-time"
        and finding.get("source") == "Linux Log Detection"
    ]

    assert len(matching_findings) == 1

    finding = matching_findings[0]

    assert finding["first_seen"] is None
    assert finding["last_seen"] is None

    matching_timeline = [
        entry
        for entry in report["timeline"]
        if entry.get("event") == title
        and entry.get("source") == "Linux Log Detection"
    ]

    assert len(matching_timeline) == 1
    assert matching_timeline[0]["time"] is None
