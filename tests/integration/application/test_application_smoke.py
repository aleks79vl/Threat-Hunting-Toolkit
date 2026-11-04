import json
import pytest

from types import SimpleNamespace
from dataclasses import replace

from src.main import main
from src.config.app_config import default_app_config


def test_application_generates_json_and_html_reports(tmp_path):
    json_output_file = tmp_path / "threat_report.json"
    html_output_file = tmp_path / "threat_report.html"

    config = replace(
        default_app_config(),
        json_output_file=str(json_output_file),
        html_output_file=str(html_output_file),
    )

    main(config)

    assert json_output_file.is_file()
    assert html_output_file.is_file()

    with json_output_file.open(encoding="utf-8") as report_file:
        json_report = json.load(report_file)

    assert isinstance(json_report, dict)
    assert json_report

    html_report = html_output_file.read_text(encoding="utf-8")

    assert json_report
    assert "Threat Hunting Report" in html_report
    assert "network_statistics" in json_report
    assert "linux_statistics" in json_report
    assert "web_infrastructure_statistics" in json_report


def test_main_forwards_windows_source_timezone(
    monkeypatch,
):
    config = replace(
        default_app_config(),
        windows_source_timezone="Asia/Jerusalem",
    )

    captured_arguments = {}

    class StopAfterTraditionalPipeline(Exception):
        pass

    def fake_traditional_pipeline(**kwargs):
        captured_arguments.update(kwargs)
        raise StopAfterTraditionalPipeline()

    monkeypatch.setattr(
        "src.main.run_traditional_detection_pipeline",
        fake_traditional_pipeline,
    )

    with pytest.raises(StopAfterTraditionalPipeline):
        main(config)

    assert captured_arguments["windows_source_timezone"] == (
        "Asia/Jerusalem"
    )


def test_main_forwards_firewall_source_timezone(
    monkeypatch,
):
    config = replace(
        default_app_config(),
        firewall_source_timezone="Asia/Jerusalem",
    )

    captured_arguments = {}

    class StopAfterTraditionalPipeline(Exception):
        pass

    def fake_traditional_pipeline(**kwargs):
        captured_arguments.update(kwargs)
        raise StopAfterTraditionalPipeline()

    monkeypatch.setattr(
        "src.main.run_traditional_detection_pipeline",
        fake_traditional_pipeline,
    )

    with pytest.raises(StopAfterTraditionalPipeline):
        main(config)

    assert captured_arguments["firewall_source_timezone"] == (
        "Asia/Jerusalem"
    )


def test_main_forwards_independent_linux_time_contexts(
    monkeypatch,
):
    config = replace(
        default_app_config(),
        linux_auth_source_year=2026,
        linux_auth_source_timezone="Asia/Jerusalem",
        linux_syslog_source_year=2025,
        linux_syslog_source_timezone="America/New_York",
    )

    # Isolate the Linux pipeline invocation from
    # unrelated application pipelines.
    monkeypatch.setattr(
        "src.main.run_traditional_detection_pipeline",
        lambda **kwargs: SimpleNamespace(
            nmap_findings=[],
            windows_findings=[],
            firewall_events=[],
            firewall_findings=[],
            web_findings=[],
        ),
    )

    monkeypatch.setattr(
        "src.main.run_web_infrastructure_application_pipeline",
        lambda **kwargs: SimpleNamespace(findings=[]),
    )

    monkeypatch.setattr(
        "src.main.run_network_detection_pipeline",
        lambda **kwargs: SimpleNamespace(
            events=[],
            findings=[],
        ),
    )

    captured_arguments = {}

    class StopAfterLinuxPipeline(Exception):
        pass

    def fake_linux_pipeline(**kwargs):
        captured_arguments.update(kwargs)
        raise StopAfterLinuxPipeline()

    monkeypatch.setattr(
        "src.main.run_linux_detection_pipeline",
        fake_linux_pipeline,
    )

    with pytest.raises(StopAfterLinuxPipeline):
        main(config)

    expected_time_context = {
        "linux_auth_source_year": 2026,
        "linux_auth_source_timezone": "Asia/Jerusalem",
        "linux_syslog_source_year": 2025,
        "linux_syslog_source_timezone": "America/New_York",
    }

    actual_time_context = {
        key: captured_arguments.get(key)
        for key in expected_time_context
    }

    assert actual_time_context == expected_time_context

    assert captured_arguments["linux_auth_file"] == (
        config.linux_auth_file
    )
    assert captured_arguments["linux_syslog_file"] == (
        config.linux_syslog_file
    )


def test_main_warns_about_rejected_firewall_records(
    tmp_path,
    capsys,
):
    firewall_log = tmp_path / "firewall_mixed.log"

    firewall_log.write_text(
        "\n".join([
            "2026-07-16 13:00:00 DENY TCP "
            "203.0.113.15 192.168.1.77 22",

            "2026-07-16 13:00:01 DENY TCP "
            "password=do_not_echo",

            "2026-07-16 13:00:02 DENY TCP "
            "203.0.113.16 192.168.1.77 3389",
        ]) + "\n",
        encoding="utf-8",
    )

    config = replace(
        default_app_config(),
        firewall_file=str(firewall_log),
        json_output_file=str(
            tmp_path / "threat_report.json"
        ),
        html_output_file=str(
            tmp_path / "threat_report.html"
        ),
    )

    main(config)

    output = capsys.readouterr().out

    assert "WARNING: Firewall input incomplete" in output

    assert "read=3" in output
    assert "accepted=2" in output
    assert "rejected=1" in output

    assert "too_few_fields" in output

    assert "password=do_not_echo" not in output

    assert (
        tmp_path / "threat_report.json"
    ).is_file()

    assert (
        tmp_path / "threat_report.html"
    ).is_file()


def test_main_warns_about_rejected_nginx_records(
    tmp_path,
    capsys,
):
    nginx_log = tmp_path / "nginx_mixed.jsonl"

    nginx_log.write_text(
        "\n".join([
            '{"time":"2026-10-21T10:00:00Z",'
            '"remote_addr":"192.0.2.10",'
            '"request_method":"GET",'
            '"request_uri":"/first",'
            '"status":200}',

            '["secret=do_not_echo"]',

            '{"time":"2026-10-21T10:00:02Z",'
            '"remote_addr":"192.0.2.20",'
            '"request_method":"GET",'
            '"request_uri":"/second",'
            '"status":200}',
        ]) + "\n",
        encoding="utf-8",
    )

    config = replace(
        default_app_config(),
        nginx_access_log_file=str(nginx_log),
        json_output_file=str(
            tmp_path / "threat_report.json"
        ),
        html_output_file=str(
            tmp_path / "threat_report.html"
        ),
    )

    main(config)

    output = capsys.readouterr().out

    assert "WARNING: Nginx input incomplete" in output
    assert "nginx read=3 accepted=2 rejected=1" in output
    assert "invalid_root_type" in output
    assert "secret=do_not_echo" not in output
    assert "WARNING: Firewall input incomplete" not in output
    assert (
        tmp_path / "threat_report.json"
    ).is_file()
    assert (
        tmp_path / "threat_report.html"
    ).is_file()
