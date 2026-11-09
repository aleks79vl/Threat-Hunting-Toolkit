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


def test_main_warns_about_rejected_waf_records(
    tmp_path,
    capsys,
):
    waf_log = tmp_path / "waf_mixed.jsonl"

    waf_log.write_text(
        "\n".join([
            '{"timestamp":"2026-10-21T10:00:00Z",'
            '"client_ip":"192.0.2.10",'
            '"method":"GET",'
            '"path":"/first",'
            '"status_code":200,'
            '"host":"api.example.com",'
            '"action":"allow"}',

            '["secret=do_not_echo"]',

            '{"timestamp":"2026-10-21T10:00:02Z",'
            '"client_ip":"192.0.2.20",'
            '"method":"GET",'
            '"path":"/second",'
            '"status_code":403,'
            '"host":"api.example.com",'
            '"action":"block"}',
        ]) + "\n",
        encoding="utf-8",
    )

    nginx_log = tmp_path / "nginx_clean.jsonl"

    nginx_log.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.40",'
        '"request_method":"GET",'
        '"request_uri":"/health",'
        '"status":200}\n',
        encoding="utf-8",
    )

    config = replace(
        default_app_config(),
        waf_cdn_log_file=str(waf_log),
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

    assert "WARNING: WAF input incomplete" in output

    assert (
        "waf_cdn read=3 accepted=2 rejected=1"
        in output
    )

    assert (
        "WAF rejection reasons (retained): "
        "invalid_root_type"
    ) in output

    assert "secret=do_not_echo" not in output

    assert (
        "WARNING: Firewall input incomplete"
        not in output
    )

    assert (
        "WARNING: Nginx input incomplete"
        not in output
    )

    assert (
        tmp_path / "threat_report.json"
    ).is_file()

    assert (
        tmp_path / "threat_report.html"
    ).is_file()


@pytest.mark.parametrize(
    (
        "invalid_source",
        "expected_warning",
        "unexpected_warning",
        "source_name",
        "reason_label",
    ),
    [
        (
            "access",
            "WARNING: Apache Access input incomplete",
            "WARNING: Apache VHost input incomplete",
            "apache_access",
            "Apache Access",
        ),
        (
            "vhost",
            "WARNING: Apache VHost input incomplete",
            "WARNING: Apache Access input incomplete",
            "apache_vhost",
            "Apache VHost",
        ),
    ],
    ids=["apache_access", "apache_vhost"],
)
def test_main_warns_about_rejected_apache_records(
    tmp_path,
    capsys,
    invalid_source,
    expected_warning,
    unexpected_warning,
    source_name,
    reason_label,
):
    access_log = tmp_path / "apache_mixed.log"
    vhost_log = tmp_path / "apache_vhost_mixed.log"
    nginx_log = tmp_path / "nginx_clean.jsonl"

    first_record = (
        '192.0.2.10 - - '
        '[21/Oct/2026:10:00:00 +0000] '
        '"GET /first HTTP/1.1" 200 1024 '
        '"-" "pytest"'
    )

    last_record = (
        '192.0.2.20 - - '
        '[21/Oct/2026:10:00:01 +0000] '
        '"GET /last HTTP/1.1" 204 - '
        '"-" "pytest"'
    )

    malformed = (
        "invalid apache record secret=do_not_echo"
    )

    access_records = [first_record]
    vhost_records = [
        f"api.example.com {first_record}"
    ]

    if invalid_source == "access":
        access_records.extend([
            malformed,
            last_record,
        ])
    else:
        vhost_records.extend([
            malformed,
            f"api.example.com {last_record}",
        ])

    access_log.write_text(
        "\n".join(access_records) + "\n",
        encoding="utf-8",
    )

    vhost_log.write_text(
        "\n".join(vhost_records) + "\n",
        encoding="utf-8",
    )

    nginx_log.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.40",'
        '"request_method":"GET",'
        '"request_uri":"/health",'
        '"status":200}\n',
        encoding="utf-8",
    )

    waf_log = tmp_path / "waf_clean.jsonl"

    waf_log.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.50",'
        '"method":"GET",'
        '"path":"/health",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"provider":"cloudflare",'
        '"action":"allow"}\n',
        encoding="utf-8",
    )


    config = replace(
        default_app_config(),
        web_log_file=str(access_log),
        apache_vhost_log_file=str(vhost_log),
        nginx_access_log_file=str(nginx_log),
        waf_cdn_log_file=str(waf_log),
        json_output_file=str(
            tmp_path / "threat_report.json"
        ),
        html_output_file=str(
            tmp_path / "threat_report.html"
        ),
    )

    main(config)

    output = capsys.readouterr().out

    assert expected_warning in output

    assert (
        f"{source_name} read=3 accepted=2 rejected=1"
        in output
    )

    assert (
        f"{reason_label} rejection reasons (retained): "
        "invalid_log_format"
    ) in output

    assert unexpected_warning not in output

    assert "secret=do_not_echo" not in output

    assert (
        "WARNING: Firewall input incomplete"
        not in output
    )
    assert (
        "WARNING: Nginx input incomplete"
        not in output
    )
    assert (
        "WARNING: WAF input incomplete"
        not in output
    )

    assert (
        tmp_path / "threat_report.json"
    ).is_file()

    assert (
        tmp_path / "threat_report.html"
    ).is_file()
