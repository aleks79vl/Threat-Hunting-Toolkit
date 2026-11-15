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


def test_main_reports_unavailable_nginx_source(
    tmp_path,
    capsys,
):
    missing_nginx_log = (
        tmp_path / "nginx_secret=do_not_echo.jsonl"
    )

    assert not missing_nginx_log.exists()

    json_report = tmp_path / "source_failure_report.json"
    html_report = tmp_path / "source_failure_report.html"

    config = replace(
        default_app_config(),
        nginx_access_log_file=str(missing_nginx_log),
        json_output_file=str(json_report),
        html_output_file=str(html_report),
    )

    main(config)

    output = capsys.readouterr().out

    assert "WARNING: Web source unavailable" in output

    assert (
        "source=nginx reason=file_not_found"
        in output
    )

    assert str(missing_nginx_log) not in output
    assert "secret=do_not_echo" not in output

    assert json_report.is_file()
    assert html_report.is_file()

def test_main_reports_multiple_unavailable_web_sources(
    tmp_path,
    capsys,
):
    missing_vhost = (
        tmp_path / "vhost_secret=do_not_echo.log"
    )

    missing_nginx = (
        tmp_path / "nginx_secret=do_not_echo.jsonl"
    )

    assert not missing_vhost.exists()
    assert not missing_nginx.exists()

    json_report = tmp_path / "multiple_failures.json"
    html_report = tmp_path / "multiple_failures.html"

    config = replace(
        default_app_config(),
        apache_vhost_log_file=str(missing_vhost),
        nginx_access_log_file=str(missing_nginx),
        json_output_file=str(json_report),
        html_output_file=str(html_report),
    )

    main(config)

    output = capsys.readouterr().out

    assert "WARNING: Web source unavailable" in output

    assert output.count(
        "source=apache_vhost reason=file_not_found"
    ) == 1

    assert output.count(
        "source=nginx reason=file_not_found"
    ) == 1

    assert str(missing_vhost) not in output
    assert str(missing_nginx) not in output
    assert "secret=do_not_echo" not in output

    assert json_report.is_file()
    assert html_report.is_file()


def test_main_reports_failures_from_both_application_pipelines(
    tmp_path,
    monkeypatch,
    capsys,
):
    import src.application.traditional_detection_pipeline as traditional

    def failed_windows(_path):
        raise FileNotFoundError(
            "windows_secret=do_not_echo "
            "/private/internal/windows.json"
        )

    monkeypatch.setattr(
        traditional,
        "parse_windows_events",
        failed_windows,
    )

    missing_waf = (
        tmp_path / "waf_secret=do_not_echo.jsonl"
    )

    assert not missing_waf.exists()

    json_report = tmp_path / "combined_failures.json"
    html_report = tmp_path / "combined_failures.html"

    config = replace(
        default_app_config(),
        waf_cdn_log_file=str(missing_waf),
        json_output_file=str(json_report),
        html_output_file=str(html_report),
    )

    main(config)

    output = capsys.readouterr().out

    assert output.count(
        "source=windows_events reason=file_not_found"
    ) == 1

    assert output.count(
        "source=waf_cdn reason=file_not_found"
    ) == 1

    assert "windows_secret=do_not_echo" not in output
    assert "waf_secret=do_not_echo" not in output
    assert "/private/internal/windows.json" not in output
    assert str(missing_waf) not in output

    assert json_report.is_file()
    assert html_report.is_file()

    for report_file in (json_report, html_report):
        report_content = report_file.read_text(
            encoding="utf-8"
        )

        assert (
            "windows_secret=do_not_echo"
            not in report_content
        )

        assert (
            "waf_secret=do_not_echo"
            not in report_content
        )

    import json

    report = json.loads(
        json_report.read_text(encoding="utf-8")
    )

    integrity = report["input_integrity"]

    assert integrity["status"] == "incomplete"

    failures = integrity["source_failures"]

    assert {
        "source": "windows_events",
        "reason": "file_not_found",
    } in failures

    assert {
        "source": "waf_cdn",
        "reason": "file_not_found",
    } in failures

    for failure in failures:
        assert "path" not in failure
        assert "exception" not in failure
        assert "message" not in failure
        assert "raw_event" not in failure


    html_content = html_report.read_text(
        encoding="utf-8",
    )

    assert "Input Integrity" in html_content
    assert "Incomplete" in html_content

    assert "windows_events" in html_content
    assert "waf_cdn" in html_content
    assert "file_not_found" in html_content

    assert "windows_secret=do_not_echo" not in html_content
    assert "waf_secret=do_not_echo" not in html_content
    assert "/private/internal/windows.json" not in html_content


def test_main_exports_partial_firewall_input_integrity(
    tmp_path,
):
    import json
    from pathlib import Path

    config = default_app_config()

    original_data = Path(
        config.firewall_file
    ).read_text(encoding="utf-8")

    assert original_data.strip()

    malformed_marker = (
        "RAW_PRIVATE_INCOMPLETE_FIREWALL_RECORD"
    )

    mixed_firewall = tmp_path / "mixed_firewall.log"

    mixed_firewall.write_text(
        original_data.rstrip("\n")
        + "\n"
        + malformed_marker
        + "\n",
        encoding="utf-8",
    )

    json_report = tmp_path / "partial_firewall.json"
    html_report = tmp_path / "partial_firewall.html"

    test_config = replace(
        config,
        firewall_file=str(mixed_firewall),
        json_output_file=str(json_report),
        html_output_file=str(html_report),
    )

    main(test_config)

    report = json.loads(
        json_report.read_text(encoding="utf-8")
    )

    integrity = report["input_integrity"]

    assert integrity["status"] == "incomplete"

    firewall_records = [
        item
        for item in integrity["parser_diagnostics"]
        if item["source"] == "firewall"
    ]

    assert len(firewall_records) == 1

    firewall = firewall_records[0]

    assert firewall["accepted"] >= 1
    assert firewall["rejected"] >= 1

    assert firewall["read"] == (
        firewall["accepted"] + firewall["rejected"]
    )

    assert firewall["reason_codes"]
    assert firewall["issues_dropped"] >= 0

    assert malformed_marker not in json_report.read_text(
        encoding="utf-8"
    )

    assert malformed_marker not in html_report.read_text(
        encoding="utf-8"
    )

    html_content = html_report.read_text(
        encoding="utf-8",
    )

    assert "Input Integrity" in html_content
    assert "Incomplete" in html_content
    assert "Parser Diagnostics" in html_content

    expected_firewall_row = (
        "<tr>"
        "<td>firewall</td>"
        f"<td>{firewall['read']}</td>"
        f"<td>{firewall['accepted']}</td>"
        f"<td>{firewall['rejected']}</td>"
        f"<td>{', '.join(firewall['reason_codes'])}</td>"
        f"<td>{firewall['issues_dropped']}</td>"
        f"<td>{firewall['quarantine']['retained']}</td>"
        f"<td>{firewall['quarantine']['dropped']}</td>"
        "</tr>"
    )

    assert expected_firewall_row in html_content

    if not integrity["source_failures"]:
        assert "Unavailable Sources" not in html_content

    assert malformed_marker not in html_content



def test_main_preserves_firewall_rejection_counts_when_issue_limit_exceeded(
    tmp_path,
    monkeypatch,
):
    import importlib
    import json
    from pathlib import Path

    main_module = importlib.import_module("src.main")
    original_build = main_module.build_input_integrity

    captured_diagnostics = []

    def capture_input_integrity(
        *,
        source_failures,
        parser_diagnostics,
    ):
        captured_diagnostics.extend(parser_diagnostics)

        return original_build(
            source_failures=source_failures,
            parser_diagnostics=parser_diagnostics,
        )

    monkeypatch.setattr(
        main_module,
        "build_input_integrity",
        capture_input_integrity,
    )

    config = default_app_config()

    original_data = Path(
        config.firewall_file
    ).read_text(encoding="utf-8")

    assert original_data.strip()

    malformed_marker = (
        "PRIVATE_FIREWALL_RECORD_DO_NOT_EXPORT"
    )

    malformed_count = 105

    firewall_file = tmp_path / "firewall_issue_limit.log"

    firewall_file.write_text(
        original_data.rstrip("\n")
        + "\n"
        + (malformed_marker + "\n") * malformed_count,
        encoding="utf-8",
    )

    json_report = tmp_path / "firewall_limit.json"
    html_report = tmp_path / "firewall_limit.html"

    test_config = replace(
        config,
        firewall_file=str(firewall_file),
        json_output_file=str(json_report),
        html_output_file=str(html_report),
    )

    main(test_config)

    report = json.loads(
        json_report.read_text(encoding="utf-8")
    )

    integrity = report["input_integrity"]

    assert integrity["status"] == "incomplete"

    firewall_records = [
        item
        for item in integrity["parser_diagnostics"]
        if item["source"] == "firewall"
    ]

    assert len(firewall_records) == 1

    firewall = firewall_records[0]

    assert firewall["rejected"] >= malformed_count
    assert firewall["accepted"] >= 1

    assert firewall["read"] == (
        firewall["accepted"] + firewall["rejected"]
    )

    assert firewall["issues_dropped"] == (
        firewall["rejected"] - 100
    )

    assert firewall["issues_dropped"] >= 5


    runtime_firewall = [
        diagnostics
        for diagnostics in captured_diagnostics
        if diagnostics.source == "firewall"
    ]

    assert len(runtime_firewall) == 1

    diagnostics = runtime_firewall[0]

    assert diagnostics.read == firewall["read"]
    assert diagnostics.accepted == firewall["accepted"]
    assert diagnostics.rejected == firewall["rejected"]

    assert (
        diagnostics.issues_dropped
        == firewall["issues_dropped"]
    )


    quarantine = diagnostics.quarantine

    assert quarantine is not None

    assert quarantine.max_records == 100
    assert quarantine.max_record_bytes == 4096

    assert 0 < len(quarantine.records) <= 100
    assert quarantine.dropped >= 5

    assert (
        len(quarantine.records) + quarantine.dropped
        == diagnostics.rejected
    )

    assert any(
        record.raw_record == malformed_marker
        for record in quarantine.records
    )

    assert all(
        record.source == "firewall"
        for record in quarantine.records
    )

    assert malformed_marker not in repr(quarantine)
    assert malformed_marker not in repr(diagnostics)


    assert set(firewall) == {
        "source",
        "read",
        "accepted",
        "rejected",
        "reason_codes",
        "issues_dropped",
        "quarantine",
    }

    quarantine_metrics = firewall["quarantine"]

    assert set(quarantine_metrics) == {
        "retained",
        "dropped",
    }

    assert quarantine_metrics == {
        "retained": len(quarantine.records),
        "dropped": quarantine.dropped,
    }

    assert quarantine_metrics["retained"] == 100
    assert quarantine_metrics["dropped"] == 5

    assert (
        quarantine_metrics["retained"]
        + quarantine_metrics["dropped"]
        == firewall["rejected"]
    )

    assert firewall["issues_dropped"] == 5
    assert diagnostics.issues_dropped == 5
    assert quarantine.dropped == 5

    assert "raw_record" not in firewall
    assert "records" not in quarantine_metrics

    json_content = json_report.read_text(
        encoding="utf-8"
    )

    html_content = html_report.read_text(
        encoding="utf-8"
    )

    assert malformed_marker not in json_content
    assert malformed_marker not in html_content

    assert "PRIVATE_FIREWALL_RECORD" not in json_content
    assert "PRIVATE_FIREWALL_RECORD" not in html_content

    assert "Input Integrity" in html_content
    assert "Parser Diagnostics" in html_content

    assert (
        f"<td>{firewall['issues_dropped']}</td>"
        in html_content
    )

    assert (
        "Reason codes describe retained diagnostic issues only."
        in html_content
    )

    if not integrity["source_failures"]:
        assert "Unavailable Sources" not in html_content


def test_main_initializes_independent_quarantine_per_source(
    tmp_path,
    monkeypatch,
):
    import importlib

    from src.parsers.quarantine_buffer import QuarantineBuffer

    main_module = importlib.import_module("src.main")

    original_build = main_module.build_input_integrity
    captured_diagnostics = []

    def capture_input_integrity(
        *,
        source_failures,
        parser_diagnostics,
    ):
        captured_diagnostics.extend(parser_diagnostics)

        return original_build(
            source_failures=source_failures,
            parser_diagnostics=parser_diagnostics,
        )

    monkeypatch.setattr(
        main_module,
        "build_input_integrity",
        capture_input_integrity,
    )

    config = replace(
        default_app_config(),
        json_output_file=str(
            tmp_path / "runtime_quarantine.json"
        ),
        html_output_file=str(
            tmp_path / "runtime_quarantine.html"
        ),
    )

    main(config)

    assert len(captured_diagnostics) == 5

    assert {
        diagnostics.source
        for diagnostics in captured_diagnostics
    } == {
        "firewall",
        "nginx",
        "waf_cdn",
        "apache_access",
        "apache_vhost",
    }

    quarantines = [
        diagnostics.quarantine
        for diagnostics in captured_diagnostics
    ]

    assert all(
        isinstance(quarantine, QuarantineBuffer)
        for quarantine in quarantines
    )

    assert len({
        id(quarantine)
        for quarantine in quarantines
    }) == 5

    assert all(
        quarantine.max_records == 100
        and quarantine.max_record_bytes == 4096
        for quarantine in quarantines
    )


def test_main_quarantines_firewall_raw_record_without_exporting_it(
    tmp_path,
    monkeypatch,
):
    import importlib
    import json

    main_module = importlib.import_module("src.main")

    original_build = main_module.build_input_integrity
    captured_diagnostics = []

    def capture_input_integrity(
        *,
        source_failures,
        parser_diagnostics,
    ):
        captured_diagnostics.extend(parser_diagnostics)

        return original_build(
            source_failures=source_failures,
            parser_diagnostics=parser_diagnostics,
        )

    monkeypatch.setattr(
        main_module,
        "build_input_integrity",
        capture_input_integrity,
    )

    malformed_record = (
        "PRIVATE_RUNTIME_QUARANTINE_TOKEN_password=do_not_export"
    )

    firewall_file = tmp_path / "runtime_firewall.log"

    firewall_file.write_text(
        "\n".join([
            "2026-06-27 09:00:15 ALLOW TCP "
            "192.168.1.10 192.168.1.77 3389",
            malformed_record,
            "2026-06-27 09:00:17 DENY UDP "
            "192.168.1.30 192.168.1.80 53",
        ]) + "\n",
        encoding="utf-8",
    )

    json_report = tmp_path / "quarantine_e2e.json"
    html_report = tmp_path / "quarantine_e2e.html"

    config = replace(
        default_app_config(),
        firewall_file=str(firewall_file),
        json_output_file=str(json_report),
        html_output_file=str(html_report),
    )

    main(config)

    firewall_diagnostics = [
        diagnostics
        for diagnostics in captured_diagnostics
        if diagnostics.source == "firewall"
    ]

    assert len(firewall_diagnostics) == 1

    diagnostics = firewall_diagnostics[0]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "too_few_fields"),
    ]

    quarantine = diagnostics.quarantine

    assert quarantine is not None
    assert len(quarantine.records) == 1
    assert quarantine.dropped == 0

    retained = quarantine.records[0]

    assert retained.source == "firewall"
    assert retained.line_number == 2
    assert retained.reason_code == "too_few_fields"
    assert retained.raw_record == malformed_record

    report = json.loads(
        json_report.read_text(encoding="utf-8")
    )

    integrity = report["input_integrity"]

    assert integrity["status"] == "incomplete"

    firewall_records = [
        item
        for item in integrity["parser_diagnostics"]
        if item["source"] == "firewall"
    ]

    assert len(firewall_records) == 1

    assert firewall_records[0]["read"] == 3
    assert firewall_records[0]["accepted"] == 2
    assert firewall_records[0]["rejected"] == 1
    assert firewall_records[0]["reason_codes"] == [
        "too_few_fields",
    ]

    assert "raw_record" not in firewall_records[0]

    json_content = json_report.read_text(
        encoding="utf-8"
    )
    html_content = html_report.read_text(
        encoding="utf-8"
    )

    assert "Parser Diagnostics" in html_content

    assert malformed_record not in json_content
    assert malformed_record not in html_content

    assert "do_not_export" not in json_content
    assert "do_not_export" not in html_content

    assert malformed_record not in repr(diagnostics)
    assert malformed_record not in repr(quarantine)
