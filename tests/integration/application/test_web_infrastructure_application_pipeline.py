from src.application.web_infrastructure_application_pipeline import (
    run_web_infrastructure_application_pipeline,
)
from src.config.app_config import default_app_config
from src.parsers.parser_diagnostics import ParserDiagnostics


def test_web_infrastructure_application_pipeline_loads_all_sources():
    config = default_app_config()

    result = run_web_infrastructure_application_pipeline(
        apache_access_log_file=config.web_log_file,
        apache_vhost_log_file=config.apache_vhost_log_file,
        apache_error_log_file=config.apache_error_log_file,
        nginx_access_log_file=config.nginx_access_log_file,
        nginx_error_log_file=config.nginx_error_log_file,
        api_gateway_log_file=config.api_gateway_log_file,
        haproxy_log_file=config.haproxy_log_file,
        waf_cdn_log_file=config.waf_cdn_log_file,
        web_security_baseline_file=config.web_security_baseline_file,
    )

    assert result.event_statistics() == {
        "total_events": 30,
        "events_by_source": {
            "apache": 14,
            "apache_error": 3,
            "api_gateway": 3,
            "haproxy": 2,
            "nginx": 2,
            "nginx_error": 3,
            "waf_cdn": 3,
        },
    }
    assert result.findings


def test_web_infrastructure_pipeline_exposes_nginx_diagnostics(
    tmp_path,
):
    config = default_app_config()

    nginx_log = tmp_path / "nginx_mixed.jsonl"

    nginx_log.write_text(
        "\n".join([
            '{"time":"2026-10-21T10:00:00Z",'
            '"remote_addr":"192.0.2.10",'
            '"request_method":"GET",'
            '"request_uri":"/first",'
            '"status":200}',

            '["unexpected", "root"]',

            '{"time":"2026-10-21T10:00:02Z",'
            '"remote_addr":"192.0.2.20",'
            '"request_method":"GET",'
            '"request_uri":"/second",'
            '"status":200}',
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    result = run_web_infrastructure_application_pipeline(
        apache_access_log_file=config.web_log_file,
        apache_vhost_log_file=config.apache_vhost_log_file,
        apache_error_log_file=config.apache_error_log_file,
        nginx_access_log_file=str(nginx_log),
        nginx_error_log_file=config.nginx_error_log_file,
        api_gateway_log_file=config.api_gateway_log_file,
        haproxy_log_file=config.haproxy_log_file,
        waf_cdn_log_file=config.waf_cdn_log_file,
        web_security_baseline_file=config.web_security_baseline_file,
        nginx_diagnostics=diagnostics,
    )

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_root_type"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

    statistics = result.event_statistics()

    assert statistics["total_events"] == 30
    assert statistics["events_by_source"] == {
        "apache": 14,
        "apache_error": 3,
        "api_gateway": 3,
        "haproxy": 2,
        "nginx": 2,
        "nginx_error": 3,
        "waf_cdn": 3,
    }
