from dataclasses import replace

from src.config.app_config import AppConfig, default_app_config


def test_default_app_config_preserves_current_application_paths():
    config = default_app_config()

    assert isinstance(config, AppConfig)
    assert config.nmap_file == "data/raw/network/nmap_scan.xml"
    assert config.web_log_file == "data/raw/web/apache_access.log"
    assert config.linux_auth_file == "data/raw/linux/auth.log"
    assert config.physical_events_file == (
        "data/raw/physical/sample_physical_events.json"
    )
    assert config.web_security_baseline_file == (
        "config/web_security_baseline.json"
    )
    assert config.json_output_file == "reports/threat_report.json"
    assert config.html_output_file == "reports/threat_report.html"


def test_app_config_supports_isolated_report_output_overrides():
    default_config = default_app_config()

    test_config = replace(
        default_config,
        json_output_file="temporary/report.json",
        html_output_file="temporary/report.html",
    )

    assert test_config.json_output_file == "temporary/report.json"
    assert test_config.html_output_file == "temporary/report.html"
    assert default_config.json_output_file == "reports/threat_report.json"
    assert default_config.html_output_file == "reports/threat_report.html"