from dataclasses import replace

from src.config.app_config import default_app_config


def test_default_linux_time_context_is_unknown():
    config = default_app_config()

    assert config.linux_auth_source_year is None
    assert config.linux_auth_source_timezone is None
    assert config.linux_syslog_source_year is None
    assert config.linux_syslog_source_timezone is None


def test_app_config_supports_independent_linux_time_contexts():
    config = replace(
        default_app_config(),
        linux_auth_source_year=2026,
        linux_auth_source_timezone="Asia/Jerusalem",
        linux_syslog_source_year=2025,
        linux_syslog_source_timezone="America/New_York",
    )

    assert config.linux_auth_source_year == 2026
    assert config.linux_auth_source_timezone == "Asia/Jerusalem"

    assert config.linux_syslog_source_year == 2025
    assert config.linux_syslog_source_timezone == "America/New_York"

    # Existing source configuration must remain independent.
    assert config.windows_source_timezone is None
    assert config.firewall_source_timezone is None
