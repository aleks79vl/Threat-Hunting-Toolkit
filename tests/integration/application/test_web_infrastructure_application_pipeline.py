from src.application.web_infrastructure_application_pipeline import (
    run_web_infrastructure_application_pipeline,
)
from src.config.app_config import default_app_config


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