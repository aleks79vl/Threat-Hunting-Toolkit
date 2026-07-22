from pathlib import Path

from src.detection.web.web_baseline_detector import (
    load_web_security_baseline,
)
from src.detection.web.web_infrastructure_pipeline import (
    run_web_infrastructure_detection_pipeline,
)
from src.parsers.apache_access_log_parser import (
    parse_apache_access_log,
    parse_apache_vhost_access_log,
)
from src.parsers.apache_error_log_parser import (
    parse_apache_error_log,
)
from src.parsers.api_gateway_log_parser import (
    parse_api_gateway_log,
)
from src.parsers.haproxy_log_parser import (
    parse_haproxy_http_log,
)
from src.parsers.nginx_error_log_parser import (
    parse_nginx_error_log,
)
from src.parsers.nginx_json_log_parser import (
    parse_nginx_json_log,
)
from src.parsers.waf_cdn_log_parser import (
    parse_waf_cdn_log,
)


WEB_DATA_DIR = Path("data/raw/web")
WEB_BASELINE_FILE = Path("config/web_security_baseline.json")


def test_web_infrastructure_fixture_pipeline():
    events = (
        parse_apache_access_log(
            WEB_DATA_DIR / "apache_access.log"
        )
        + parse_apache_vhost_access_log(
            WEB_DATA_DIR / "apache_vhost_access.log"
        )
        + parse_apache_error_log(
            WEB_DATA_DIR / "apache_error.log"
        )
        + parse_nginx_json_log(
            WEB_DATA_DIR / "nginx_access.jsonl"
        )
        + parse_nginx_error_log(
            WEB_DATA_DIR / "nginx_error.log"
        )
        + parse_api_gateway_log(
            WEB_DATA_DIR / "api_gateway_access.jsonl"
        )
        + parse_haproxy_http_log(
            WEB_DATA_DIR / "haproxy_http.log"
        )
        + parse_waf_cdn_log(
            WEB_DATA_DIR / "waf_cdn_events.jsonl"
        )
    )

    baseline = load_web_security_baseline(
        WEB_BASELINE_FILE
    )

    result = run_web_infrastructure_detection_pipeline(
        events,
        web_security_baseline=baseline,
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

    finding_sources = {
        finding.source
        for finding in result.findings
    }

    assert {
        "Nginx Reverse Proxy Detector",
        "Nginx Upstream Error Detector",
        "HAProxy Load Balancer Detector",
    } <= finding_sources