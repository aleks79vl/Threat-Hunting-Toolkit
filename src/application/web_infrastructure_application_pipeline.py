from src.detection.web.web_baseline_detector import (
    load_web_security_baseline,
)
from src.detection.web.web_infrastructure_pipeline import (
    WebInfrastructurePipelineResult,
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
from src.parsers.waf_cdn_log_parser import parse_waf_cdn_log


def run_web_infrastructure_application_pipeline(
    apache_access_log_file: str,
    apache_vhost_log_file: str,
    apache_error_log_file: str,
    nginx_access_log_file: str,
    nginx_error_log_file: str,
    api_gateway_log_file: str,
    haproxy_log_file: str,
    waf_cdn_log_file: str,
    web_security_baseline_file: str,
) -> WebInfrastructurePipelineResult:
    web_infrastructure_events = (
        parse_apache_access_log(apache_access_log_file)
        + parse_apache_vhost_access_log(apache_vhost_log_file)
        + parse_apache_error_log(apache_error_log_file)
        + parse_nginx_json_log(nginx_access_log_file)
        + parse_nginx_error_log(nginx_error_log_file)
        + parse_api_gateway_log(api_gateway_log_file)
        + parse_haproxy_http_log(haproxy_log_file)
        + parse_waf_cdn_log(waf_cdn_log_file)
    )

    web_security_baseline = load_web_security_baseline(
        web_security_baseline_file
    )

    return run_web_infrastructure_detection_pipeline(
        web_infrastructure_events,
        web_security_baseline=web_security_baseline,
    )