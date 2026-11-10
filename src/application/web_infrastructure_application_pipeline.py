from collections.abc import Callable

from src.models.web_infrastructure_event import WebInfrastructureEvent
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
from src.parsers.parser_diagnostics import ParserDiagnostics

from src.application.source_failure import SourceFailure
from src.application.source_isolation import parse_isolated_source


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
    *,
    nginx_diagnostics: ParserDiagnostics | None = None,
    waf_diagnostics: ParserDiagnostics | None = None,
    apache_access_diagnostics: ParserDiagnostics | None = None,
    apache_vhost_diagnostics: ParserDiagnostics | None = None,
    source_failures: list[SourceFailure] | None = None,
) -> WebInfrastructurePipelineResult:

    apache_access_events = parse_isolated_source(
        source="apache_access",
        parse=lambda: parse_apache_access_log(
            apache_access_log_file,
            diagnostics=apache_access_diagnostics,
        ),
        source_failures=source_failures,
    )

    apache_vhost_events = parse_isolated_source(
        source="apache_vhost",
        parse=lambda: parse_apache_vhost_access_log(
            apache_vhost_log_file,
            diagnostics=apache_vhost_diagnostics,
        ),
        source_failures=source_failures,
    )

    nginx_events = parse_isolated_source(
        source="nginx",
        parse=lambda: parse_nginx_json_log(
            nginx_access_log_file,
            diagnostics=nginx_diagnostics,
        ),
        source_failures=source_failures,
    )

    waf_events = parse_isolated_source(
        source="waf_cdn",
        parse=lambda: parse_waf_cdn_log(
            waf_cdn_log_file,
            diagnostics=waf_diagnostics,
        ),
        source_failures=source_failures,
    )

    web_infrastructure_events = (
        apache_access_events
        + apache_vhost_events
        + parse_isolated_source(
            source="apache_error",
            parse=lambda: parse_apache_error_log(
                apache_error_log_file,
            ),
            source_failures=source_failures,
        )
        + nginx_events
        + parse_isolated_source(
            source="nginx_error",
            parse=lambda: parse_nginx_error_log(
                nginx_error_log_file,
            ),
            source_failures=source_failures,
        )
        + parse_isolated_source(
            source="api_gateway",
            parse=lambda: parse_api_gateway_log(
                api_gateway_log_file,
            ),
            source_failures=source_failures,
        )
        + parse_isolated_source(
            source="haproxy",
            parse=lambda: parse_haproxy_http_log(
                haproxy_log_file,
            ),
            source_failures=source_failures,
        )

        + waf_events
    )

    web_security_baseline = load_web_security_baseline(
        web_security_baseline_file
    )

    return run_web_infrastructure_detection_pipeline(
        web_infrastructure_events,
        web_security_baseline=web_security_baseline,
    )
