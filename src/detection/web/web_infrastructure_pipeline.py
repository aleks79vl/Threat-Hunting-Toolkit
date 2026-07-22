from collections import defaultdict
from dataclasses import dataclass, field

from src.detection.web.apache_web_shell_detector import (
    detect_apache_web_shells,
)
from src.detection.web.backend_exposure_detector import (
    detect_backend_exposure,
)
from src.detection.web.cache_poisoning_detector import (
    detect_cache_poisoning_indicators,
)
from src.detection.web.header_manipulation_detector import (
    detect_header_manipulation,
)
from src.detection.web.http_request_smuggling_detector import (
    detect_http_request_smuggling_indicators,
)
from src.detection.web.api_admin_endpoint_detector import (
    detect_api_admin_endpoint_access,
)
from src.detection.web.api_auth_attack_detector import (
    detect_api_auth_attacks,
)
from src.detection.web.api_bot_scraping_detector import (
    detect_api_bot_and_scraping_activity,
)
from src.detection.web.api_resource_consumption_detector import (
    detect_api_resource_consumption,
)
from src.detection.web.api_session_abuse_detector import (
    detect_api_session_abuse,
)
from src.detection.web.haproxy_load_balancer_detector import (
    detect_haproxy_load_balancer_anomalies,
)
from src.detection.web.load_balancer_rate_limit_detector import (
    detect_rate_limit_bypass,
)
from src.detection.web.load_balancer_session_detector import (
    detect_load_balancer_session_abuse,
)
from src.detection.web.http_protocol_metadata_detector import (
    detect_http_protocol_metadata_anomalies,
)
from src.detection.web.nginx_directory_traversal_detector import (
    detect_nginx_directory_traversal,
)
from src.detection.web.nginx_http_method_detector import (
    detect_nginx_http_method_abuse,
)
from src.detection.web.nginx_load_balancer_detector import (
    detect_nginx_load_balancer_anomalies,
)
from src.detection.web.nginx_php_attack_detector import (
    detect_nginx_php_attacks,
)
from src.detection.web.nginx_reverse_proxy_detector import (
    detect_nginx_reverse_proxy_abuse,
)
from src.detection.web.nginx_upload_abuse_detector import (
    detect_nginx_upload_abuse,
)
from src.detection.web.nginx_upstream_error_detector import (
    detect_nginx_upstream_errors,
)
from src.detection.web.reverse_proxy_chain_detector import (
    detect_proxy_chain_anomalies,
)
from src.detection.web.reverse_proxy_policy import (
    ReverseProxyPolicy,
)
from src.detection.web.ssrf_indicator_detector import (
    detect_ssrf_indicators,
)
from src.detection.web.tls_metadata_detector import (
    detect_tls_metadata_anomalies,
)
from src.detection.web.waf_security_detector import (
    detect_waf_security_events,
)
from src.detection.web.web_baseline_detector import (
    detect_web_baseline_deviations,
)
from src.detection.web.websocket_upgrade_detector import (
    detect_websocket_upgrade_anomalies,
)
from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


WEB_INFRASTRUCTURE_SOURCES = (
    "apache",
    "apache_error",
    "api_gateway",
    "haproxy",
    "nginx",
    "nginx_error",
    "waf_cdn",
)


@dataclass
class WebInfrastructurePipelineResult:
    events_by_source: dict[
        str,
        list[WebInfrastructureEvent],
    ] = field(default_factory=dict)

    findings: list[ThreatFinding] = field(
        default_factory=list
    )

    def total_events(self) -> int:
        return sum(
            len(events)
            for events in self.events_by_source.values()
        )

    def event_statistics(self) -> dict:
        return {
            "total_events": self.total_events(),
            "events_by_source": {
                source: len(
                    self.events_by_source.get(source, [])
                )
                for source in WEB_INFRASTRUCTURE_SOURCES
            },
        }


def create_web_infrastructure_result(
    events: list[WebInfrastructureEvent],
) -> WebInfrastructurePipelineResult:
    events_by_source = defaultdict(list)

    for event in events:
        if event.source not in WEB_INFRASTRUCTURE_SOURCES:
            continue

        events_by_source[event.source].append(event)

    return WebInfrastructurePipelineResult(
        events_by_source=dict(events_by_source)
    )


def run_web_infrastructure_detection_pipeline(
    events: list[WebInfrastructureEvent],
    *,
    reverse_proxy_policy: ReverseProxyPolicy | None = None,
    web_security_baseline: dict | None = None,
) -> WebInfrastructurePipelineResult:
    result = create_web_infrastructure_result(events)

    nginx_events = result.events_by_source.get(
        "nginx",
        [],
    )
    nginx_error_events = result.events_by_source.get(
        "nginx_error",
        [],
    )
    api_gateway_events = result.events_by_source.get(
        "api_gateway",
        [],
    )
    haproxy_events = result.events_by_source.get(
        "haproxy",
        [],
    )
    waf_cdn_events = result.events_by_source.get(
        "waf_cdn",
        [],
    )
    apache_events = result.events_by_source.get(
        "apache",
        [],
    )

    policy = reverse_proxy_policy or ReverseProxyPolicy()

    result.findings.extend(
        detect_nginx_reverse_proxy_abuse(
            nginx_events,
            policy=policy,
        )
    )
    result.findings.extend(
        detect_proxy_chain_anomalies(
            nginx_events,
            policy=policy,
        )
    )
    result.findings.extend(
        detect_nginx_upstream_errors(nginx_error_events)
    )
    result.findings.extend(
        detect_nginx_http_method_abuse(nginx_events)
    )
    result.findings.extend(
        detect_nginx_directory_traversal(nginx_events)
    )
    result.findings.extend(
        detect_nginx_upload_abuse(nginx_events)
    )
    result.findings.extend(
        detect_nginx_php_attacks(nginx_events)
    )
    result.findings.extend(
        detect_nginx_load_balancer_anomalies(
            nginx_events
        )
    )

    result.findings.extend(
        detect_api_auth_attacks(api_gateway_events)
    )
    result.findings.extend(
        detect_api_session_abuse(api_gateway_events)
    )
    result.findings.extend(
        detect_api_admin_endpoint_access(
            api_gateway_events
        )
    )
    result.findings.extend(
        detect_api_resource_consumption(
            api_gateway_events
        )
    )
    result.findings.extend(
        detect_api_bot_and_scraping_activity(
            api_gateway_events
        )
    )

    result.findings.extend(
        detect_haproxy_load_balancer_anomalies(
            haproxy_events
        )
    )

    result.findings.extend(
        detect_waf_security_events(waf_cdn_events)
    )
    result.findings.extend(
        detect_tls_metadata_anomalies(waf_cdn_events)
    )
    result.findings.extend(
        detect_http_protocol_metadata_anomalies(
            waf_cdn_events
        )
    )

    allowed_websocket_paths = None

    if web_security_baseline is not None:
        allowed_websocket_paths = set(
            web_security_baseline.get(
                "allowed_websocket_paths",
                [],
            )
        )

    result.findings.extend(
        detect_websocket_upgrade_anomalies(
            waf_cdn_events,
            allowed_websocket_paths=allowed_websocket_paths,
        )
    )

    if web_security_baseline is not None:
        result.findings.extend(
            detect_web_baseline_deviations(
                waf_cdn_events,
                web_security_baseline,
            )
        )

    result.findings.extend(
        detect_apache_web_shells(apache_events)
    )

    request_response_events = (
        apache_events
        + nginx_events
        + api_gateway_events
        + haproxy_events
        + waf_cdn_events
    )

    result.findings.extend(
        detect_backend_exposure(request_response_events)
    )
    result.findings.extend(
        detect_cache_poisoning_indicators(
            request_response_events
        )
    )
    result.findings.extend(
        detect_header_manipulation(request_response_events)
    )
    result.findings.extend(
        detect_http_request_smuggling_indicators(
            request_response_events
        )
    )
    result.findings.extend(
        detect_ssrf_indicators(request_response_events)
    )

    load_balancer_events = (
        nginx_events
        + haproxy_events
        + api_gateway_events
    )

    result.findings.extend(
        detect_load_balancer_session_abuse(
            load_balancer_events
        )
    )
    result.findings.extend(
        detect_rate_limit_bypass(load_balancer_events)
    )

    return result