from src.detection.web.nginx_reverse_proxy_detector import (
    detect_nginx_reverse_proxy_abuse,
)
from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)

from src.detection.web.reverse_proxy_policy import (
    ReverseProxyPolicy,
)


def make_event(
    *,
    client_ip: str,
    host: str,
    forwarded_for: list[str] | None = None,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-18T16:30:00Z",
        source="nginx",
        client_ip=client_ip,
        method="GET",
        path="/api/users",
        status_code=200,
        host=host,
        virtual_host="api.example.com",
        server_port=443,
        forwarded_for=forwarded_for or [],
    )


def test_detects_private_backend_in_host_header():
    findings = detect_nginx_reverse_proxy_abuse(
        [
            make_event(
                client_ip="203.0.113.44",
                host="10.0.1.15",
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential Backend Exposure Through Host Header"
    )


def test_detects_untrusted_forwarded_for_header():
    findings = detect_nginx_reverse_proxy_abuse(
        [
            make_event(
                client_ip="203.0.113.44",
                host="api.example.com",
                forwarded_for=["198.51.100.10"],
            )
        ],
        policy=ReverseProxyPolicy(
            trusted_proxy_networks=["10.0.0.5"]
        ),
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Untrusted X-Forwarded-For Header Detected"
    )


def test_ignores_forwarded_for_from_trusted_proxy():
    findings = detect_nginx_reverse_proxy_abuse(
        [
            make_event(
                client_ip="10.0.0.5",
                host="api.example.com",
                forwarded_for=["198.51.100.10"],
            )
        ],
        policy=ReverseProxyPolicy(
            trusted_proxy_networks=["10.0.0.5"]
        ),
    )

    assert findings == []