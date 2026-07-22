from src.detection.web.reverse_proxy_chain_detector import (
    detect_proxy_chain_anomalies,
)
from src.detection.web.reverse_proxy_policy import ReverseProxyPolicy
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    client_ip: str,
    forwarded_for: list[str],
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T00:00:00Z",
        source="nginx",
        client_ip=client_ip,
        method="GET",
        path="/api/users",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        forwarded_for=forwarded_for,
    )


def test_detects_excessive_proxy_chain_length():
    findings = detect_proxy_chain_anomalies(
        [
            make_event(
                client_ip="10.0.0.5",
                forwarded_for=[
                    "198.51.100.10",
                    "198.51.100.11",
                    "198.51.100.12",
                ],
            )
        ],
        policy=ReverseProxyPolicy(
            trusted_proxy_networks=["10.0.0.5"],
            max_proxy_chain_length=2,
        ),
    )

    assert len(findings) == 1
    assert findings[0].title == "Excessive Reverse Proxy Chain Length"


def test_detects_invalid_address_in_trusted_proxy_chain():
    findings = detect_proxy_chain_anomalies(
        [
            make_event(
                client_ip="10.0.0.5",
                forwarded_for=["198.51.100.10", "unknown"],
            )
        ],
        policy=ReverseProxyPolicy(
            trusted_proxy_networks=["10.0.0.5"]
        ),
    )

    assert len(findings) == 1
    assert findings[0].title == "Invalid Address in X-Forwarded-For Chain"


def test_ignores_chain_from_untrusted_client():
    findings = detect_proxy_chain_anomalies(
        [
            make_event(
                client_ip="203.0.113.44",
                forwarded_for=[
                    "198.51.100.10",
                    "198.51.100.11",
                    "198.51.100.12",
                    "invalid",
                ],
            )
        ],
        policy=ReverseProxyPolicy(
            trusted_proxy_networks=["10.0.0.5"],
            max_proxy_chain_length=2,
        ),
    )

    assert findings == []