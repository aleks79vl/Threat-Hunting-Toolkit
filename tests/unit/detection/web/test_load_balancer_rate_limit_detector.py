from src.detection.web.load_balancer_rate_limit_detector import (
    detect_rate_limit_bypass,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    client_ip: str,
    session_id_hash: str = "",
    api_key_id: str = "",
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-21T14:00:00Z",
        source="nginx",
        client_ip=client_ip,
        method="GET",
        path="/v1/products",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        metadata={
            "session_id_hash": session_id_hash,
            "api_key_id": api_key_id,
        },
    )


def test_detects_session_used_from_multiple_ips():
    findings = detect_rate_limit_bypass(
        [
            make_event(
                client_ip="198.51.100.10",
                session_id_hash="sha256:session-1001",
            ),
            make_event(
                client_ip="198.51.100.11",
                session_id_hash="sha256:session-1001",
            ),
            make_event(
                client_ip="198.51.100.12",
                session_id_hash="sha256:session-1001",
            ),
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "Potential Rate Limit Bypass"
    assert findings[0].severity == "medium"


def test_detects_api_key_used_from_multiple_ips():
    findings = detect_rate_limit_bypass(
        [
            make_event(
                client_ip="198.51.100.10",
                api_key_id="demo-key-001",
            ),
            make_event(
                client_ip="198.51.100.11",
                api_key_id="demo-key-001",
            ),
            make_event(
                client_ip="198.51.100.12",
                api_key_id="demo-key-001",
            ),
        ]
    )

    assert len(findings) == 1
    assert findings[0].ioc_value == "api_key:demo-key-001"


def test_ignores_identity_used_from_one_ip():
    findings = detect_rate_limit_bypass(
        [
            make_event(
                client_ip="198.51.100.10",
                session_id_hash="sha256:session-1001",
            ),
            make_event(
                client_ip="198.51.100.10",
                session_id_hash="sha256:session-1001",
            ),
        ]
    )

    assert findings == []