from src.detection.web.api_session_abuse_detector import (
    detect_api_session_abuse,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    client_ip: str,
    session_id_hash: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-20T10:00:00Z",
        source="api_gateway",
        client_ip=client_ip,
        method="GET",
        path="/v1/profile",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        metadata={
            "session_id_hash": session_id_hash,
        },
    )


def test_detects_session_used_from_multiple_ips():
    findings = detect_api_session_abuse(
        [
            make_event(
                client_ip="198.51.100.10",
                session_id_hash="sha256:session-1001",
            ),
            make_event(
                client_ip="203.0.113.44",
                session_id_hash="sha256:session-1001",
            ),
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "Potential API Session Abuse"
    assert findings[0].severity == "medium"


def test_ignores_session_used_from_one_ip():
    findings = detect_api_session_abuse(
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


def test_ignores_events_without_session_hash():
    findings = detect_api_session_abuse(
        [
            make_event(
                client_ip="198.51.100.10",
                session_id_hash="",
            ),
            make_event(
                client_ip="203.0.113.44",
                session_id_hash="",
            ),
        ]
    )

    assert findings == []