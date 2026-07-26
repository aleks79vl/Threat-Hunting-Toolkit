from src.detection.web.load_balancer_session_detector import (
    detect_load_balancer_session_abuse,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    backend: str,
    session_id_hash: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-21T13:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path="/v1/profile",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        upstream="api_backend",
        backend=backend,
        metadata={
            "session_id_hash": session_id_hash,
        },
    )


def test_detects_session_routed_to_multiple_backends():
    findings = detect_load_balancer_session_abuse(
        [
            make_event(
                backend="10.0.1.10:8080",
                session_id_hash="sha256:session-1001",
            ),
            make_event(
                backend="10.0.1.11:8080",
                session_id_hash="sha256:session-1001",
            ),
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Load Balancer Session Affinity Anomaly"
    )
    assert findings[0].severity == "medium"


def test_ignores_session_routed_to_one_backend():
    findings = detect_load_balancer_session_abuse(
        [
            make_event(
                backend="10.0.1.10:8080",
                session_id_hash="sha256:session-1001",
            ),
            make_event(
                backend="10.0.1.10:8080",
                session_id_hash="sha256:session-1001",
            ),
        ]
    )

    assert findings == []


def test_ignores_events_without_session_hash():
    findings = detect_load_balancer_session_abuse(
        [
            make_event(
                backend="10.0.1.10:8080",
                session_id_hash="",
            ),
            make_event(
                backend="10.0.1.11:8080",
                session_id_hash="",
            ),
        ]
    )

    assert findings == []