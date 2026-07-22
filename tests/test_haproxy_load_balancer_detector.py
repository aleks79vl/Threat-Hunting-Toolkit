from src.detection.web.haproxy_load_balancer_detector import (
    detect_haproxy_load_balancer_anomalies,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    backend: str,
    status_code: int,
    termination_state: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-21T12:00:00Z",
        source="haproxy",
        client_ip="203.0.113.44",
        method="GET",
        path="/v1/products",
        status_code=status_code,
        host="public_frontend",
        virtual_host="public_frontend",
        upstream="api_backend",
        backend=backend,
        metadata={
            "termination_state": termination_state,
        },
    )


def test_detects_unavailable_haproxy_backend():
    findings = detect_haproxy_load_balancer_anomalies(
        [
            make_event(
                backend="<NOSRV>",
                status_code=503,
                termination_state="SC--",
            )
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "HAProxy Backend Unavailable"
    assert findings[0].severity == "high"


def test_detects_haproxy_backend_server_error():
    findings = detect_haproxy_load_balancer_anomalies(
        [
            make_event(
                backend="api-01",
                status_code=502,
                termination_state="----",
            )
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "HAProxy Backend Server Error"
    assert findings[0].severity == "medium"


def test_ignores_healthy_haproxy_event():
    findings = detect_haproxy_load_balancer_anomalies(
        [
            make_event(
                backend="api-01",
                status_code=200,
                termination_state="----",
            )
        ]
    )

    assert findings == []
