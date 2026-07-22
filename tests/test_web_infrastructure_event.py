from src.models.web_infrastructure_event import WebInfrastructureEvent


def test_web_infrastructure_event_creation():
    event = WebInfrastructureEvent(
        timestamp="2026-07-18T12:00:00Z",
        source="nginx",
        client_ip="203.0.113.10",
        method="GET",
        path="/api/health",
        status_code=200,
        host="api.example.com",
        request_id="req-123",
        response_time_ms=12.5,
    )

    assert event.source == "nginx"
    assert event.status_code == 200
    assert event.request_id == "req-123"
    assert event.forwarded_for == []


def test_web_infrastructure_event_to_dict():
    event = WebInfrastructureEvent(
        timestamp="2026-07-18T12:00:00Z",
        source="apache",
        client_ip="198.51.100.25",
        method="POST",
        path="/login",
        status_code=401,
        forwarded_for=["198.51.100.25", "10.0.0.10"],
        response_size=512,
    )

    data = event.to_dict()

    assert data["client_ip"] == "198.51.100.25"
    assert data["forwarded_for"] == [
        "198.51.100.25",
        "10.0.0.10",
    ]
    assert data["response_size"] == 512

def test_web_infrastructure_event_redacts_sensitive_headers():
    event = WebInfrastructureEvent(
        timestamp="2026-07-18T12:00:00Z",
        source="nginx",
        client_ip="203.0.113.10",
        method="GET",
        path="/api/profile",
        status_code=200,
        request_headers={
            "Authorization": "Bearer secret-token",
            "User-Agent": "Threat-Hunting-Toolkit-Test",
            "X-API-Key": "super-secret-key",
        },
    )

    assert event.request_headers["Authorization"] == "[REDACTED]"
    assert event.request_headers["X-API-Key"] == "[REDACTED]"
    assert (event.request_headers["User-Agent"]
        == "Threat-Hunting-Toolkit-Test")