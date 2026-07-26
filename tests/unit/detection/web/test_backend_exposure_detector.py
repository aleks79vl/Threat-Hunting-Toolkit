from src.detection.web.backend_exposure_detector import (
    detect_backend_exposure,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    response_headers: dict[str, str],
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T00:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path="/api/users",
        status_code=302,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        response_headers=response_headers,
    )


def test_detects_private_backend_address_in_location_header():
    findings = detect_backend_exposure(
        [
            make_event(
                response_headers={
                    "Location": "http://10.0.1.15:8080/login"
                }
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Private Backend Address Exposed in Response"
    )
    assert findings[0].severity == "high"


def test_ignores_public_redirect_location():
    findings = detect_backend_exposure(
        [
            make_event(
                response_headers={
                    "Location": "https://api.example.com/login"
                }
            )
        ]
    )

    assert findings == []