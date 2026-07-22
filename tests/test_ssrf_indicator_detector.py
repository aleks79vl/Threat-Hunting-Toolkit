from src.detection.web.ssrf_indicator_detector import (
    detect_ssrf_indicators,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(*, path: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T00:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
    )


def test_detects_cloud_metadata_ssrf_target():
    findings = detect_ssrf_indicators(
        [
            make_event(
                path=(
                    "/fetch?url=http%3A%2F%2F169.254.169.254"
                    "%2Flatest%2Fmeta-data%2F"
                )
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential SSRF Request to Internal Target"
    )
    assert findings[0].severity == "high"


def test_detects_localhost_ssrf_target():
    findings = detect_ssrf_indicators(
        [
            make_event(
                path="/proxy?target=http://localhost:8080/admin"
            )
        ]
    )

    assert len(findings) == 1


def test_ignores_public_url_target():
    findings = detect_ssrf_indicators(
        [
            make_event(
                path="/fetch?url=https://example.com/avatar.png"
            )
        ]
    )

    assert findings == []