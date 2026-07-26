from src.detection.web.cache_poisoning_detector import (
    detect_cache_poisoning_indicators,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    request_headers: dict[str, str],
    response_headers: dict[str, str],
    method: str = "GET",
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T00:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method=method,
        path="/",
        status_code=200,
        host="www.example.com",
        virtual_host="www.example.com",
        server_port=443,
        request_headers=request_headers,
        response_headers=response_headers,
    )


def test_detects_unkeyed_forwarded_host_on_cached_response():
    findings = detect_cache_poisoning_indicators(
        [
            make_event(
                request_headers={
                    "X-Forwarded-Host": "attacker.example",
                },
                response_headers={
                    "Cache-Control": "public, s-maxage=600",
                },
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential Web Cache Poisoning via Forwarded Host"
    )
    assert findings[0].severity == "high"


def test_ignores_forwarded_host_without_shared_cache():
    findings = detect_cache_poisoning_indicators(
        [
            make_event(
                request_headers={
                    "X-Forwarded-Host": "attacker.example",
                },
                response_headers={
                    "Cache-Control": "private, max-age=60",
                },
            )
        ]
    )

    assert findings == []


def test_ignores_matching_forwarded_host():
    findings = detect_cache_poisoning_indicators(
        [
            make_event(
                request_headers={
                    "X-Forwarded-Host": "www.example.com",
                },
                response_headers={
                    "Cache-Control": "public, max-age=300",
                },
            )
        ]
    )

    assert findings == []