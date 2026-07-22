from src.detection.web.http_request_smuggling_detector import (
    detect_http_request_smuggling_indicators,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    request_headers: dict[str, str],
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T00:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="POST",
        path="/api/orders",
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        request_headers=request_headers,
    )


def test_detects_content_length_and_transfer_encoding():
    findings = detect_http_request_smuggling_indicators(
        [
            make_event(
                request_headers={
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                }
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Ambiguous HTTP Request Framing Detected"
    )
    assert findings[0].severity == "high"


def test_detects_framing_header_in_connection_header():
    findings = detect_http_request_smuggling_indicators(
        [
            make_event(
                request_headers={
                    "Connection": "keep-alive, Content-Length",
                    "Content-Length": "12",
                }
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Framing Header Listed in Connection Header"
    )


def test_ignores_regular_chunked_request():
    findings = detect_http_request_smuggling_indicators(
        [
            make_event(
                request_headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/json",
                }
            )
        ]
    )

    assert findings == []