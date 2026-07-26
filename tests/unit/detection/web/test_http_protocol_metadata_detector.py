from src.detection.web.http_protocol_metadata_detector import (
    detect_http_protocol_metadata_anomalies,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    protocol: str,
    request_headers: dict[str, str] | None = None,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-22T12:00:00Z",
        source="waf_cdn",
        client_ip="203.0.113.44",
        method="GET",
        path="/v1/profile",
        status_code=200,
        protocol=protocol,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        request_headers=request_headers or {},
    )


def test_detects_connection_header_in_http2_request():
    findings = detect_http_protocol_metadata_anomalies(
        [
            make_event(
                protocol="HTTP/2",
                request_headers={
                    "Connection": "keep-alive",
                },
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "HTTP/2 Connection Header Detected"
    )
    assert findings[0].severity == "high"


def test_detects_transfer_encoding_in_http2_request():
    findings = detect_http_protocol_metadata_anomalies(
        [
            make_event(
                protocol="HTTP/2.0",
                request_headers={
                    "Transfer-Encoding": "chunked",
                },
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "HTTP/2 Transfer-Encoding Header Detected"
    )


def test_detects_legacy_http10_request():
    findings = detect_http_protocol_metadata_anomalies(
        [
            make_event(
                protocol="HTTP/1.0",
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Legacy HTTP/1.0 Request Detected"
    )
    assert findings[0].severity == "low"


def test_ignores_valid_http2_request():
    findings = detect_http_protocol_metadata_anomalies(
        [
            make_event(
                protocol="HTTP/2",
                request_headers={
                    "Accept": "application/json",
                },
            )
        ]
    )

    assert findings == []