from src.detection.web.websocket_upgrade_detector import (
    detect_websocket_upgrade_anomalies,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    path: str,
    status_code: int,
    websocket_upgrade: bool,
    server_port: int = 443,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-22T13:00:00Z",
        source="nginx",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=status_code,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=server_port,
        websocket_upgrade=websocket_upgrade,
    )


def test_detects_unexpected_websocket_upgrade_path():
    findings = detect_websocket_upgrade_anomalies(
        [
            make_event(
                path="/admin/socket",
                status_code=101,
                websocket_upgrade=True,
            )
        ],
        allowed_websocket_paths={"/socket"},
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Unexpected WebSocket Upgrade Path"
    )


def test_detects_http101_without_websocket_upgrade():
    findings = detect_websocket_upgrade_anomalies(
        [
            make_event(
                path="/socket",
                status_code=101,
                websocket_upgrade=False,
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Unexpected HTTP Protocol Switch"
    )


def test_detects_websocket_upgrade_without_tls():
    findings = detect_websocket_upgrade_anomalies(
        [
            make_event(
                path="/socket",
                status_code=101,
                websocket_upgrade=True,
                server_port=80,
            )
        ],
        allowed_websocket_paths={"/socket"},
    )

    assert len(findings) == 1
    assert findings[0].title == "WebSocket Upgrade Without TLS"
    assert findings[0].severity == "high"


def test_ignores_allowed_secure_websocket_upgrade():
    findings = detect_websocket_upgrade_anomalies(
        [
            make_event(
                path="/socket",
                status_code=101,
                websocket_upgrade=True,
            )
        ],
        allowed_websocket_paths={"/socket"},
    )

    assert findings == []