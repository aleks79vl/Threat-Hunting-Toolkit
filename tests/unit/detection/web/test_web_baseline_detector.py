from src.detection.web.web_baseline_detector import (
    detect_web_baseline_deviations,
    load_web_security_baseline,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


BASELINE_FILE = "config/web_security_baseline.json"


def make_event(
    *,
    user_agent: str = "ExampleMobileApp/2.4",
    tls_version: str = "TLSv1.3",
    path: str = "/v1/profile",
    websocket_upgrade: bool = False,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-22T15:00:00Z",
        source="waf_cdn",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=200,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        user_agent=user_agent,
        tls_version=tls_version,
        websocket_upgrade=websocket_upgrade,
    )


def test_load_web_security_baseline():
    baseline = load_web_security_baseline(BASELINE_FILE)

    assert baseline["allowed_tls_versions"] == [
        "TLSv1.2",
        "TLSv1.3",
    ]


def test_detects_suspicious_user_agent_marker():
    findings = detect_web_baseline_deviations(
        [
            make_event(
                user_agent="sqlmap/1.8",
            )
        ],
        load_web_security_baseline(BASELINE_FILE),
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Threat Intelligence User-Agent Match in Web Activity"
    )


def test_detects_unapproved_websocket_path():
    findings = detect_web_baseline_deviations(
        [
            make_event(
                path="/admin/socket",
                websocket_upgrade=True,
            )
        ],
        load_web_security_baseline(BASELINE_FILE),
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "WebSocket Path Deviates from Web Baseline"
    )


def test_ignores_event_matching_web_baseline():
    findings = detect_web_baseline_deviations(
        [
            make_event(
                path="/socket",
                websocket_upgrade=True,
            )
        ],
        load_web_security_baseline(BASELINE_FILE),
    )

    assert findings == []