from src.detection.web.web_infrastructure_pipeline import (
    create_web_infrastructure_result,
    run_web_infrastructure_detection_pipeline,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(source: str) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-22T16:00:00Z",
        source=source,
        client_ip="203.0.113.44",
        method="GET",
        path="/v1/profile",
        status_code=200,
    )


def test_pipeline_groups_events_by_supported_source():
    result = create_web_infrastructure_result(
        [
            make_event("nginx"),
            make_event("nginx"),
            make_event("api_gateway"),
            make_event("waf_cdn"),
        ]
    )

    assert len(result.events_by_source["nginx"]) == 2
    assert len(result.events_by_source["api_gateway"]) == 1
    assert len(result.events_by_source["waf_cdn"]) == 1


def test_pipeline_ignores_non_web_source():
    result = create_web_infrastructure_result(
        [
            make_event("nginx"),
            make_event("firewall"),
        ]
    )

    assert result.total_events() == 1
    assert "firewall" not in result.events_by_source


def test_pipeline_generates_event_statistics():
    result = create_web_infrastructure_result(
        [
            make_event("apache"),
            make_event("haproxy"),
            make_event("waf_cdn"),
        ]
    )

    assert result.event_statistics() == {
        "total_events": 3,
        "events_by_source": {
            "apache": 1,
            "apache_error": 0,
            "api_gateway": 0,
            "haproxy": 1,
            "nginx": 0,
            "nginx_error": 0,
            "waf_cdn": 1,
        },
    }


def test_pipeline_runs_nginx_detectors():
    result = run_web_infrastructure_detection_pipeline(
        [
            WebInfrastructureEvent(
                timestamp="2026-07-22T16:00:00Z",
                source="nginx",
                client_ip="203.0.113.44",
                method="GET",
                path="/../../etc/passwd",
                status_code=400,
                host="api.example.com",
                virtual_host="api.example.com",
                server_port=443,
            )
        ]
    )

    assert len(result.findings) == 1
    assert (
        result.findings[0].title
        == "Nginx Directory Traversal Attempt Detected"
    )


def test_pipeline_runs_api_gateway_detectors():
    events = [
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:00Z",
            source="api_gateway",
            client_ip="203.0.113.44",
            method="POST",
            path="/v1/auth/login",
            status_code=401,
            host="api.example.com",
            virtual_host="api.example.com",
            server_port=443,
            metadata={
                "auth_status": "failure",
                "principal_id": "account-1001",
                "route_template": "/v1/auth/login",
            },
        )
        for _ in range(5)
    ]

    result = run_web_infrastructure_detection_pipeline(events)

    assert len(result.findings) == 1
    assert (
        result.findings[0].title
        == "Potential API Brute Force Attack"
    )


def test_pipeline_runs_haproxy_detector():
    result = run_web_infrastructure_detection_pipeline(
        [
            WebInfrastructureEvent(
                timestamp="2026-07-22T16:00:00Z",
                source="haproxy",
                client_ip="203.0.113.44",
                method="GET",
                path="/v1/products",
                status_code=503,
                host="public_frontend",
                virtual_host="public_frontend",
                upstream="api_backend",
                backend="<NOSRV>",
                metadata={
                    "termination_state": "SC--",
                },
            )
        ]
    )

    assert len(result.findings) == 1
    assert (
        result.findings[0].title
        == "HAProxy Backend Unavailable"
    )


def test_pipeline_runs_waf_protocol_detectors():
    result = run_web_infrastructure_detection_pipeline(
        [
            WebInfrastructureEvent(
                timestamp="2026-07-22T16:00:00Z",
                source="waf_cdn",
                client_ip="203.0.113.44",
                method="GET",
                path="/v1/profile",
                status_code=200,
                protocol="HTTP/2",
                host="api.example.com",
                virtual_host="api.example.com",
                request_headers={
                    "Connection": "keep-alive",
                },
            )
        ]
    )

    assert len(result.findings) == 1
    assert (
        result.findings[0].title
        == "HTTP/2 Connection Header Detected"
    )


def test_pipeline_runs_apache_detector():
    result = run_web_infrastructure_detection_pipeline(
        [
            WebInfrastructureEvent(
                timestamp="2026-07-22T16:00:00Z",
                source="apache",
                client_ip="203.0.113.44",
                method="GET",
                path="/uploads/shell.php",
                status_code=200,
                host="api.example.com",
                virtual_host="api.example.com",
                server_port=443,
            )
        ]
    )

    assert len(result.findings) == 1
    assert (
        result.findings[0].title
        == "Potential Apache Web Shell Access"
    )


def test_pipeline_runs_cross_source_request_detectors():
    events = [
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:00Z",
            source="nginx",
            client_ip="203.0.113.44",
            method="GET",
            path="/redirect",
            status_code=302,
            host="api.example.com",
            response_headers={
                "Location": "http://10.0.0.5/internal",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:01Z",
            source="nginx",
            client_ip="203.0.113.45",
            method="GET",
            path="/news",
            status_code=200,
            host="api.example.com",
            request_headers={
                "X-Forwarded-Host": "attacker.example",
            },
            response_headers={
                "Cache-Control": "public, max-age=300",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:02Z",
            source="nginx",
            client_ip="203.0.113.46",
            method="GET",
            path="/profile",
            status_code=200,
            request_headers={
                "X-Original-URL": "/admin/users",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:03Z",
            source="nginx",
            client_ip="203.0.113.47",
            method="POST",
            path="/submit",
            status_code=200,
            request_headers={
                "Content-Length": "10",
                "Transfer-Encoding": "chunked",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:04Z",
            source="nginx",
            client_ip="203.0.113.48",
            method="GET",
            path=(
                "/fetch?url=http%3A%2F%2F127.0.0.1"
                "%2Fadmin"
            ),
            status_code=200,
        ),
    ]

    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert {
        "Private Backend Address Exposed in Response",
        "Potential Web Cache Poisoning via Forwarded Host",
        "Potential Header-Based Route Override",
        "Ambiguous HTTP Request Framing Detected",
        "Potential SSRF Request to Internal Target",
    } <= finding_titles


def test_pipeline_runs_load_balancer_detectors():
    events = [
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:00Z",
            source="nginx",
            client_ip="203.0.113.44",
            method="GET",
            path="/profile",
            status_code=200,
            virtual_host="api.example.com",
            backend="backend-a",
            metadata={
                "session_id_hash": "sha256:session-1001",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:01Z",
            source="nginx",
            client_ip="203.0.113.44",
            method="GET",
            path="/profile",
            status_code=200,
            virtual_host="api.example.com",
            backend="backend-b",
            metadata={
                "session_id_hash": "sha256:session-1001",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:02Z",
            source="api_gateway",
            client_ip="203.0.113.51",
            method="GET",
            path="/v1/profile",
            status_code=200,
            virtual_host="api.example.com",
            metadata={
                "api_key_id": "api-key-1001",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:03Z",
            source="api_gateway",
            client_ip="203.0.113.52",
            method="GET",
            path="/v1/profile",
            status_code=200,
            virtual_host="api.example.com",
            metadata={
                "api_key_id": "api-key-1001",
            },
        ),
        WebInfrastructureEvent(
            timestamp="2026-07-22T16:00:04Z",
            source="api_gateway",
            client_ip="203.0.113.53",
            method="GET",
            path="/v1/profile",
            status_code=200,
            virtual_host="api.example.com",
            metadata={
                "api_key_id": "api-key-1001",
            },
        ),
    ]

    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Load Balancer Session Affinity Anomaly" in finding_titles
    assert "Potential Rate Limit Bypass" in finding_titles


def test_pipeline_runs_nginx_upstream_error_detector():
    result = run_web_infrastructure_detection_pipeline(
        [
            WebInfrastructureEvent(
                timestamp="2026-07-22T16:00:00Z",
                source="nginx_error",
                client_ip="203.0.113.44",
                method="GET",
                path="/v1/profile",
                status_code=0,
                host="api.example.com",
                virtual_host="api.example.com",
                upstream="http://10.0.0.10:8080",
                metadata={
                    "message": (
                        "upstream timed out while reading "
                        "response header from upstream"
                    ),
                },
            )
        ]
    )

    assert len(result.findings) == 1
    assert (
        result.findings[0].title
        == "Nginx Upstream Timeout Detected"
    )


def test_nginx_session_hash_reaches_load_balancer_detector(tmp_path):
    from src.parsers.nginx_json_log_parser import parse_nginx_json_log

    log_file = tmp_path / "nginx_sessions.jsonl"
    session_hash = "sha256:" + "a" * 64

    log_file.write_text(
        '{"time":"2026-10-23T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"server_name":"api.example.com",'
        '"upstream_addr":"backend-a",'
        f'"session_id_hash":"{session_hash}"'
        '}\n'
        '{"time":"2026-10-23T10:00:01Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"server_name":"api.example.com",'
        '"upstream_addr":"backend-b",'
        f'"session_id_hash":"{session_hash}"'
        '}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 2
    assert all(
        event.metadata["session_id_hash"] == session_hash
        for event in events
    )

    result = run_web_infrastructure_detection_pipeline(events)

    session_findings = [
        finding
        for finding in result.findings
        if finding.title == "Load Balancer Session Affinity Anomaly"
    ]

    assert len(session_findings) == 1
    assert session_findings[0].ioc_value == session_hash


def test_pipeline_routes_nginx_websocket_events_to_detector():
    events = [
        WebInfrastructureEvent(
            timestamp="2026-10-23T10:00:00Z",
            source="nginx",
            client_ip="192.0.2.10",
            method="GET",
            path="/socket",
            status_code=101,
            host="ws.example.com",
            server_port=80,
            websocket_upgrade=True,
        )
    ]

    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "WebSocket Upgrade Without TLS" in finding_titles


def test_pipeline_routes_nginx_websocket_events_to_baseline():
    events = [
        WebInfrastructureEvent(
            timestamp="2026-10-23T10:00:00Z",
            source="nginx",
            client_ip="192.0.2.10",
            method="GET",
            path="/private-ws",
            status_code=101,
            host="ws.example.com",
            server_port=443,
            tls_version="TLSv1.3",
            websocket_upgrade=True,
        )
    ]

    baseline = {
        "allowed_websocket_paths": ["/socket"],
    }

    result = run_web_infrastructure_detection_pipeline(
        events,
        web_security_baseline=baseline,
    )

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "WebSocket Path Deviates from Web Baseline"
        in finding_titles
    )
