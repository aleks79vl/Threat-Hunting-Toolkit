from src.parsers.nginx_json_log_parser import (
    parse_nginx_json_log,
)


def test_parse_nginx_json_log_returns_valid_events():
    events = parse_nginx_json_log(
        "data/raw/web/nginx_access.jsonl"
    )

    assert len(events) == 2


def test_nginx_event_contains_infrastructure_fields():
    event = parse_nginx_json_log(
        "data/raw/web/nginx_access.jsonl"
    )[0]

    assert event.source == "nginx"
    assert event.request_id == "req-001"
    assert event.trace_id == "trace-001"
    assert event.virtual_host == "api.example.com"
    assert event.upstream == "users_backend"
    assert event.backend == "10.0.1.15:8080"
    assert event.response_size == 2048
    assert event.response_time_ms == 125.0
    assert event.forwarded_for == [
        "198.51.100.10",
        "10.0.0.5",
    ]


def test_nginx_event_detects_websocket_upgrade():
    event = parse_nginx_json_log(
        "data/raw/web/nginx_access.jsonl"
    )[1]

    assert event.websocket_upgrade is True
    assert event.status_code == 101
    assert event.tls_version == "TLSv1.3"