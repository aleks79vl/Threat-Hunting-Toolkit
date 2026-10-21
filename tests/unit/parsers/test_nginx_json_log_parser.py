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

def test_nginx_parser_preserves_request_and_response_headers(tmp_path):
    log_file = tmp_path / "nginx_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/news",'
        '"status":200,'
        '"host":"example.com",'
        '"request_headers":{"X-Original-URL":"/admin"},'
        '"response_headers":{"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 1
    assert events[0].request_headers == {
        "X-Original-URL": "/admin",
    }
    assert events[0].response_headers == {
        "Cache-Control": "public, max-age=300",
    }

def test_nginx_parser_redacts_sensitive_headers(tmp_path):
    log_file = tmp_path / "nginx_sensitive_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"request_headers":{'
        '"Authorization":"Bearer secret-token",'
        '"Cookie":"session=secret-value",'
        '"X-Original-URL":"/admin"},'
        '"response_headers":{'
        '"Set-Cookie":"session=another-secret",'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 1

    assert events[0].request_headers["Authorization"] == "[REDACTED]"
    assert events[0].request_headers["Cookie"] == "[REDACTED]"
    assert events[0].response_headers["Set-Cookie"] == "[REDACTED]"

    assert events[0].request_headers["X-Original-URL"] == "/admin"
    assert (
        events[0].response_headers["Cache-Control"]
        == "public, max-age=300"
    )

def test_nginx_parser_handles_invalid_header_types(tmp_path):
    log_file = tmp_path / "nginx_invalid_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"request_headers":["invalid", "headers"],'
        '"response_headers":{"Cache-Control":"no-store"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {}
    assert events[0].response_headers == {
        "Cache-Control": "no-store",
    }

def test_nginx_parser_filters_invalid_header_values(tmp_path):
    log_file = tmp_path / "nginx_invalid_header_values.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"request_headers":{'
        '"X-Original-URL":["/admin"],'
        '"Accept":"application/json"},'
        '"response_headers":{'
        '"Cache-Control":null,'
        '"X-Trace-ID":"trace-123"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {
        "Accept": "application/json",
    }
    assert events[0].response_headers == {
        "X-Trace-ID": "trace-123",
    }
