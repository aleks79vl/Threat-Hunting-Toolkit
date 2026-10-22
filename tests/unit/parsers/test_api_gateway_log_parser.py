from src.parsers.api_gateway_log_parser import (
    parse_api_gateway_log,
)


def test_parse_api_gateway_log_returns_valid_events():
    events = parse_api_gateway_log(
        "data/raw/web/api_gateway_access.jsonl"
    )

    assert len(events) == 3


def test_api_gateway_event_contains_auth_metadata():
    event = parse_api_gateway_log(
        "data/raw/web/api_gateway_access.jsonl"
    )[0]

    assert event.source == "api_gateway"
    assert event.request_id == "api-req-001"
    assert event.trace_id == "trace-api-001"
    assert event.response_time_ms == 28.4
    assert event.metadata["auth_status"] == "success"
    assert event.metadata["principal_id"] == "account-1001"
    assert (event.metadata["session_id_hash"]
    == "sha256:demo-session-1001")
    assert event.metadata["rate_limit_remaining"] == 99


def test_api_gateway_event_does_not_store_raw_log_line():
    event = parse_api_gateway_log(
        "data/raw/web/api_gateway_access.jsonl"
    )[0]

    assert event.raw_event == ""


def test_api_gateway_parser_preserves_request_and_response_headers(tmp_path):
    log_file = tmp_path / "api_gateway_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/news",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{"X-Original-URL":"/admin"},'
        '"response_headers":{"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))

    assert len(events) == 1

    assert events[0].request_headers == {
        "X-Original-URL": "/admin",
    }

    assert events[0].response_headers == {
        "Cache-Control": "public, max-age=300",
    }


def test_api_gateway_parser_redacts_sensitive_headers(tmp_path):
    log_file = tmp_path / "api_gateway_sensitive_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/account",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Authorization":"Bearer secret-token-123",'
        '"Cookie":"session=secret-session-456",'
        '"Accept":"application/json"},'
        '"response_headers":{'
        '"Set-Cookie":"session=secret-response-789"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))

    assert len(events) == 1

    event = events[0]

    assert event.request_headers["Authorization"] == "[REDACTED]"
    assert event.request_headers["Cookie"] == "[REDACTED]"
    assert event.response_headers["Set-Cookie"] == "[REDACTED]"

    assert event.request_headers["Accept"] == "application/json"


def test_api_gateway_parser_handles_invalid_header_types(tmp_path):
    log_file = tmp_path / "api_gateway_invalid_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/health",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":["invalid", "headers"],'
        '"response_headers":null}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))

    assert len(events) == 1
    assert events[0].request_headers == {}
    assert events[0].response_headers == {}


def test_api_gateway_parser_filters_invalid_header_values(tmp_path):
    log_file = tmp_path / "api_gateway_invalid_header_values.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/health",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Accept":"application/json",'
        '"Content-Length":123,'
        '"X-Test":["invalid"]},'
        '"response_headers":{'
        '"Cache-Control":"no-store",'
        '"Server":null}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))

    assert len(events) == 1

    assert events[0].request_headers == {
        "Accept": "application/json",
    }

    assert events[0].response_headers == {
        "Cache-Control": "no-store",
    }
