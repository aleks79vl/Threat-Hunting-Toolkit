from src.parsers.waf_cdn_log_parser import (
    parse_waf_cdn_log,
)


def test_parse_waf_cdn_log_returns_valid_events():
    events = parse_waf_cdn_log(
        "data/raw/web/waf_cdn_events.jsonl"
    )

    assert len(events) == 3


def test_waf_event_contains_normalized_security_metadata():
    event = parse_waf_cdn_log(
        "data/raw/web/waf_cdn_events.jsonl"
    )[0]

    assert event.source == "waf_cdn"
    assert event.request_id == "waf-req-001"
    assert event.trace_id == "waf-trace-001"
    assert event.tls_version == "TLSv1.3"
    assert event.sni == "api.example.com"
    assert event.metadata["provider"] == "cloudflare"
    assert event.metadata["waf_action"] == "block"
    assert event.metadata["waf_rule_id"] == "100173"
    assert event.metadata["waf_rule_category"] == "sqli"


def test_waf_parser_does_not_store_raw_log_line():
    event = parse_waf_cdn_log(
        "data/raw/web/waf_cdn_events.jsonl"
    )[0]

    assert event.raw_event == ""

def test_waf_cdn_parser_preserves_request_and_response_headers(tmp_path):
    log_file = tmp_path / "waf_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/news",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":{"X-Original-URL":"/admin"},'
        '"response_headers":{"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {
        "X-Original-URL": "/admin",
    }
    assert events[0].response_headers == {
        "Cache-Control": "public, max-age=300",
    }

def test_waf_cdn_parser_redacts_sensitive_headers(tmp_path):
    log_file = tmp_path / "waf_sensitive_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/account",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Authorization":"Bearer secret-token-123",'
        '"Cookie":"session=secret-session-456"},'
        '"response_headers":{'
        '"Set-Cookie":"session=secret-response-789"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1

    event = events[0]

    assert "secret-token-123" not in event.request_headers["Authorization"]
    assert "secret-session-456" not in event.request_headers["Cookie"]
    assert "secret-response-789" not in event.response_headers["Set-Cookie"]

def test_waf_cdn_parser_ignores_invalid_header_fields(tmp_path):
    log_file = tmp_path / "waf_invalid_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/health",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":["invalid", "headers"],'
        '"response_headers":null}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {}
    assert events[0].response_headers == {}

def test_waf_cdn_parser_filters_invalid_header_values(tmp_path):
    log_file = tmp_path / "waf_invalid_header_values.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/health",'
        '"status_code":200,'
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

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1

    assert events[0].request_headers == {
        "Accept": "application/json",
    }

    assert events[0].response_headers == {
        "Cache-Control": "no-store",
    }
