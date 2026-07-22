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