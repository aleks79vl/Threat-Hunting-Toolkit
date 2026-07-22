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