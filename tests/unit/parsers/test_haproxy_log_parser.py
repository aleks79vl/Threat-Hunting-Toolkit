from src.parsers.haproxy_log_parser import (
    parse_haproxy_http_log,
)


def test_parse_haproxy_http_log_returns_valid_events():
    events = parse_haproxy_http_log(
        "data/raw/web/haproxy_http.log"
    )

    assert len(events) == 2


def test_haproxy_event_contains_load_balancer_fields():
    event = parse_haproxy_http_log(
        "data/raw/web/haproxy_http.log"
    )[0]

    assert event.source == "haproxy"
    assert event.client_ip == "203.0.113.44"
    assert event.virtual_host == "public_frontend"
    assert event.upstream == "api_backend"
    assert event.backend == "api-01"
    assert event.status_code == 200
    assert event.response_size == 512
    assert event.response_time_ms == 21.0
    assert event.metadata["termination_state"] == "----"


def test_haproxy_parser_keeps_termination_state_for_error():
    event = parse_haproxy_http_log(
        "data/raw/web/haproxy_http.log"
    )[1]

    assert event.status_code == 503
    assert event.backend == "<NOSRV>"
    assert event.metadata["termination_state"] == "SC--"