from src.parsers.nginx_error_log_parser import (
    parse_nginx_error_log,
)


def test_parse_nginx_error_log_returns_valid_events():
    events = parse_nginx_error_log(
        "data/raw/web/nginx_error.log"
    )

    assert len(events) == 3


def test_nginx_error_event_contains_request_context():
    event = parse_nginx_error_log(
        "data/raw/web/nginx_error.log"
    )[0]

    assert event.source == "nginx_error"
    assert event.client_ip == "203.0.113.44"
    assert event.virtual_host == "portal.example.com"
    assert event.method == "GET"
    assert event.path == "/.env"
    assert event.metadata["nginx_level"] == "error"


def test_nginx_upstream_error_preserves_upstream():
    event = parse_nginx_error_log(
        "data/raw/web/nginx_error.log"
    )[1]

    assert event.upstream == "http://10.0.1.15:8080/api/users"
    assert event.client_ip == "198.51.100.23"
    assert event.virtual_host == "api.example.com"