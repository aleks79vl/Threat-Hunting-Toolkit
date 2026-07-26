from src.parsers.apache_error_log_parser import (
    parse_apache_error_log,
)


def test_parse_apache_error_log_returns_valid_events():
    events = parse_apache_error_log(
        "data/raw/web/apache_error.log"
    )

    assert len(events) == 3


def test_apache_error_event_contains_client_and_metadata():
    event = parse_apache_error_log(
        "data/raw/web/apache_error.log"
    )[0]

    assert event.source == "apache_error"
    assert event.client_ip == "203.0.113.44"
    assert event.metadata["apache_module"] == "core"
    assert event.metadata["error_level"] == "error"
    assert event.metadata["error_code"] == "AH00126"


def test_apache_proxy_error_preserves_proxy_module():
    event = parse_apache_error_log(
        "data/raw/web/apache_error.log"
    )[1]

    assert event.client_ip == "198.51.100.23"
    assert event.metadata["apache_module"] == "proxy"
    assert event.metadata["error_code"] == "AH00957"