from src.parsers.apache_access_log_parser import (
    parse_apache_access_log,
)


def test_parse_apache_access_log_returns_events():
    events = parse_apache_access_log(
        "data/raw/web/apache_access.log"
    )

    assert len(events) == 11


def test_apache_access_event_contains_request_details():
    event = parse_apache_access_log(
        "data/raw/web/apache_access.log"
    )[0]

    assert event.source == "apache"
    assert event.client_ip == "192.168.1.10"
    assert event.method == "GET"
    assert event.path == "/"
    assert event.protocol == "HTTP/1.1"
    assert event.status_code == 200
    assert event.response_size == 1024


def test_apache_access_event_preserves_user_agent():
    event = parse_apache_access_log(
        "data/raw/web/apache_access.log"
    )[4]

    assert event.user_agent == "sqlmap/1.7"
    assert "OR" in event.path