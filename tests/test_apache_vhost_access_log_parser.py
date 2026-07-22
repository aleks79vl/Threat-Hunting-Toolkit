from src.parsers.apache_access_log_parser import (
    parse_apache_vhost_access_log,
)


def test_parse_apache_vhost_access_log_returns_events():
    events = parse_apache_vhost_access_log(
        "data/raw/web/apache_vhost_access.log"
    )

    assert len(events) == 3


def test_apache_vhost_is_mapped_to_event():
    event = parse_apache_vhost_access_log(
        "data/raw/web/apache_vhost_access.log"
    )[1]

    assert event.virtual_host == "admin.example.com"
    assert event.client_ip == "203.0.113.15"
    assert event.method == "POST"
    assert event.status_code == 401


def test_apache_vhost_access_log_preserves_request_context():
    event = parse_apache_vhost_access_log(
        "data/raw/web/apache_vhost_access.log"
    )[2]

    assert event.virtual_host == "shop.example.com"
    assert event.path == "/product?id=42"
    assert event.referer == "https://shop.example.com/"