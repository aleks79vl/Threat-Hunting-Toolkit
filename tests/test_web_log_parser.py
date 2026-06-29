from src.parsers.web_log_parser import parse_web_log


def test_parse_web_log_returns_events():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    assert len(events) == 11


def test_first_event():
    event = parse_web_log(
        "data/raw/web/apache_access.log"
    )[0]

    assert event.source == "Web"
    assert event.src_ip == "192.168.1.10"
    assert event.protocol == "HTTP"


def test_sqlmap_event():
    event = parse_web_log("data/raw/web/apache_access.log")[4]

    assert "sqlmap" in event.raw_event.lower()


def test_xss_event():
    event = parse_web_log("data/raw/web/apache_access.log")[5]

    assert "<script>" in event.raw_event.lower()


def test_directory_traversal():
    event = parse_web_log("data/raw/web/apache_access.log")[6]

    assert "/etc/passwd" in event.raw_event