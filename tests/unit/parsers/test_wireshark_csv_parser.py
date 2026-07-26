from src.parsers.wireshark_csv_parser import parse_wireshark_csv


def test_parse_wireshark_csv_returns_events():
    events = parse_wireshark_csv(
        "tests/fixtures/wireshark_sample.csv"
    )

    assert len(events) == 2


def test_parse_wireshark_csv_dns_event():
    events = parse_wireshark_csv(
        "tests/fixtures/wireshark_sample.csv"
    )

    dns_event = events[0]

    assert dns_event.protocol == "DNS"
    assert dns_event.src_ip == "192.168.1.10"
    assert dns_event.dst_ip == "8.8.8.8"
    assert dns_event.src_port == "5353"
    assert dns_event.dst_port == "53"
    assert dns_event.dns_query == "example.com"


def test_parse_wireshark_csv_http_event():
    events = parse_wireshark_csv(
        "tests/fixtures/wireshark_sample.csv"
    )

    http_event = events[1]

    assert http_event.protocol == "HTTP"
    assert http_event.src_ip == "192.168.1.20"
    assert http_event.dst_ip == "93.184.216.34"
    assert http_event.src_port == "51514"
    assert http_event.dst_port == "80"
    assert http_event.http_host == "example.com"
    assert http_event.http_uri == "/index.html"