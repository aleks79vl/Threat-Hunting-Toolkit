from src.models.network_event import NetworkEvent


def test_create_network_event_with_all_fields():
    event = NetworkEvent(
        timestamp="2026-07-04 21:00:00",
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        protocol="DNS",
        src_port="5353",
        dst_port="53",
        dns_query="example.com",
        http_host="",
        http_uri="",
    )

    assert event.timestamp == "2026-07-04 21:00:00"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "8.8.8.8"
    assert event.protocol == "DNS"
    assert event.dns_query == "example.com"


def test_create_network_event_with_defaults():
    event = NetworkEvent(timestamp="2026-07-04 21:00:00",)

    assert event.src_ip == ""
    assert event.dst_ip == ""
    assert event.src_mac == ""
    assert event.dst_mac == ""
    assert event.protocol == ""
    assert event.src_port == ""
    assert event.dst_port == ""
    assert event.dns_query == ""
    assert event.http_host == ""
    assert event.http_uri == ""