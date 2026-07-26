from src.models.network_event import NetworkEvent
from src.reporting.network_statistics import generate_network_statistics


def test_generate_network_statistics():
    events = [
        NetworkEvent(timestamp="1",protocol="DNS",dns_query="example.com",),
        NetworkEvent(timestamp="2",protocol="TCP",http_host="example.com",
                     http_uri="/index.html",),
        NetworkEvent(timestamp="3",protocol="DNS",dns_query="walla.co.il",),
    ]

    stats = generate_network_statistics(events)

    assert stats["total_network_events"] == 3
    assert stats["protocols"]["DNS"] == 2
    assert stats["protocols"]["TCP"] == 1
    assert stats["http_requests"] == 1
    assert "example.com" in stats["dns_queries"]
    assert "walla.co.il" in stats["dns_queries"]