from src.detection.mitm_detector import detect_arp_spoofing
from src.models.network_event import NetworkEvent


def create_arp_event(
    arp_src_ip: str,
    arp_src_mac: str,
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        protocol="ARP",
        arp_src_ip=arp_src_ip,
        arp_src_mac=arp_src_mac,
    )


def test_detect_arp_spoofing_when_ip_has_multiple_macs():
    events = [
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:aa:aa:aa:aa:aa",
        ),
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="bb:bb:bb:bb:bb:bb",
        ),
    ]

    findings = detect_arp_spoofing(events)

    assert len(findings) == 1
    assert findings[0].title == "Possible ARP Spoofing Detected"
    assert findings[0].severity == "high"
    assert findings[0].ip == "10.0.0.1"


def test_ignore_normal_arp_mapping():
    events = [
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:aa:aa:aa:aa:aa",
        ),
        create_arp_event(
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:aa:aa:aa:aa:aa",
        ),
    ]

    findings = detect_arp_spoofing(events)

    assert findings == []


def test_ignore_empty_events():
    findings = detect_arp_spoofing([])

    assert findings == []