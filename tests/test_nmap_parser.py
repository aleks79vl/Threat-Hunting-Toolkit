from src.parsers.nmap_parser import parse_nmap_xml


def test_parse_nmap_xml_returns_events():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    assert len(events) == 3


def test_parse_nmap_xml_detects_host_ip():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    ips = [event.src_ip for event in events]

    assert "192.168.1.10" in ips
    assert "192.168.1.77" in ips


def test_parse_nmap_xml_detects_open_ports():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")

    ports = [event.dst_port for event in events]

    assert 22 in ports
    assert 445 in ports
    assert 3389 in ports


def test_parse_nmap_xml_returns_security_event_fields():
    events = parse_nmap_xml("data/raw/network/nmap_scan.xml")
    event = events[0]

    assert event.source == "nmap"
    assert event.event_type == "open_port"
    assert event.protocol == "TCP"