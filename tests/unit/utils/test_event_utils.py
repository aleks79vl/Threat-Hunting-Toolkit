import json

from src.utils.event_utils import SecurityEvent


def test_security_event_creation():
    event = SecurityEvent(
        timestamp="2026-06-25 10:00:00",
        source="nmap",
        event_type="open_port",
        severity="medium",
        src_ip="192.168.1.10",
        dst_port=22,
        protocol="TCP",
        raw_event="Nmap scan detected open SSH port"
    )

    assert event.timestamp == "2026-06-25 10:00:00"
    assert event.source == "nmap"
    assert event.event_type == "open_port"
    assert event.severity == "medium"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_port == 22
    assert event.protocol == "TCP"


def test_security_event_to_dict():
    event = SecurityEvent(
        timestamp="2026-06-25 10:00:00",
        source="firewall",
        event_type="connection",
        severity="high",
        src_ip="192.168.1.50",
        dst_ip="192.168.1.10",
        dst_port=445,
        protocol="TCP"
    )

    event_dict = event.to_dict()

    assert isinstance(event_dict, dict)
    assert event_dict["source"] == "firewall"
    assert event_dict["event_type"] == "connection"
    assert event_dict["dst_port"] == 445


def test_security_event_to_json():
    event = SecurityEvent(
        timestamp="2026-06-25 10:00:00",
        source="windows",
        event_type="failed_login",
        severity="high",
        username="admin",
        raw_event="Event ID 4625"
    )

    event_json = event.to_json()
    parsed_json = json.loads(event_json)

    assert parsed_json["source"] == "windows"
    assert parsed_json["event_type"] == "failed_login"
    assert parsed_json["username"] == "admin"
