import json

from src.detection.network_unknown_ip_detector import (
    detect_unknown_network_ips,
)
from src.models.network_event import NetworkEvent


def create_network_event(
    src_ip: str = "",
    dst_ip: str = "",
) -> NetworkEvent:
    return NetworkEvent(
        timestamp="1385452028.038401000",
        src_mac="08:2e:5f:11:50:cd",
        dst_mac="34:08:04:2e:a1:fd",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="TCP",
        src_port=45822,
        dst_port=443,
        dns_query="",
        http_host="",
        http_uri="",
    )


def test_detect_unknown_source_ip(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(json.dumps({"allowed_ips": ["10.0.0.3"]}),
        encoding="utf-8",)

    events = [
        create_network_event(src_ip="192.168.1.50",dst_ip="10.0.0.3",)
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert len(findings) == 1
    assert findings[0].ip == "192.168.1.50"
    assert findings[0].source == "PCAP Network Detection"


def test_detect_unknown_destination_ip(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(json.dumps({"allowed_ips": ["10.0.0.3"]}),
        encoding="utf-8",)

    events = [
        create_network_event(src_ip="10.0.0.3",dst_ip="173.194.112.47",)
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert len(findings) == 1
    assert findings[0].ip == "173.194.112.47"


def test_ignore_whitelisted_ips(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(
        json.dumps(
            {
                "allowed_ips": ["10.0.0.3","10.0.0.138",]
            }
        ),
        encoding="utf-8",
    )

    events = [
        create_network_event(src_ip="10.0.0.3",dst_ip="10.0.0.138",)
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert findings == []


def test_duplicate_unknown_ip_creates_single_finding(tmp_path):
    whitelist_file = tmp_path / "whitelist.json"

    whitelist_file.write_text(json.dumps({"allowed_ips": []}),
        encoding="utf-8",)

    events = [
        create_network_event(
            src_ip="192.168.1.50",
            dst_ip="",
        ),
        create_network_event(
            src_ip="192.168.1.50",
            dst_ip="",
        ),
        create_network_event(
            src_ip="192.168.1.50",
            dst_ip="",
        ),
    ]

    findings = detect_unknown_network_ips(events,str(whitelist_file),)

    assert len(findings) == 1
    assert findings[0].ip == "192.168.1.50"