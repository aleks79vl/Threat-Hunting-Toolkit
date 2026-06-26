import json

from src.utils.event_utils import SecurityEvent


def load_known_ips(config_path: str) -> set:
    with open(config_path, "r") as file:
        data = json.load(file)

    return {
        host["ip"]
        for host in data["known_hosts"]
    }


def detect_unknown_ips(events: list[SecurityEvent], config_path: str) -> list[SecurityEvent]:
    known_ips = load_known_ips(config_path)

    unknown_events = []

    for event in events:
        if event.src_ip not in known_ips:
            event.severity = "high"
            unknown_events.append(event)

    return unknown_events