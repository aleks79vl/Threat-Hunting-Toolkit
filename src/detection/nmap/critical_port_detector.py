import json

from src.utils.event_utils import SecurityEvent


def load_critical_ports(config_path: str) -> dict:
    """
    Load critical ports configuration.

    Returns:
        Dictionary:
        {
            22: {...},
            445: {...},
            ...
        }
    """
    with open(config_path, "r") as file:
        data = json.load(file)

    return {
        port["port"]: port
        for port in data["critical_ports"]
    }


def detect_critical_ports(
    events: list[SecurityEvent],
    config_path: str
) -> list[SecurityEvent]:

    critical_ports = load_critical_ports(config_path)

    alerts = []

    for event in events:

        if event.dst_port in critical_ports:

            severity = critical_ports[event.dst_port]["severity"]
            service = critical_ports[event.dst_port]["service"]

            event.severity = severity

            event.raw_event += (
                f" | Critical Service: {service}"
            )

            alerts.append(event)

    return alerts