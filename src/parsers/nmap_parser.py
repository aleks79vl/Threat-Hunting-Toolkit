import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from src.utils.event_utils import SecurityEvent


def _normalize_nmap_epoch(value: str | None) -> str | None:
    """
    Convert Nmap Unix epoch seconds to UTC ISO 8601.

    Return None if the timestamp is missing or invalid.
    """
    if not value or not value.isascii() or not value.isdecimal():
        return None

    try:
        return datetime.fromtimestamp(
            int(value),
            tz=timezone.utc,
        ).isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        return None


def parse_nmap_xml(file_path: str) -> list[SecurityEvent]:
    events = []

    tree = ET.parse(file_path)
    root = tree.getroot()

    # Overall scan interval.
    scan_start = _normalize_nmap_epoch(
        root.get("start")
    )

    finished = root.find("runstats/finished")

    scan_end = _normalize_nmap_epoch(
        finished.get("time") if finished is not None else None
    )

    scan_interval_valid = (
        scan_start is not None
        and scan_end is not None
        and scan_start <= scan_end
    )

    for host in root.findall("host"):

        # Host-specific observation interval.
        host_start = _normalize_nmap_epoch(
            host.get("starttime")
        )

        host_end = _normalize_nmap_epoch(
            host.get("endtime")
        )

        if (
            host_start is not None
            and host_end is not None
            and host_start <= host_end
        ):
            observation_start = host_start
            observation_end = host_end
            observation_scope = "host"

        elif scan_interval_valid:
            observation_start = scan_start
            observation_end = scan_end
            observation_scope = "scan"

        else:
            observation_start = None
            observation_end = None
            observation_scope = None

        # Host information.
        address_element = host.find("address")
        if address_element is None:
            continue

        host_ip = address_element.get("addr", "")

        hostname = ""
        hostname_element = host.find("hostnames/hostname")
        if hostname_element is not None:
            hostname = hostname_element.get("name", "")

        # Open ports.
        for port in host.findall("ports/port"):
            protocol = port.get("protocol", "")
            port_id = int(port.get("portid", 0))

            state_element = port.find("state")
            if (
                state_element is None
                or state_element.get("state") != "open"
            ):
                continue

            service_name = ""
            service_element = port.find("service")
            if service_element is not None:
                service_name = service_element.get("name", "")

            event = SecurityEvent(
                timestamp="",
                observation_start=observation_start,
                observation_end=observation_end,
                observation_scope=observation_scope,
                source="nmap",
                event_type="open_port",
                severity="low",
                src_ip=host_ip,
                dst_port=port_id,
                protocol=protocol.upper(),
                hostname=hostname,
                raw_event=(
                    f"Nmap detected open port "
                    f"{port_id}/{protocol} "
                    f"service={service_name}"
                ),
            )

            events.append(event)

    return events
