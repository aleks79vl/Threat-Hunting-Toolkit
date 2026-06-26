import xml.etree.ElementTree as ET

from src.utils.event_utils import SecurityEvent


def parse_nmap_xml(file_path: str) -> list[SecurityEvent]:
    events = []

    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall("host"):
        address_element = host.find("address")
        if address_element is None:
            continue

        host_ip = address_element.get("addr", "")

        hostname = ""
        hostname_element = host.find("hostnames/hostname")
        if hostname_element is not None:
            hostname = hostname_element.get("name", "")

        for port in host.findall("ports/port"):
            protocol = port.get("protocol", "")
            port_id = int(port.get("portid", 0))

            state_element = port.find("state")
            if state_element is None or state_element.get("state") != "open":
                continue

            service_name = ""
            service_element = port.find("service")
            if service_element is not None:
                service_name = service_element.get("name", "")

            event = SecurityEvent(
                timestamp="",
                source="nmap",
                event_type="open_port",
                severity="low",
                src_ip=host_ip,
                dst_port=port_id,
                protocol=protocol.upper(),
                hostname=hostname,
                raw_event=f"Nmap detected open port {port_id}/{protocol} service={service_name}"
            )

            events.append(event)

    return events