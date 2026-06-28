from src.utils.event_utils import SecurityEvent


def parse_firewall_log(file_path: str) -> list[SecurityEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            timestamp = f"{parts[0]} {parts[1]}"
            action = parts[2]
            protocol = parts[3]
            src_ip = parts[4]
            dst_ip = parts[5]
            dst_port = int(parts[6])

            event = SecurityEvent(
                timestamp=timestamp,
                source="Firewall",
                event_type=action,
                severity="low",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=0,
                dst_port=dst_port,
                protocol=protocol,
                hostname="unknown",
                username="",
                raw_event=line,
            )

            events.append(event)

    return events