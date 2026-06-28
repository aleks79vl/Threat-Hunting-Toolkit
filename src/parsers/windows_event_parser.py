import csv

from src.utils.event_utils import SecurityEvent


def parse_windows_events(file_path: str) -> list[SecurityEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            event_id = row["event_id"]
            username = row["username"]
            computer = row["computer"]
            src_ip = row["src_ip"]
            process_name = row["process_name"]
            message = row["message"]

            event = SecurityEvent(
                timestamp=row["timestamp"],
                source="Windows",
                event_type=event_id,
                severity="low",
                src_ip=src_ip,
                dst_ip="",
                src_port=0,
                dst_port=0,
                protocol="",
                hostname=computer,
                username=username,
                raw_event=message,
            )

            events.append(event)

    return events