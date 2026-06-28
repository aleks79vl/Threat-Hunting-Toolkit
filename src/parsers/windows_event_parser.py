import csv

from src.utils.event_utils import SecurityEvent


def parse_windows_events(file_path: str) -> list[SecurityEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            message = row["message"]
            process_name = row["process_name"]
            raw_event = f"{message}: {process_name}"

            event = SecurityEvent(
                timestamp=row["timestamp"],
                source="Windows",
                event_type=row["event_id"],
                severity="low",
                src_ip=row["src_ip"],
                dst_ip="",
                src_port=0,
                dst_port=0,
                protocol="",
                hostname=row["computer"],
                username=row["username"],
                raw_event=raw_event,
            )

            events.append(event)

    return events
