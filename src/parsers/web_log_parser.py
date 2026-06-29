import re

from src.utils.event_utils import SecurityEvent


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) .* \[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<url>.*?) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status>\d{3}) (?P<size>\d+) '
    r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
)


def parse_web_log(file_path: str) -> list[SecurityEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = LOG_PATTERN.match(line)

            if not match:
                continue

            data = match.groupdict()

            event = SecurityEvent(
                timestamp=data["timestamp"],
                source="Web",
                event_type=data["method"],
                severity="low",
                src_ip=data["ip"],
                dst_ip="",
                src_port=0,
                dst_port=80,
                protocol="HTTP",
                hostname="web-server",
                username="",
                raw_event=line.strip(),
            )

            events.append(event)

    return events