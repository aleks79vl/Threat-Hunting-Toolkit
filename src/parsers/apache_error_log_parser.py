import re

from src.models.web_infrastructure_event import (WebInfrastructureEvent,)


HEADER_PATTERN = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\] "
    r"\[(?P<module>[^:\]]+):(?P<level>[^\]]+)\]"
)

CLIENT_PATTERN = re.compile(
    r"\[client (?P<client>[^\]]+)\]"
)

ERROR_CODE_PATTERN = re.compile(
    r"\b(?P<error_code>AH\d{5})\b"
)


def _extract_client_ip(client_value: str) -> str:
    host, separator, port = client_value.rpartition(":")

    if separator and port.isdigit():
        return host

    return client_value


def parse_apache_error_log(
    file_path: str,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            header_match = HEADER_PATTERN.match(line)

            if not header_match:
                continue

            data = header_match.groupdict()
            client_match = CLIENT_PATTERN.search(line)
            error_code_match = ERROR_CODE_PATTERN.search(line)

            client_ip = (
                _extract_client_ip(client_match.group("client"))
                if client_match
                else ""
            )

            events.append(
                WebInfrastructureEvent(
                    timestamp=data["timestamp"],
                    source="apache_error",
                    client_ip=client_ip,
                    method="",
                    path="",
                    status_code=0,
                    raw_event=line.strip(),
                    metadata={
                        "apache_module": data["module"],
                        "error_level": data["level"],
                        "error_code": (
                            error_code_match.group("error_code")
                            if error_code_match
                            else ""
                        ),
                    },
                )
            )

    return events