import re

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


HEADER_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>[^\]]+)\] "
    r"(?P<details>.*)$"
)

CLIENT_PATTERN = re.compile(r"client: (?P<client_ip>[^,]+)")
SERVER_PATTERN = re.compile(r"server: (?P<server>[^,]+)")
REQUEST_PATTERN = re.compile(
    r'request: "(?P<method>\S+) '
    r'(?P<path>.*?) '
    r'(?P<protocol>HTTP/\d\.\d)"'
)
UPSTREAM_PATTERN = re.compile(r'upstream: "(?P<upstream>[^"]+)"')
HOST_PATTERN = re.compile(r'host: "(?P<host>[^"]+)"')


def _group_or_empty(
    match: re.Match | None,
    name: str,
) -> str:
    return match.group(name) if match else ""


def parse_nginx_error_log(
    file_path: str,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            header_match = HEADER_PATTERN.match(line)

            if not header_match:
                continue

            data = header_match.groupdict()
            details = data["details"]

            request_match = REQUEST_PATTERN.search(details)
            client_match = CLIENT_PATTERN.search(details)
            server_match = SERVER_PATTERN.search(details)
            upstream_match = UPSTREAM_PATTERN.search(details)
            host_match = HOST_PATTERN.search(details)

            message = details.split(", client:")[0]

            events.append(
                WebInfrastructureEvent(
                    timestamp=data["timestamp"],
                    source="nginx_error",
                    client_ip=_group_or_empty(
                        client_match,
                        "client_ip",
                    ),
                    method=_group_or_empty(
                        request_match,
                        "method",
                    ),
                    path=_group_or_empty(
                        request_match,
                        "path",
                    ),
                    status_code=0,
                    protocol=_group_or_empty(
                        request_match,
                        "protocol",
                    ),
                    host=_group_or_empty(host_match, "host"),
                    virtual_host=_group_or_empty(
                        server_match,
                        "server",
                    ),
                    upstream=_group_or_empty(
                        upstream_match,
                        "upstream",
                    ),
                    raw_event=line.strip(),
                    metadata={
                        "nginx_level": data["level"],
                        "message": message,
                    },
                )
            )

    return events