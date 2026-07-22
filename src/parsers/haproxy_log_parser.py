import re

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


HAPROXY_HTTP_LOG_PATTERN = re.compile(
    r"^(?P<client_ip>[^:\s]+):\d+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"(?P<frontend>\S+)\s+"
    r"(?P<upstream>\S+)/(?P<backend>\S+)\s+"
    r"(?P<timers>\S+)\s+"
    r"(?P<status_code>\d{3})\s+"
    r"(?P<response_size>\d+)\s+"
    r"\S+\s+\S+\s+"
    r"(?P<termination_state>\S+).*"
    r"\"(?P<method>\S+)\s+"
    r"(?P<path>\S+)\s+"
    r"(?P<protocol>HTTP/\S+)\"$"
)


def _as_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except ValueError:
        return default


def _response_time_ms(timers: str) -> float | None:
    timer_values = timers.split("/")

    if not timer_values:
        return None

    try:
        return float(timer_values[-1])
    except ValueError:
        return None


def parse_haproxy_http_log(
    file_path: str,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = HAPROXY_HTTP_LOG_PATTERN.match(
                line.strip()
            )

            if not match:
                continue

            data = match.groupdict()

            events.append(
                WebInfrastructureEvent(
                    timestamp=data["timestamp"],
                    source="haproxy",
                    client_ip=data["client_ip"],
                    method=data["method"],
                    path=data["path"],
                    status_code=_as_int(
                        data["status_code"]
                    ),
                    protocol=data["protocol"],
                    host=data["frontend"],
                    virtual_host=data["frontend"],
                    upstream=data["upstream"],
                    backend=data["backend"],
                    response_size=_as_int(
                        data["response_size"]
                    ),
                    response_time_ms=_response_time_ms(
                        data["timers"]
                    ),
                    raw_event=line.strip(),
                    metadata={
                        "load_balancer": "haproxy",
                        "termination_state": data[
                            "termination_state"
                        ],
                    },
                )
            )

    return events