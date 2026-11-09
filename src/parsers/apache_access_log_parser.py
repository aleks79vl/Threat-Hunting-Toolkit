import re

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)
from src.parsers.parser_diagnostics import ParserDiagnostics


APACHE_COMBINED_LOG_PATTERN = re.compile(
    r'(?P<client_ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.*?) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+|-) '
    r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
)

APACHE_VHOST_COMBINED_LOG_PATTERN = re.compile(
    r'(?P<virtual_host>\S+) '
    r'(?P<client_ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.*?) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+|-) '
    r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
)


def _parse_access_log(
    file_path: str,
    pattern: re.Pattern,
    *,
    diagnostics: ParserDiagnostics | None = None,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            if not line.strip():
                continue

            match = pattern.fullmatch(line.rstrip("\r\n"))

            if not match:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_log_format",
                    )
                continue

            data = match.groupdict()

            events.append(
                WebInfrastructureEvent(
                    timestamp=data["timestamp"],
                    source="apache",
                    client_ip=data["client_ip"],
                    method=data["method"],
                    path=data["path"],
                    status_code=int(data["status_code"]),
                    protocol=data["protocol"],
                    virtual_host=data.get("virtual_host", ""),
                    response_size=(
                        0
                        if data["response_size"] == "-"
                        else int(data["response_size"])
                    ),
                    referer=data["referer"],
                    user_agent=data["user_agent"],
                    raw_event=line.strip(),
                )
            )

            if diagnostics is not None:
                diagnostics.accept()

    return events


def parse_apache_access_log(
    file_path: str,
    *,
    diagnostics: ParserDiagnostics | None = None,
) -> list[WebInfrastructureEvent]:
    return _parse_access_log(
        file_path,
        APACHE_COMBINED_LOG_PATTERN,
        diagnostics=diagnostics,
    )


def parse_apache_vhost_access_log(
    file_path: str,
    *,
    diagnostics: ParserDiagnostics | None = None,
) -> list[WebInfrastructureEvent]:
    return _parse_access_log(
        file_path,
        APACHE_VHOST_COMBINED_LOG_PATTERN,
        diagnostics=diagnostics,
    )
