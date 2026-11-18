import json
import math

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
    redact_sensitive_headers,
)
from src.parsers.parser_diagnostics import ParserDiagnostics
from src.security.redaction import redact_data


def _split_forwarded_for(value: str) -> list[str]:
    return [
        ip.strip()
        for ip in value.split(",")
        if ip.strip()
    ]


def parse_nginx_json_log(
    file_path: str,
    *,
    diagnostics: ParserDiagnostics | None = None,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            if not line.strip():
                continue

            raw_record = line.rstrip("\r\n")

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_json",
                        raw_record=raw_record,
                    )
                continue

            if not isinstance(data, dict):
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_root_type",
                        raw_record=raw_record,
                    )
                continue

            string_fields = (

                "time",
                "remote_addr",
                "request_method",
                "request_uri",
                "server_protocol",
                "host",
                "server_name",
                "server_addr",
                "request_id",
                "trace_id",
                "session_id_hash",
                "http_x_forwarded_for",
                "upstream",
                "upstream_addr",
                "http_user_agent",
                "http_referer",
                "http_upgrade",
                "ssl_protocol",
                "ssl_server_name",
            )

            invalid_field_type = any(
                field_name in data
                and not isinstance(data[field_name], str)
                for field_name in string_fields
            )

            if invalid_field_type:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_field_type",
                        raw_record=raw_record,
                    )
                continue

            status_value = data.get("status", 0)

            if type(status_value) is int:
                status_code = status_value

            elif (
                isinstance(status_value, str)
                and status_value.isascii()
                and status_value.isdecimal()
            ):
                try:
                    status_code = int(status_value)
                except ValueError:
                    status_code = None

            else:
                status_code = None

            if status_code is None:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_status",
                        raw_record=raw_record,
                    )
                continue

            port_value = data.get("server_port", 0)

            if type(port_value) is int:
                server_port = port_value

            elif (
                isinstance(port_value, str)
                and port_value.isascii()
                and port_value.isdecimal()
            ):
                try:
                    server_port = int(port_value)
                except ValueError:
                    server_port = None

            else:
                server_port = None

            if (
                server_port is None
                or not 0 <= server_port <= 65535
            ):
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_server_port",
                        raw_record=raw_record,
                    )
                continue

            size_value = data.get("bytes_sent", 0)

            if type(size_value) is int:
                response_size = size_value

            elif (
                isinstance(size_value, str)
                and size_value.isascii()
                and size_value.isdecimal()
            ):
                try:
                    response_size = int(size_value)
                except ValueError:
                    response_size = None

            else:
                response_size = None

            if response_size is None or response_size < 0:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_response_size",
                        raw_record=raw_record,
                    )
                continue

            response_time_ms = None

            if "request_time" in data:
                raw_request_time = data["request_time"]

                try:
                    if type(raw_request_time) not in (
                        int,
                        float,
                        str,
                    ):
                        raise ValueError(
                            "invalid request time type"
                        )

                    request_time = float(raw_request_time)

                    response_time_ms = request_time * 1000

                    if (
                        not math.isfinite(request_time)
                        or request_time < 0
                        or not math.isfinite(response_time_ms)
                    ):
                        raise ValueError(
                            "invalid request time value"
                        )

                except (ValueError, OverflowError):
                    if diagnostics is not None:
                        diagnostics.reject(
                            line_number=line_number,
                            reason="invalid_request_time",
                            raw_record=raw_record,
                        )
                    continue

            upstream_value = data.get("upstream_status")

            if upstream_value is None or upstream_value == "-":
                upstream_status = None

            else:
                try:
                    if type(upstream_value) is int:
                        upstream_status = upstream_value

                    elif (
                        isinstance(upstream_value, str)
                        and upstream_value.isascii()
                        and upstream_value.isdecimal()
                    ):
                        upstream_status = int(upstream_value)

                    else:
                        raise ValueError(
                            "invalid upstream status"
                        )

                except ValueError:
                    if diagnostics is not None:
                        diagnostics.reject(
                            line_number=line_number,
                            reason="invalid_upstream_status",
                            raw_record=raw_record,
                        )
                    continue

                if upstream_status == 0:
                    upstream_status = None

            sanitized_data = data.copy()

            for header_field in (
                "request_headers",
                "response_headers",
            ):
                if header_field not in data:
                    continue

                headers = data[header_field]

                if not isinstance(headers, dict):
                    sanitized_data[header_field] = {}
                    continue

                valid_headers = {
                    name: value
                    for name, value in headers.items()
                    if isinstance(name, str)
                    and isinstance(value, str)
                }

                sanitized_data[header_field] = (
                    redact_sensitive_headers(valid_headers)
                )

            sanitized_data = redact_data(sanitized_data)

            events.append(
                WebInfrastructureEvent(
                    timestamp=data.get("time", ""),
                    source="nginx",
                    client_ip=data.get("remote_addr", ""),
                    method=data.get("request_method", ""),
                    path=sanitized_data.get("request_uri", ""),
                    status_code=status_code,
                    protocol=data.get(
                        "server_protocol",
                        "HTTP/1.1",
                    ),
                    host=data.get("host", ""),
                    virtual_host=data.get("server_name", ""),
                    server_ip=data.get("server_addr", ""),
                    server_port=server_port,
                    request_id=data.get("request_id", ""),
                    trace_id=data.get("trace_id", ""),
                    forwarded_for=_split_forwarded_for(
                        data.get("http_x_forwarded_for", "")
                    ),
                    upstream=data.get("upstream", ""),
                    backend=data.get("upstream_addr", ""),
                    upstream_status=upstream_status,
                    response_size=response_size,
                    response_time_ms=response_time_ms,
                    user_agent=sanitized_data.get("http_user_agent", ""),
                    referer=sanitized_data.get("http_referer", ""),
                    request_headers=(
                        {
                            name: value
                            for name, value in data["request_headers"].items()
                            if isinstance(name, str) and isinstance(value, str)
                        }
                        if isinstance(data.get("request_headers"), dict)
                        else {}
                    ),
                    response_headers=(
                        {
                            name: value
                            for name, value in data["response_headers"].items()
                            if isinstance(name, str) and isinstance(value, str)
                        }
                        if isinstance(data.get("response_headers"), dict)
                        else {}
                    ),
                    tls_version=data.get("ssl_protocol", ""),
                    sni=data.get("ssl_server_name", ""),
                    websocket_upgrade=(
                        data.get("http_upgrade", "").lower()
                        == "websocket"
                    ),
                    raw_event=json.dumps(
                        sanitized_data,
                        ensure_ascii=False,
                    ),
                    metadata={
                        "session_id_hash": data.get(
                            "session_id_hash",
                            "",
                        ),
                    },

                )
            )

            if diagnostics is not None:
                diagnostics.accept()

    return events
