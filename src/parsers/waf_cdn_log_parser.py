import json

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)

from src.parsers.parser_diagnostics import ParserDiagnostics

from src.security.redaction import redact_data


def parse_waf_cdn_log(
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

            status_value = data.get("status_code", 0)

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

            if status_code is None or status_code < 0:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_status_code",
                        raw_record=raw_record,
                    )
                continue

            string_fields = (
                "timestamp",
                "client_ip",
                "method",
                "path",
                "protocol",
                "host",
                "request_id",
                "trace_id",
                "user_agent",
                "tls_version",
                "sni",
                "provider",
                "action",
                "rule_name",
                "rule_category",
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

            raw_rule_id = data.get("rule_id")

            if raw_rule_id is None:
                rule_id = ""

            elif isinstance(raw_rule_id, str):
                rule_id = raw_rule_id

            elif (
                type(raw_rule_id) is int
                and raw_rule_id >= 0
            ):
                rule_id = str(raw_rule_id)

            else:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_rule_id",
                        raw_record=raw_record,
                    )
                continue

            data = redact_data(data)

            rule_id = redact_data({
                "rule_id": rule_id,
            })["rule_id"]

            events.append(
                WebInfrastructureEvent(
                    timestamp=data.get("timestamp", ""),
                    source="waf_cdn",
                    client_ip=data.get("client_ip", ""),
                    method=data.get("method", ""),
                    path=data.get("path", ""),
                    status_code=status_code,
                    protocol=data.get(
                        "protocol",
                        "HTTP/1.1",
                    ),
                    host=data.get("host", ""),
                    virtual_host=data.get("host", ""),
                    request_id=data.get("request_id", ""),
                    trace_id=data.get("trace_id", ""),
                    user_agent=data.get("user_agent", ""),
                    tls_version=data.get("tls_version", ""),
                    sni=data.get("sni", ""),
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
                    metadata={
                        "provider": data.get("provider", ""),
                        "waf_action": data.get("action", ""),
                        "waf_rule_id": rule_id,
                        "waf_rule_name": data.get(
                            "rule_name",
                            "",
                        ),
                        "waf_rule_category": data.get(
                            "rule_category",
                            "",
                        ),
                    },
                )
            )

            if diagnostics is not None:
                diagnostics.accept()

    return events