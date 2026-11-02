"""Firewall log parser with record-level error handling."""

from src.utils.event_utils import SecurityEvent
from src.parsers.parser_diagnostics import ParserDiagnostics


def parse_firewall_log(
    file_path: str,
    *,
    diagnostics: ParserDiagnostics | None = None,
) -> list[SecurityEvent]:
    """Parse firewall records without aborting on malformed lines."""

    events: list[SecurityEvent] = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 7:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="too_few_fields",
                    )
                continue

            timestamp = f"{parts[0]} {parts[1]}"
            action = parts[2]
            protocol = parts[3]
            src_ip = parts[4]
            dst_ip = parts[5]

            try:
                dst_port = int(parts[6])
            except ValueError:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_port",
                    )
                continue

            if not 0 <= dst_port <= 65535:
                if diagnostics is not None:
                    diagnostics.reject(
                        line_number=line_number,
                        reason="invalid_port_range",
                    )
                continue

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

            if diagnostics is not None:
                diagnostics.accept()

    return events
