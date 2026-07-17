import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.models.physical_event import PhysicalEvent


def _parse_timestamp(value: str) -> datetime:
    """
    Parse an ISO 8601 timestamp.

    Both formats are supported:

    2026-07-16T10:00:00
    2026-07-16T10:00:00Z
    """

    normalized_value = value.replace("Z", "+00:00")

    return datetime.fromisoformat(normalized_value)


def _build_physical_event(
    raw_event: dict[str, Any],
) -> PhysicalEvent:
    required_fields = {
        "timestamp",
        "event_type",
        "device_type",
        "device_name",
        "device_id",
    }

    missing_fields = required_fields - raw_event.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))

        raise ValueError(
            f"Physical event is missing required fields: {missing}"
        )

    return PhysicalEvent(
        timestamp=_parse_timestamp(
            str(raw_event["timestamp"])
        ),
        event_type=str(raw_event["event_type"]),
        device_type=str(raw_event["device_type"]),
        device_name=str(raw_event["device_name"]),
        device_id=str(raw_event["device_id"]),
        vendor=raw_event.get("vendor"),
        serial_number=raw_event.get("serial_number"),
        user=raw_event.get("user"),
        hostname=raw_event.get("hostname"),
        action=raw_event.get("action"),
        trusted=bool(raw_event.get("trusted", False)),
        raw_event=json.dumps(
            raw_event,
            ensure_ascii=False,
        ),
        input_rate=raw_event.get("input_rate"),
        command=raw_event.get("command"),
        metadata=raw_event.get("metadata", {}),
        bytes_transferred=raw_event.get(
            "bytes_transferred"
        ),
        file_count=raw_event.get("file_count"),
        source_path=raw_event.get("source_path"),
        destination_path=raw_event.get(
            "destination_path"
        ),
        logon_type=raw_event.get("logon_type"),
        session_id=raw_event.get("session_id"),
        previous_user=raw_event.get("previous_user"),
        encrypted=raw_event.get("encrypted"),
        read_only=raw_event.get("read_only"),
        driver_signed=raw_event.get(
            "driver_signed"
        ),
    )


def load_physical_events(
    file_path: str | Path,
) -> list[PhysicalEvent]:
    """
    Load normalized Physical Security events from a JSON file.

    Supported root formats:

    [
        {...},
        {...}
    ]

    or:

    {
        "events": [
            {...},
            {...}
        ]
    }
    """

    path = Path(file_path)

    if not path.exists():
        return []

    try:
        raw_data = json.loads(
            path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid Physical Security JSON: {error}"
        ) from error

    if isinstance(raw_data, dict):
        raw_events = raw_data.get("events", [])
    elif isinstance(raw_data, list):
        raw_events = raw_data
    else:
        raise ValueError(
            "Physical Security input must contain "
            "a JSON list or an object with an 'events' list."
        )

    if not isinstance(raw_events, list):
        raise ValueError(
            "The 'events' value must be a list."
        )

    events: list[PhysicalEvent] = []

    for raw_event in raw_events:
        if not isinstance(raw_event, dict):
            raise ValueError(
                "Every Physical Security event must be an object."
            )

        events.append(
            _build_physical_event(raw_event)
        )

    return events