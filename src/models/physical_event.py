from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PhysicalEvent:
    timestamp: datetime
    event_type: str
    device_type: str
    device_name: str
    device_id: str
    vendor: Optional[str] = None
    serial_number: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    action: Optional[str] = None
    trusted: bool = False
    raw_event: str = ""
    input_rate: float | None = None
    command: str | None = None
    metadata: dict = field(default_factory=dict)
    bytes_transferred: int | None = None
    file_count: int | None = None
    source_path: str | None = None
    destination_path: str | None = None
    logon_type: str | None = None
    session_id: str | None = None
    previous_user: str | None = None
    encrypted: bool | None = None
    read_only: bool | None = None
    driver_signed: bool | None = None