from dataclasses import dataclass
from typing import Optional


@dataclass
class WindowsDetectionContext:
    """
    Unified Windows Event Context used by all Windows detection modules.
    """

    event_id: int

    timestamp: str

    computer: str

    username: str

    domain: Optional[str] = None

    logon_type: Optional[str] = None

    source_ip: Optional[str] = None

    destination_ip: Optional[str] = None

    process_name: Optional[str] = None

    parent_process: Optional[str] = None

    command_line: Optional[str] = None

    service_name: Optional[str] = None

    registry_key: Optional[str] = None

    scheduled_task: Optional[str] = None

    dll_name: Optional[str] = None

    file_path: Optional[str] = None

    hash_value: Optional[str] = None