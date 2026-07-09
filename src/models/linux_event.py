from dataclasses import dataclass


@dataclass
class LinuxEvent:
    timestamp: str = ""
    hostname: str = ""
    service: str = ""
    process: str = ""
    pid: str = ""
    message: str = ""
    user: str = ""
    source_ip: str = ""
    port: int | None = None
    action: str = ""
    status: str = ""
    raw_log: str = ""