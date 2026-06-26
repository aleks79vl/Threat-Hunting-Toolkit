from dataclasses import dataclass, asdict
import json


@dataclass
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str = "low"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    hostname: str = ""
    username: str = ""
    raw_event: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)
