from dataclasses import dataclass, asdict
import json


@dataclass
class ThreatFinding:
    title: str
    severity: str
    description: str
    source: str
    ip: str = ""
    hostname: str = ""
    port: int = 0
    technique: str = ""
    recommendation: str = ""
    risk_score: int = 0

    technique: str = ""
    technique_name: str = ""
    tactic: str = ""

    ioc_match: bool = False
    ioc_type: str = ""
    ioc_value: str = ""
    ioc_confidence: str = ""
    ioc_source: str = ""
    ioc_description: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    observation_start: str | None = None
    observation_end: str | None = None
    observation_scope: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)