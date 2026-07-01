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

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)