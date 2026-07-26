from dataclasses import dataclass
from typing import Generic, TypeVar

from src.models.threat_finding import ThreatFinding


EventT = TypeVar("EventT")


@dataclass(frozen=True, slots=True)
class DomainPipelineResult(Generic[EventT]):
    events: list[EventT]
    findings: list[ThreatFinding]
    statistics: dict[str, object]