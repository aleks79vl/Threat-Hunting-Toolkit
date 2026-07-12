from dataclasses import dataclass, field
import json

from src.models.threat_finding import ThreatFinding


@dataclass
class ThreatReport:
    title: str
    generated_at: str
    findings: list[ThreatFinding] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    network_statistics: dict = field(default_factory=dict)
    linux_statistics: dict = field(default_factory=dict)
    linux_execution_statistics: dict = field(default_factory=dict)

    def total_findings(self) -> int:
        return len(self.findings)

    def count_by_severity(self, severity: str) -> int:
        return sum(
            1 for finding in self.findings
            if finding.severity == severity
        )

    def summary(self) -> dict:
        return {
            "total_findings": self.total_findings(),
            "critical": self.count_by_severity("critical"),
            "high": self.count_by_severity("high"),
            "medium": self.count_by_severity("medium"),
            "low": self.count_by_severity("low"),
        }

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "summary": self.summary(),
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "timeline": self.timeline,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)