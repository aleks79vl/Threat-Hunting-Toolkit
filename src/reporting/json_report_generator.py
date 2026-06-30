import json
from pathlib import Path

from src.models.threat_report import ThreatReport


def generate_json_report(
    report: ThreatReport,
    output_path: str = "reports/threat_report.json"
) -> None:
    """
    Save ThreatReport as JSON.
    """

    output_file = Path(output_path)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    report_data = report.to_dict()

    for finding in report_data.get("findings", []):
        finding["mitre"] = {
            "technique": finding.get("technique", "Unknown"),
            "name": finding.get("technique_name", "Unknown"),
            "tactic": finding.get("tactic", "Unknown"),
        }

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)