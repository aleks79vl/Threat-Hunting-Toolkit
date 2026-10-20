import json
from pathlib import Path

from src.models.threat_report import ThreatReport
from src.reporting.mitre_statistics import generate_mitre_statistics
from src.security.redaction import redact_for_export


def generate_json_report(
    report: ThreatReport,
    output_path: str = "reports/threat_report.json"
) -> None:
    """
    Save ThreatReport as JSON.
    """

    output_file = Path(output_path)

    output_file.parent.mkdir(parents=True,exist_ok=True)

    report_data = report.to_dict()

    report_data["network_statistics"] = report.network_statistics
    report_data["linux_statistics"] = report.linux_statistics
    report_data["linux_execution_statistics"] = (
        report.linux_execution_statistics
    )

    report_data["physical_security"] = {
        "risk_score": report.physical_risk_score,
        "statistics": report.physical_statistics,
    }

    report_data["mitre_statistics"] = generate_mitre_statistics(
        report.findings
    )

    for finding in report_data.get("findings", []):
        finding["mitre"] = {
            "technique": finding.get("technique", "Unknown"),
            "name": finding.get("technique_name", "Unknown"),
            "tactic": finding.get("tactic", "Unknown"),
        }

        finding["ioc"] = {
            "matched": finding.get("ioc_match", False),
            "type": finding.get("ioc_type", ""),
            "value": finding.get("ioc_value", ""),
            "confidence": finding.get("ioc_confidence", ""),
            "source": finding.get("ioc_source", ""),
            "description": finding.get("ioc_description", ""),
        }

    report_data = redact_for_export(report_data)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)
