import json
from pathlib import Path

from src.models.threat_report import ThreatReport
from src.reporting.mitre_statistics import generate_mitre_statistics


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

    report_data["network_statistics"] = getattr(report,
        "network_statistics",
        {"total_network_events": 0,"protocols": {},
        "dns_queries": [],"http_requests": 0,},
    )

    report_data["linux_statistics"] = getattr(
        report,
        "linux_statistics",
        {"total_events": 0,"actions": {},"statuses": {},
        "users": {},"source_ips": {},},
    )

    report_data["linux_execution_statistics"] = getattr(report,
        "linux_execution_statistics",
        {"total_executions": 0,"suspicious_executions": 0,
        "unique_executables": 0,"top_executables": [],
        "top_users": [],"mitre_statistics": [],},
    )

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

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)