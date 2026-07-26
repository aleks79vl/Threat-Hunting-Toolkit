from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.console_summary import print_console_summary


def test_print_console_summary_preserves_output_contract(
    capsys,
):
    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-25 13:00:00",
        findings=[
            ThreatFinding(
                title="Critical Test Finding",
                severity="critical",
                description="Synthetic finding for console testing.",
                source="Test Source",
            ),
        ],
    )

    print_console_summary(
        report,
        json_output_file="reports/threat_report.json",
        html_output_file="reports/threat_report.html",
        network_event_count=773,
        network_finding_count=175,
        linux_event_count=13,
        linux_finding_count=14,
        physical_event_count=5,
        physical_finding_count=23,
        physical_policy_finding_count=4,
        physical_correlation_finding_count=6,
        physical_risk_score=100,
    )

    assert capsys.readouterr().out.splitlines() == [
        "Threat Hunting Report generated successfully.",
        "JSON output file: reports/threat_report.json",
        "HTML output file: reports/threat_report.html",
        "Total findings: 1",
        "Critical findings: 1",
        "Network events parsed: 773",
        "Network findings: 175",
        "Linux events parsed: 13",
        "Linux findings: 14",
        "Physical events parsed: 5",
        "Physical findings: 23",
        "Physical policy findings: 4",
        "Physical correlation findings: 6",
        "Physical risk score: 100",
    ]