from dataclasses import dataclass

from src.models.threat_finding import ThreatFinding


@dataclass(frozen=True)
class LinuxMitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str


LINUX_MITRE_MAPPING = {
    "Suspicious Linux Process Execution Detected": (
        LinuxMitreTechnique(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="Execution",
        ),
    ),
    "Linux Reverse Shell Detected": (
        LinuxMitreTechnique(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="Execution",
        ),
    ),
    "Advanced Telnet Activity Detected": (
        LinuxMitreTechnique(
            technique_id="T1021",
            technique_name="Remote Services",
            tactic="Lateral Movement",
        ),
    ),
    "Linux SSH Persistence Activity Detected": (
        LinuxMitreTechnique(
            technique_id="T1098.004",
            technique_name="SSH Authorized Keys",
            tactic="Persistence",
        ),
    ),
    "Linux Audit Tampering Activity Detected": (
        LinuxMitreTechnique(
            technique_id="T1562.001",
            technique_name="Disable or Modify Tools",
            tactic="Defense Evasion",
        ),
    ),
    "Linux Log Clearing Activity Detected": (
        LinuxMitreTechnique(
            technique_id="T1070.002",
            technique_name="Clear Linux or Mac System Logs",
            tactic="Defense Evasion",
        ),
    ),
    "Suspicious Linux File Permission Change Detected": (
        LinuxMitreTechnique(
            technique_id="T1222.002",
            technique_name="Linux and Mac File and Directory Permissions Modification",
            tactic="Defense Evasion",
        ),
        LinuxMitreTechnique(
            technique_id="T1548.001",
            technique_name="Setuid and Setgid",
            tactic="Privilege Escalation",
        ),
    ),
    "Linux Systemd Persistence Activity Detected": (
        LinuxMitreTechnique(
            technique_id="T1543.002",
            technique_name="Systemd Service",
            tactic="Persistence",
        ),
    ),
    "Linux Cron Persistence Activity Detected": (
        LinuxMitreTechnique(
            technique_id="T1053.003",
            technique_name="Cron",
            tactic="Persistence",
        ),
    ),
}


def get_linux_mitre_techniques(finding: ThreatFinding,
) -> tuple[LinuxMitreTechnique, ...]:
    return LINUX_MITRE_MAPPING.get(finding.title,(),)


def get_linux_mitre_technique_ids(finding: ThreatFinding,
) -> list[str]:
    return [
        technique.technique_id
        for technique in get_linux_mitre_techniques(finding)
    ]


def get_linux_mitre_tactics(finding: ThreatFinding,
) -> list[str]:
    return list(
        dict.fromkeys(
            technique.tactic
            for technique in get_linux_mitre_techniques(finding)
        )
    )