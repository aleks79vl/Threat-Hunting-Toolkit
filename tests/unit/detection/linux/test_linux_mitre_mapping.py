from src.detection.linux.mitre_mapping import (get_linux_mitre_tactics,
    get_linux_mitre_technique_ids,get_linux_mitre_techniques,)
from src.models.threat_finding import ThreatFinding


def create_finding(title: str) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity="high",
        description="Test Linux finding",
        source="Linux Host Detection",
        recommendation="Investigate activity",
    )


def test_reverse_shell_maps_to_unix_shell():
    finding = create_finding("Linux Reverse Shell Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1059.004"]


def test_telnet_maps_to_remote_services():
    finding = create_finding("Advanced Telnet Activity Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1021"]


def test_ssh_persistence_maps_to_authorized_keys():
    finding = create_finding( "Linux SSH Persistence Activity Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1098.004"]


def test_audit_tampering_maps_to_impair_defenses():
    finding = create_finding("Linux Audit Tampering Activity Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1562.001"]


def test_log_clearing_maps_to_linux_log_clearing():
    finding = create_finding("Linux Log Clearing Activity Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1070.002"]


def test_file_permission_finding_maps_to_two_techniques():
    finding = create_finding(
        "Suspicious Linux File Permission Change Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1222.002","T1548.001",]


def test_systemd_persistence_mapping():
    finding = create_finding("Linux Systemd Persistence Activity Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1543.002"]


def test_cron_persistence_mapping():
    finding = create_finding("Linux Cron Persistence Activity Detected")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == ["T1053.003"]


def test_get_linux_mitre_tactics_removes_duplicates():
    finding = create_finding("Suspicious Linux File Permission Change Detected")

    tactics = get_linux_mitre_tactics(finding)

    assert tactics == ["Defense Evasion","Privilege Escalation",]


def test_unknown_finding_returns_empty_techniques():
    finding = create_finding("Unknown Linux Finding")

    techniques = get_linux_mitre_techniques(finding)

    assert techniques == ()


def test_unknown_finding_returns_empty_ids():
    finding = create_finding("Unknown Linux Finding")

    technique_ids = get_linux_mitre_technique_ids(finding)

    assert technique_ids == []


def test_unknown_finding_returns_empty_tactics():
    finding = create_finding("Unknown Linux Finding")

    tactics = get_linux_mitre_tactics(finding)

    assert tactics == []