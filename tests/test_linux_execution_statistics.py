from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding
from src.reporting.linux_execution_statistics import (generate_linux_execution_statistics,)


def create_execution(
    executable: str = "",
    user: str = "",
    command: str = "",
) -> LinuxProcessExecution:
    return LinuxProcessExecution(
        command=command,
        executable=executable,
        process=executable,
        user=user,
        source_ip="",
        hostname="ubuntu-server",
        timestamp="jul 11 16:00:00",
        raw_text=command,
    )


def create_finding(
    technique: str = "",
) -> ThreatFinding:
    finding = ThreatFinding(
        title="Test Linux Finding",
        severity="high",
        description="Test finding",
        source="Linux Host Detection",
        recommendation="Investigate activity",
    )

    finding.technique = technique

    return finding


def test_total_executions_count():
    executions = [create_execution(executable="/bin/bash"),
        create_execution(executable="python3"),create_execution(executable="telnet"),]

    statistics = generate_linux_execution_statistics(executions,[],)

    assert statistics["total_executions"] == 3


def test_suspicious_executions_count():
    findings = [create_finding("T1059.004"),create_finding("T1021"),create_finding("T1059.004"),]

    statistics = generate_linux_execution_statistics([],findings,)

    assert statistics["suspicious_executions"] == 3


def test_unique_executables_count():
    executions = [create_execution(executable="/bin/bash"),create_execution(executable="/bin/bash"),
        create_execution(executable="python3"),create_execution(executable="telnet"),]

    statistics = generate_linux_execution_statistics(executions,[],)

    assert statistics["unique_executables"] == 3


def test_top_executables_counter():
    executions = [create_execution(executable="/bin/bash"),create_execution(executable="/bin/bash"),
        create_execution(executable="/bin/bash"),create_execution(executable="python3"),
        create_execution(executable="python3"),create_execution(executable="telnet"),]

    statistics = generate_linux_execution_statistics(executions,[],)

    assert statistics["top_executables"] == [("/bin/bash", 3),("python3", 2),("telnet", 1),]


def test_top_users_counter():
    executions = [create_execution(executable="/bin/bash", user="root"),
        create_execution(executable="python3", user="root"),create_execution(executable="telnet", user="alex"),
        create_execution(executable="curl", user="alex"),create_execution(executable="wget", user="www-data"),]

    statistics = generate_linux_execution_statistics(executions,[],)

    assert statistics["top_users"] == [("root", 2),("alex", 2),("www-data", 1),]


def test_mitre_statistics_counter():
    findings = [create_finding("T1059.004"),create_finding("T1059.004"),
        create_finding("T1021"),]

    statistics = generate_linux_execution_statistics([],findings,)

    assert statistics["mitre_statistics"] == [("T1059.004", 2),("T1021", 1),]


def test_empty_values_are_ignored():
    executions = [create_execution(executable="", user=""),
        create_execution(executable="/bin/bash", user="root"),]

    findings = [create_finding(""),create_finding("T1059.004"),]

    statistics = generate_linux_execution_statistics(executions,findings,)

    assert statistics["total_executions"] == 2
    assert statistics["unique_executables"] == 1
    assert statistics["top_executables"] == [
        ("/bin/bash", 1),
    ]
    assert statistics["top_users"] == [("root", 1),]
    assert statistics["mitre_statistics"] == [("T1059.004", 1),]


def test_empty_input_returns_empty_statistics():
    statistics = generate_linux_execution_statistics([],[],)

    assert statistics == {
        "total_executions": 0,
        "suspicious_executions": 0,
        "unique_executables": 0,
        "top_executables": [],
        "top_users": [],
        "mitre_statistics": [],
    }