from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.systemd_persistence_detector import (
    detect_linux_systemd_persistence,)
from src.models.linux_process_execution import LinuxProcessExecution


class FakeLinuxEvent:
    def __init__(
        self,
        command="",
        process="",
        user="root",
        source_ip="",
        hostname="ubuntu-server",
        timestamp="Jul 7 10:00:01",
        message="",
        raw_log="",
    ):
        self.command = command
        self.process = process
        self.user = user
        self.source_ip = source_ip
        self.hostname = hostname
        self.timestamp = timestamp
        self.message = message
        self.raw_log = raw_log


def create_execution(
    command: str = "",
    process: str = "",
    user: str = "root",
    source_ip: str = "",
    message: str = "",
) -> LinuxProcessExecution:
    event = FakeLinuxEvent(
        command=command,
        process=process,
        user=user,
        source_ip=source_ip,
        message=message,
    )

    context = LinuxDetectionContext.from_event(event)

    return LinuxProcessExecution.from_context(context)


def test_detect_systemd_service_file_creation():
    executions = [create_execution(command=("echo 'ExecStart=/tmp/payload' "
        "> /etc/systemd/system/backdoor.service"))]

    findings = detect_linux_systemd_persistence(executions)

    assert len(findings) == 1
    assert findings[0].title == ("Linux Systemd Persistence Activity Detected")
    assert findings[0].severity == "high"
    assert findings[0].source == "Linux Host Detection"


def test_detect_systemctl_enable_service():
    executions = [create_execution(
        command="systemctl enable backdoor.service")]

    findings = detect_linux_systemd_persistence(executions)

    assert len(findings) == 1


def test_detect_systemctl_enable_now_service():
    executions = [create_execution(
        command="systemctl enable --now backdoor.service")]

    findings = detect_linux_systemd_persistence(executions)

    assert len(findings) == 1


def test_detect_systemctl_link_service():
    executions = [create_execution(
        command="systemctl link /tmp/backdoor.service")]

    findings = detect_linux_systemd_persistence(executions)

    assert len(findings) == 1


def test_detect_systemd_timer_creation():
    executions = [create_execution(command=("cp persistence.timer "
        "/etc/systemd/system/persistence.timer"))]

    findings = detect_linux_systemd_persistence(executions)

    assert len(findings) == 1


def test_detect_daemon_reload_with_service_context():
    executions = [create_execution(command=("systemctl daemon-reload "
        "backdoor.service"))]

    findings = detect_linux_systemd_persistence(executions)

    assert len(findings) == 1


def test_ignore_daemon_reload_without_unit_context():
    executions = [create_execution(command="systemctl daemon-reload")]

    findings = detect_linux_systemd_persistence(executions)

    assert findings == []


def test_ignore_systemctl_status():
    executions = [create_execution(command="systemctl status nginx")]

    findings = detect_linux_systemd_persistence(executions)

    assert findings == []


def test_ignore_systemctl_restart():
    executions = [create_execution(command="systemctl restart nginx")]

    findings = detect_linux_systemd_persistence(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_linux_systemd_persistence([])

    assert findings == []


def test_systemd_persistence_finding_preserves_utc_time():
    execution = create_execution(
        command="systemctl enable backdoor.service"
    )
    execution.timestamp_utc = (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    original_timestamp = execution.timestamp

    findings = detect_linux_systemd_persistence(
        [execution]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == (
        "Linux Systemd Persistence Activity Detected"
    )
    assert finding.severity == "high"
    assert finding.first_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    # Preserve original Linux syslog timestamp.
    assert execution.timestamp == original_timestamp
    assert execution.timestamp == "Jul 7 10:00:01"


def test_systemd_persistence_does_not_invent_unknown_time():
    execution = create_execution(
        command=(
            "echo 'ExecStart=/tmp/payload' "
            "> /etc/systemd/system/backdoor.service"
        )
    )

    assert execution.timestamp_utc is None

    findings = detect_linux_systemd_persistence(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None


def test_systemd_persistence_rejects_invalid_utc_time():
    execution = create_execution(
        command="systemctl link /tmp/backdoor.service"
    )
    execution.timestamp_utc = "invalid timestamp"

    findings = detect_linux_systemd_persistence(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None
