from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.log_clearing_detector import (detect_linux_log_clearing,)
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


def test_detect_auth_log_removal():
    executions = [create_execution(command="rm -f /var/log/auth.log")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1
    assert findings[0].title == "Linux Log Clearing Activity Detected"
    assert findings[0].severity == "critical"
    assert findings[0].source == "Linux Host Detection"


def test_detect_log_truncation():
    executions = [create_execution(command="truncate /var/log/syslog")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_detect_log_shredding():
    executions = [create_execution(command="shred /var/log/auth.log")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_detect_journal_vacuum():
    executions = [create_execution(command="journalctl --vacuum-time=1s")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_detect_history_clear():
    executions = [create_execution(command="history -c")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_detect_histfile_unset():
    executions = [create_execution(command="unset HISTFILE")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_detect_histfile_dev_null():
    executions = [create_execution(command="export HISTFILE=/dev/null")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_detect_bash_history_removal():
    executions = [create_execution(command="rm -f ~/.bash_history")]

    findings = detect_linux_log_clearing(executions)

    assert len(findings) == 1


def test_ignore_journal_listing():
    executions = [create_execution(command="journalctl -xe")]

    findings = detect_linux_log_clearing(executions)

    assert findings == []


def test_ignore_history_listing():
    executions = [create_execution(command="history")]

    findings = detect_linux_log_clearing(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_linux_log_clearing([])

    assert findings == []


def test_log_clearing_finding_preserves_utc_time():
    execution = create_execution(
        command="rm -f /var/log/auth.log"
    )
    execution.timestamp_utc = (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    original_timestamp = execution.timestamp

    findings = detect_linux_log_clearing(
        [execution]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == (
        "Linux Log Clearing Activity Detected"
    )
    assert finding.severity == "critical"
    assert finding.first_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    # Original Linux syslog timestamp must be preserved.
    assert execution.timestamp == original_timestamp
    assert execution.timestamp == "Jul 7 10:00:01"


def test_log_clearing_does_not_invent_unknown_time():
    execution = create_execution(
        command="history -c"
    )

    assert execution.timestamp_utc is None

    findings = detect_linux_log_clearing(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None


def test_log_clearing_rejects_invalid_utc_time():
    execution = create_execution(
        command="journalctl --vacuum-time=1s"
    )
    execution.timestamp_utc = "invalid timestamp"

    findings = detect_linux_log_clearing(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None
