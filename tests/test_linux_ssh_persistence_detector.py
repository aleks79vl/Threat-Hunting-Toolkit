from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.ssh_persistence_detector import (
    detect_linux_ssh_persistence,
)
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


def test_detect_authorized_keys_modification():
    executions = [
        create_execution(
            command=(
                'echo "ssh-rsa AAAATESTKEY attacker" '
                ">> /root/.ssh/authorized_keys"
            )
        )
    ]

    findings = detect_linux_ssh_persistence(executions)

    assert len(findings) == 1
    assert findings[0].title == "Linux SSH Persistence Activity Detected"
    assert findings[0].severity == "high"
    assert findings[0].source == "Linux Host Detection"


def test_detect_ssh_copy_id():
    executions = [create_execution(command="ssh-copy-id root@10.0.0.5")]

    findings = detect_linux_ssh_persistence(executions)

    assert len(findings) == 1


def test_detect_permit_root_login_enabled():
    executions = [
        create_execution(
            command=(
                "sed -i 's/PermitRootLogin no/"
                "PermitRootLogin yes/' /etc/ssh/sshd_config"
            )
        )
    ]

    findings = detect_linux_ssh_persistence(executions)

    assert len(findings) == 1


def test_detect_password_authentication_enabled():
    executions = [
        create_execution(
            command=(
                "echo 'PasswordAuthentication yes' "
                ">> /etc/ssh/sshd_config"
            )
        )
    ]

    findings = detect_linux_ssh_persistence(executions)

    assert len(findings) == 1


def test_detect_sshd_service_enabled():
    executions = [create_execution(command="systemctl enable sshd")]

    findings = detect_linux_ssh_persistence(executions)

    assert len(findings) == 1


def test_ignore_normal_ssh_connection():
    executions = [create_execution(command="ssh admin@10.0.0.5")]

    findings = detect_linux_ssh_persistence(executions)

    assert findings == []


def test_ignore_sshd_status_check():
    executions = [create_execution(command="systemctl status sshd")]

    findings = detect_linux_ssh_persistence(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_linux_ssh_persistence([])

    assert findings == []