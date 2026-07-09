import re

from src.models.linux_event import LinuxEvent


SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"(?P<process>[^\[:]+)"
    r"(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$")


FAILED_SSH_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<source_ip>\S+) port (?P<port>\d+)")


ACCEPTED_SSH_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<source_ip>\S+) port (?P<port>\d+)")


SUDO_PATTERN = re.compile(
    r"(?P<user>\S+) : .*COMMAND=(?P<command>.*)")


TELNET_PATTERN = re.compile(r"connect from (?P<source_ip>\S+)")


def _detect_service(process: str) -> str:
    process_lower = process.lower()

    if process_lower == "sshd":
        return "ssh"

    if "telnet" in process_lower:
        return "telnet"

    if process_lower == "sudo":
        return "sudo"

    return process_lower


def _parse_port(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_auth_log(file_path: str) -> list[LinuxEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            raw_log = line.rstrip("\n")

            match = SYSLOG_PATTERN.match(raw_log)

            if not match:
                continue

            timestamp = match.group("timestamp")
            hostname = match.group("hostname")
            process = match.group("process")
            pid = match.group("pid") or ""
            message = match.group("message")
            service = _detect_service(process)

            event = LinuxEvent(
                timestamp=timestamp,
                hostname=hostname,
                service=service,
                process=process,
                pid=pid,
                message=message,
                raw_log=raw_log,
            )

            failed_ssh = FAILED_SSH_PATTERN.search(message)

            if failed_ssh:
                event.user = failed_ssh.group("user")
                event.source_ip = failed_ssh.group("source_ip")
                event.port = _parse_port(failed_ssh.group("port"))
                event.action = "authentication"
                event.status = "failed"

            accepted_ssh = ACCEPTED_SSH_PATTERN.search(message)

            if accepted_ssh:
                event.user = accepted_ssh.group("user")
                event.source_ip = accepted_ssh.group("source_ip")
                event.port = _parse_port(accepted_ssh.group("port"))
                event.action = "authentication"
                event.status = "success"

            sudo_event = SUDO_PATTERN.search(message)

            if service == "sudo" and sudo_event:
                event.user = sudo_event.group("user")
                event.action = "command"
                event.status = "success"

            telnet_event = TELNET_PATTERN.search(message)

            if service == "telnet" and telnet_event:
                event.source_ip = telnet_event.group("source_ip")
                event.port = 23
                event.action = "connection"
                event.status = "success"

            events.append(event)

    return events