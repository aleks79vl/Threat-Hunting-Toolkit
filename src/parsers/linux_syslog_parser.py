import re

from src.models.linux_event import LinuxEvent


SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"(?P<process>[^\[:]+)"
    r"(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$")


USERADD_PATTERN = re.compile(r"new user: name=(?P<user>[^,]+)")


def _detect_service(process: str, message: str) -> str:
    process_lower = process.lower()
    message_lower = message.lower()

    if process_lower == "cron":
        return "cron"

    if process_lower == "systemd":
        return "systemd"

    if process_lower == "useradd":
        return "user"

    if "service" in message_lower:
        return "service"

    return process_lower


def _detect_action(message: str) -> str:
    message_lower = message.lower()

    if "restarted" in message_lower:
        return "service_restart"

    if "started" in message_lower:
        return "service_start"

    if "stopped" in message_lower:
        return "service_stop"

    if "cmd" in message_lower:
        return "cron_execute"

    if "new user" in message_lower:
        return "user_create"

    return ""


def parse_syslog(file_path: str) -> list[LinuxEvent]:
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

            service = _detect_service(
                process,
                message,
            )

            action = _detect_action(message)

            user_match = USERADD_PATTERN.search(message)
            user = user_match.group("user") if user_match else ""

            event = LinuxEvent(timestamp=timestamp,hostname=hostname,
                service=service,process=process,pid=pid,
                message=message,user=user,action=action,
                status="success" if action else "",raw_log=raw_log,)

            events.append(event)

    return events