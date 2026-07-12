from dataclasses import dataclass

from src.models.linux_event import LinuxEvent


@dataclass
class LinuxDetectionContext:
    event: LinuxEvent
    command: str = ""
    process: str = ""
    service: str = ""
    user: str = ""
    source_ip: str = ""
    raw_message: str = ""

    @classmethod
    def from_event(cls, event: LinuxEvent) -> "LinuxDetectionContext":
        return cls(
            event=event,
            command=cls._extract_command(event),
            process=cls._normalize(getattr(event, "process", "")),
            service=cls._normalize(getattr(event, "service", "")),
            user=cls._normalize(getattr(event, "user", "")),
            source_ip=cls._normalize(getattr(event, "source_ip", "")),
            raw_message=cls._extract_raw_message(event),
        )

    @staticmethod
    def _normalize(value: object) -> str:
        if value is None:
            return ""

        return str(value).strip().lower()

    @classmethod
    def _extract_command(cls, event: LinuxEvent) -> str:
        command = cls._normalize(getattr(event, "command", ""))

        if command:
            return command

        message = cls._normalize(getattr(event, "message", ""))

        if "command=" in message:
            return message.split("command=", 1)[1].strip()

        return ""

    @classmethod
    def _extract_raw_message(cls, event: LinuxEvent) -> str:
        values = [getattr(event, "raw_message", ""),
            getattr(event, "message", ""),
            getattr(event, "raw_log", ""),]

        return " ".join(cls._normalize(value)for value in values
            if cls._normalize(value))

    def combined_text(self) -> str:
        values = (self.command,self.process,self.service,
            self.user,self.source_ip,self.raw_message,)

        return " ".join(value for value in values if value)