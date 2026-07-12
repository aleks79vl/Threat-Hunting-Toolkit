from dataclasses import dataclass

from src.detection.linux_detection_context import (LinuxDetectionContext,)


@dataclass
class LinuxProcessExecution:
    command: str = ""
    executable: str = ""
    process: str = ""
    user: str = ""
    source_ip: str = ""
    hostname: str = ""
    timestamp: str = ""
    raw_text: str = ""

    @classmethod
    def from_context(
        cls,
        context: LinuxDetectionContext,
    ) -> "LinuxProcessExecution":
        command = context.command

        return cls(
            command=command,
            executable=cls._extract_executable(command),
            process=context.process,
            user=context.user,
            source_ip=context.source_ip,
            hostname=cls._normalize(
                getattr(context.event, "hostname", "")
            ),
            timestamp=cls._normalize(
                getattr(context.event, "timestamp", "")
            ),
            raw_text=context.combined_text(),
        )

    @staticmethod
    def _normalize(value: object) -> str:
        if value is None:
            return ""

        return str(value).strip().lower()

    @staticmethod
    def _extract_executable(command: str) -> str:
        if not command:
            return ""

        return command.split()[0]

    def searchable_text(self) -> str:
        values = (
            self.command,
            self.executable,
            self.process,
            self.user,
            self.source_ip,
            self.hostname,
            self.raw_text,
        )

        return " ".join(value
            for value in values
            if value)