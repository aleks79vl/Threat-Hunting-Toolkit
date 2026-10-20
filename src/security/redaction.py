import re

_SENSITIVE_ASSIGNMENT = re.compile(
    r"""(\b(?:password|api_key|access_token)\s*=\s*)(?:(["'])(.*?)\2|[^\s]+)""",
    re.IGNORECASE,
)

_BEARER_TOKEN = re.compile(
    r"(\bAuthorization\s*:\s*Bearer\s+)\S+",
    re.IGNORECASE,
)

_COOKIE_HEADER = re.compile(
    r"(^[ \t]*(?:Set-Cookie|Cookie)[ \t]*:[ \t]*)[^\r\n]*",
    re.IGNORECASE | re.MULTILINE,
)

SENSITIVE_FIELD_NAMES = frozenset({
    "password",
    "api_key",
    "access_token",
    "authorization",
    "cookie",
})


def _redact_value(value):
    if isinstance(value, dict):
        return redact_data(value)

    if isinstance(value, list):
        return [_redact_value(item) for item in value]

    if isinstance(value, str):
        redacted = _SENSITIVE_ASSIGNMENT.sub(
            lambda match: (
                f"{match.group(1)}"
                f"{match.group(2) or ''}"
                f"[REDACTED]"
                f"{match.group(2) or ''}"
            ),
            value,
        )

        redacted = _BEARER_TOKEN.sub(
            lambda match: f"{match.group(1)}[REDACTED]",
            redacted,
        )

        redacted = _COOKIE_HEADER.sub(
            lambda match: f"{match.group(1)}[REDACTED]",
            redacted,
        )

        return redacted

    return value


def redact_data(data: dict) -> dict:
    return {
        key: (
            "[REDACTED]"
            if key.lower() in SENSITIVE_FIELD_NAMES
            else _redact_value(value)
        )
        for key, value in data.items()
    }


def redact_for_export(data: dict) -> dict:
    def hide_raw_events(value):
        if isinstance(value, dict):
            return {
            key: hide_raw_events(item)
            for key, item in value.items()
            if key != "raw_event"
            }

        if isinstance(value, list):
            return [hide_raw_events(item) for item in value]

        return value

    return hide_raw_events(redact_data(data))
