"""Process-local pseudonymization of API key identifiers."""

import hashlib
import hmac
import secrets


_PROCESS_HMAC_KEY = secrets.token_bytes(32)


def fingerprint_api_key_id(value: str) -> str:
    """Return an opaque, process-local correlation identifier."""

    if not isinstance(value, str) or not value:
        raise ValueError("api_key_id must be a non-empty string")

    digest = hmac.new(
        _PROCESS_HMAC_KEY,
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"hmac-sha256:{digest}"
