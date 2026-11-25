import ipaddress
import re
from urllib.parse import urlsplit


_DOMAIN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?![A-Za-z0-9_-])"
)

_URL_TOKEN = re.compile(
    r"""https?://[^\s<>"']+|(?<![\w/])/[^\s<>"']+""",
    re.IGNORECASE,
)

_HASH_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])[A-Fa-f0-9]{32,128}(?![A-Za-z0-9_])"
)


def _matches_ip(indicator: str, observed: str) -> bool:
    try:
        return (
            ipaddress.ip_address(indicator.strip())
            == ipaddress.ip_address(observed.strip())
        )
    except ValueError:
        return False


def _domain_matches_host(indicator: str, hostname: str) -> bool:
    target = indicator.casefold().rstrip(".")
    host = hostname.casefold().rstrip(".")

    return bool(
        target
        and (
            host == target
            or host.endswith("." + target)
        )
    )


def _matches_domain(
    indicator: str,
    observed: str,
    *,
    prose: bool,
) -> bool:
    if prose:
        candidates = _DOMAIN_TOKEN.findall(observed)
    else:
        try:
            parsed = urlsplit("//" + observed)

            if (
                not parsed.netloc
                or parsed.path
                or parsed.query
                or parsed.fragment
                or "@" in parsed.netloc
            ):
                return False

            port = parsed.port
            if port is not None and port == 0:
                return False

            candidates = [parsed.hostname or ""]
        except ValueError:
            return False

    return any(
        _domain_matches_host(indicator, candidate)
        for candidate in candidates
    )


def _effective_url_port(parsed) -> int | None:
    """Normalize only standard HTTP/HTTPS ports."""
    if parsed.port is not None:
        return parsed.port

    defaults = {
        "http": 80,
        "https": 443,
    }

    return defaults.get(parsed.scheme.casefold())


_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._~"
)

_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _has_invalid_percent_encoding(parsed) -> bool:
    """Reject malformed percent escapes in URL components."""

    return any(
        _INVALID_PERCENT_ESCAPE.search(component)
        for component in (
            parsed.netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _normalize_unreserved_path(path: str) -> str:
    """Decode only unreserved characters, once."""

    def replace_escape(match: re.Match[str]) -> str:
        escape = match.group(0)
        character = chr(int(escape[1:], 16))

        if character in _UNRESERVED:
            return character

        return "%" + escape[1:].upper()

    return _PERCENT_ESCAPE.sub(replace_escape, path)


def _matches_url(
    indicator: str,
    observed: str,
    *,
    prose: bool,
) -> bool:
    candidates = (
        _URL_TOKEN.findall(observed)
        if prose
        else [observed]
    )

    try:
        target = urlsplit(indicator)

        if _has_invalid_percent_encoding(target):
            return False

        if (
            target.username is not None
            or target.password is not None
        ):
            return False

        for candidate in candidates:
            candidate = (
                candidate.rstrip(".,;!)]}")
                if prose
                else candidate
            )
            parsed = urlsplit(candidate)

            if _has_invalid_percent_encoding(parsed):
                continue

            if (
                parsed.username is not None
                or parsed.password is not None
            ):
                continue

            if indicator.startswith("/"):
                if (
                    _normalize_unreserved_path(parsed.path)
                    == _normalize_unreserved_path(target.path)
                    and (
                        not target.query
                        or parsed.query == target.query
                    )
                ):
                    return True

            elif target.scheme and target.netloc:
                if (
                    parsed.scheme.casefold()
                    == target.scheme.casefold()
                    and parsed.hostname
                    and target.hostname
                    and parsed.hostname.casefold()
                    == target.hostname.casefold()
                    and _effective_url_port(parsed)
                    == _effective_url_port(target)
                    and _normalize_unreserved_path(parsed.path or "/")
                    == _normalize_unreserved_path(target.path or "/")
                    and parsed.query == target.query
                ):
                    return True

    except ValueError:
        return False

    return False


def _matches_hash(
    indicator: str,
    observed: str,
    *,
    prose: bool,
) -> bool:
    target = indicator.casefold()

    if (
        len(target) not in (32, 40, 64, 128)
        or re.fullmatch(r"[a-f0-9]+", target) is None
    ):
        return False

    candidates = (
        _HASH_TOKEN.findall(observed)
        if prose
        else [observed]
    )

    return any(
        candidate.casefold() == target
        for candidate in candidates
    )


def ioc_matches(
    ioc_type: str,
    indicator: str,
    observed: str,
    *,
    prose: bool = False,
) -> bool:
    """Compare IOC against observed evidence by indicator type."""

    if (
        not isinstance(indicator, str)
        or not isinstance(observed, str)
        or not indicator
        or not observed
    ):
        return False

    if ioc_type == "ip":
        return not prose and _matches_ip(indicator, observed)

    if ioc_type == "domain":
        return _matches_domain(
            indicator, observed, prose=prose
        )

    if ioc_type == "url":
        return _matches_url(
            indicator, observed, prose=prose
        )

    if ioc_type == "hash":
        return _matches_hash(
            indicator, observed, prose=prose
        )

    return False
