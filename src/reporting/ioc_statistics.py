from collections import Counter

from src.intelligence.ioc_matcher import match_iocs


_DATABASE_IOC_TYPES = frozenset({
    "ip", "domain", "url", "hash",
})


def generate_ioc_statistics(findings):
    """
    Generate IOC statistics.

    total_matches preserves the legacy matched-finding count.
    Type counters include independent IOC records.
    """

    matched = [
        finding
        for finding in findings
        if getattr(finding, "ioc_match", False)
    ]

    counter = Counter()

    for finding in matched:
        matches = getattr(finding, "ioc_matches", []) or []

        if not matches:
            if (
                finding.ioc_type in _DATABASE_IOC_TYPES
                and finding.ioc_value
                and any(
                    ioc.ioc_type == finding.ioc_type
                    and ioc.value == finding.ioc_value
                    for ioc in match_iocs(finding)
                )
            ):
                counter[finding.ioc_type] += 1
            continue

        verified = {
            (ioc.ioc_type, ioc.value)
            for ioc in match_iocs(finding)
        }

        seen = set()

        for ioc in matches:
            if not isinstance(ioc, dict):
                continue

            ioc_type = ioc.get("ioc_type")
            value = ioc.get("value")

            if (
                ioc_type not in _DATABASE_IOC_TYPES
                or not isinstance(value, str)
                or not value
            ):
                continue

            identity = (ioc_type, value)

            if identity in seen or identity not in verified:
                continue

            seen.add(identity)
            counter[ioc_type] += 1

    return {
        "total_matches": len(matched),
        "ip": counter.get("ip", 0),
        "domain": counter.get("domain", 0),
        "url": counter.get("url", 0),
        "hash": counter.get("hash", 0),
    }
