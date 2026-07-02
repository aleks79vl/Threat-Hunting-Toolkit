from collections import Counter


def generate_ioc_statistics(findings):
    """
    Generate IOC statistics for the report.
    """

    matched = [
        finding
        for finding in findings
        if getattr(finding, "ioc_match", False)
    ]

    counter = Counter()

    for finding in matched:
        counter[getattr(finding, "ioc_type", "unknown")] += 1

    return {
        "total_matches": len(matched),
        "ip": counter.get("ip", 0),
        "domain": counter.get("domain", 0),
        "url": counter.get("url", 0),
        "hash": counter.get("hash", 0),
    }