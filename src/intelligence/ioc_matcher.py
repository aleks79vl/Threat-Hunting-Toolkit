from dataclasses import asdict

from src.intelligence.ioc_comparison import ioc_matches
from src.intelligence.ioc_loader import get_iocs
from src.intelligence.ioc_risk_scoring import IOC_CONFIDENCE_BONUSES
from src.models.ioc import IOC
from src.models.threat_finding import ThreatFinding


_DATABASE_IOC_TYPES = frozenset({
    "ip",
    "domain",
    "url",
    "hash",
})


def _supports_correlated_ioc(
    ioc: IOC,
    original: object,
) -> bool:
    """Revalidate a claimed IOC against an upstream finding."""

    if not isinstance(original, ThreatFinding):
        return False

    if (
        original.source == "IOC + Web Correlation"
        or original.ioc_match is not True
    ):
        return False

    scalar_claim = (
        original.ioc_type == ioc.ioc_type
        and original.ioc_value == ioc.value
        and original.ioc_source == ioc.source
    )

    multi_claim = any(
        isinstance(record, dict)
        and record.get("ioc_type") == ioc.ioc_type
        and record.get("value") == ioc.value
        and record.get("source") == ioc.source
        for record in (original.ioc_matches or [])
    )

    return (
        (scalar_claim or multi_claim)
        and _matches_finding(ioc, original)
    )


def _matches_finding(ioc: IOC, finding: ThreatFinding) -> bool:
    """Match an IOC against supported finding evidence."""

    if finding.source == "IOC + Web Correlation":
        upstream = getattr(
            finding,
            "_core08_correlation_sources",
            None,
        )

        if (
            not isinstance(upstream, tuple)
            or not upstream
            or finding.ioc_match is not True
            or finding.ioc_type != ioc.ioc_type
            or finding.ioc_value != ioc.value
            or finding.ioc_source != ioc.source
        ):
            return False

        return any(
            _supports_correlated_ioc(ioc, original)
            for original in upstream
        )

    # PCAP-generated narratives describe earlier detector results.
    # They are not independent evidence of an IOC match.
    if (
        finding.source == "PCAP Network Detection"
        and ioc.ioc_type in ("ip", "domain", "url")
    ):
        observation = finding.ioc_observation

        allowed_fields = {
            "ip": ("src_ip", "dst_ip"),
            "domain": ("dns_query", "http_host"),
            "url": ("http_uri_path",),
        }

        if not isinstance(observation, dict):
            return False

        if observation.get("field") not in allowed_fields[
            ioc.ioc_type
        ]:
            if ioc.ioc_type != "url":
                return False

            return (
                finding.ioc_match is True
                and finding.ioc_type == ioc.ioc_type
                and finding.ioc_value == ioc.value
                and finding.ioc_source == ioc.source
                and getattr(
                    finding,
                    "_core08_verified_url_ioc",
                    None,
                ) == (
                    ioc.ioc_type,
                    ioc.value,
                    ioc.source,
                )
            )

        return ioc_matches(
            ioc.ioc_type,
            ioc.value,
            observation.get("value", ""),
        )

    if ioc.ioc_type == "ip":
        observation = getattr(
            finding, "ioc_observation", {}
        )

        observed_value = (
            observation.get("value", "")
            if isinstance(observation, dict)
            and observation.get("field") in (
                "src_ip", "dst_ip"
            )
            else ""
        )

        return (
            ioc_matches("ip", ioc.value, finding.ip)
            or ioc_matches(
                "ip", ioc.value, observed_value
            )
        )

    if ioc.ioc_type == "domain":
        return any((
            ioc_matches(
                "domain",
                ioc.value,
                finding.hostname,
            ),
            ioc_matches(
                "domain",
                ioc.value,
                finding.description,
                prose=True,
            ),
            ioc_matches(
                "domain",
                ioc.value,
                finding.title,
                prose=True,
            ),
        ))

    if ioc.ioc_type in ("url", "hash"):
        return any((
            ioc_matches(
                ioc.ioc_type,
                ioc.value,
                finding.description,
                prose=True,
            ),
            ioc_matches(
                ioc.ioc_type,
                ioc.value,
                finding.title,
                prose=True,
            ),
        ))

    return False


def _ioc_sort_key(ioc: IOC) -> tuple:
    """Stable ordering, highest confidence first."""

    confidence_bonus = IOC_CONFIDENCE_BONUSES.get(
        ioc.confidence.lower(),
        0,
    )

    return (
        -confidence_bonus,
        ioc.ioc_type,
        ioc.value.casefold(),
        ioc.value,
        ioc.source,
        ioc.description,
        ioc.confidence,
    )


def match_iocs(finding: ThreatFinding) -> list[IOC]:
    """Return all independent matching IOCs deterministically."""

    matches = []
    seen = set()

    for ioc in get_iocs():
        if not _matches_finding(ioc, finding):
            continue

        identity = (
            ioc.ioc_type,
            ioc.value,
            ioc.source,
            ioc.confidence,
            ioc.description,
        )

        if identity in seen:
            continue

        seen.add(identity)
        matches.append(ioc)

    return sorted(matches, key=_ioc_sort_key)


def match_ioc(finding: ThreatFinding) -> IOC | None:
    """Backward-compatible primary IOC lookup."""

    matches = match_iocs(finding)

    return matches[0] if matches else None


def enrich_finding_with_ioc(
    finding: ThreatFinding,
) -> ThreatFinding:
    """Refresh IOC matches and preserve external detector identity."""

    identity = {
        "ioc_type": finding.ioc_type,
        "value": finding.ioc_value,
        "source": finding.ioc_source,
    }

    owns_primary = (
        bool(finding.ioc_enrichment_primary)
        and finding.ioc_enrichment_primary == identity
    )

    matches = match_iocs(finding)

    # Only freshly matched feed entries belong here.
    finding.ioc_matches = [
        asdict(ioc) for ioc in matches
    ]

    if not matches:
        if owns_primary:
            finding.ioc_match = False
            finding.ioc_type = ""
            finding.ioc_value = ""
            finding.ioc_confidence = ""
            finding.ioc_source = ""
            finding.ioc_description = ""

        finding.ioc_enrichment_primary = {}
        return finding

    # Preserve an existing identity owned by another detector.
    if (
        finding.ioc_match
        and finding.ioc_type
        and finding.ioc_value
        and not owns_primary
    ):
        finding.ioc_enrichment_primary = {}
        return finding

    primary = matches[0]

    finding.ioc_match = True
    finding.ioc_type = primary.ioc_type
    finding.ioc_value = primary.value
    finding.ioc_confidence = primary.confidence
    finding.ioc_source = primary.source
    finding.ioc_description = primary.description

    # Lifecycle metadata only, never a trust authorization.
    finding.ioc_enrichment_primary = {
        "ioc_type": primary.ioc_type,
        "value": primary.value,
        "source": primary.source,
    }

    return finding
