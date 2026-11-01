import json
import hashlib

from src.models.threat_finding import ThreatFinding
from src.models.risk_scoring_contract import (
    RISK_SCORING_VERSION,
    validate_risk_factors,
    validate_risk_base_sources,
    validate_risk_scoring_policy,
)


def load_risk_scores(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as file:
        return json.load(file)


def calculate_policy_fingerprint(risk_config: dict) -> str:
    canonical_json = json.dumps(
        risk_config,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


def _apply_base_risk_score(
    finding: ThreatFinding,
    calculated_score: int,
    policy_hash: str,
) -> ThreatFinding:
    validate_risk_factors(finding.risk_factors)
    validate_risk_base_sources(finding.risk_base_sources)

    finding.risk_base_sources.pop(
        "legacy_unattributed",
        None,
    )

    finding.risk_base_sources["global_policy"] = max(
        0,
        min(100, calculated_score),
    )

    finding.risk_score_base = max(
        finding.risk_base_sources.values()
    )

    finding.risk_score = max(
        0,
        min(
            100,
            finding.risk_score_base
            + sum(finding.risk_factors.values()),
        ),
    )

    finding.scoring_version = RISK_SCORING_VERSION
    finding.scoring_policy_hash = policy_hash

    return finding


def calculate_risk_score(
    finding: ThreatFinding,
    config_path: str
) -> ThreatFinding:
    risk_config = load_risk_scores(config_path)

    validate_risk_scoring_policy(risk_config)

    policy_hash = calculate_policy_fingerprint(risk_config)
    title_score = risk_config.get(finding.title)

    if title_score is not None:
        return _apply_base_risk_score(
            finding,
            title_score,
            policy_hash,
        )

    severity_scores = risk_config["severity_scores"]
    bonus_scores = risk_config["bonus_scores"]

    score = severity_scores.get(finding.severity, 0)

    title_lower = finding.title.lower()
    description_lower = finding.description.lower()

    if "unknown" in title_lower or "unknown" in description_lower:
        score += bonus_scores.get("unknown_host", 0)

    if "critical port" in title_lower or "critical port" in description_lower:
        score += bonus_scores.get("critical_port", 0)

    if finding.port == 3389:
        score += bonus_scores.get("rdp_exposed", 0)

    if finding.port == 445:
        score += bonus_scores.get("smb_exposed", 0)

    if finding.port == 22:
        score += bonus_scores.get("ssh_exposed", 0)

    return _apply_base_risk_score(
        finding,
        score,
        policy_hash,
        )
