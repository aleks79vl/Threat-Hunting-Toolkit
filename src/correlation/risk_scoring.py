import json

from src.models.threat_finding import ThreatFinding


def load_risk_scores(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as file:
        return json.load(file)


def _apply_base_risk_score(
    finding: ThreatFinding,
    calculated_score: int,
) -> ThreatFinding:
    existing_base = (
        finding.risk_score_base
        if finding.risk_score_base is not None
        else 0
    )

    base_score = max(existing_base, calculated_score)

    finding.risk_score_base = max(
        0,
        min(100, base_score),
    )

    total_score = (
        finding.risk_score_base
        + sum(finding.risk_factors.values())
    )

    finding.risk_score = max(
        0,
        min(100, total_score),
    )

    return finding


def calculate_risk_score(
    finding: ThreatFinding,
    config_path: str
) -> ThreatFinding:

    risk_config = load_risk_scores(config_path)

    title_score = risk_config.get(finding.title)

    if title_score is not None:
        return _apply_base_risk_score(
            finding,
            title_score,
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
        )
