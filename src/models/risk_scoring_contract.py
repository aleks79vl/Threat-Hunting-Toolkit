"""Shared metadata for Evidence-Based Risk Scoring V1."""

RISK_SCORING_VERSION = "1.0"


def validate_risk_factors(
    factors: dict[str, int],
) -> None:
    """Reject invalid risk factor identifiers and contributions."""

    if not isinstance(factors, dict):
        raise ValueError("risk_factors must be a dictionary")

    for factor_id, contribution in factors.items():
        if (
            not isinstance(factor_id, str)
            or not factor_id.strip()
            or type(contribution) is not int
            or contribution < 0
        ):
            raise ValueError(
                f"risk_factors[{factor_id!r}] must be "
                "a non-negative integer"
            )


def validate_risk_base_sources(
    sources: dict[str, int],
) -> None:
    """Validate registered base risk scoring sources."""

    if not isinstance(sources, dict):
        raise ValueError(
            "risk_base_sources must be a dictionary"
        )

    for source_id, score in sources.items():
        if (
            not isinstance(source_id, str)
            or not source_id.strip()
        ):
            raise ValueError(
                "risk_base_sources must have "
                "non-empty string identifiers"
            )

        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError(
                f"risk_base_sources[{source_id!r}] "
                "must be an integer between 0 and 100"
            )


def validate_risk_scoring_policy(
    policy: dict,
) -> None:
    """Validate Risk Scoring V1 policy before calculation."""

    if not isinstance(policy, dict):
        raise ValueError(
            "risk_scores must be a dictionary"
        )

    for section in ("severity_scores", "bonus_scores"):
        values = policy.get(section)

        if not isinstance(values, dict):
            raise ValueError(
                f"risk_scores.{section} must be a dictionary"
            )

        for key, value in values.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(
                    f"risk_scores.{section} contains "
                    "an invalid key"
                )

            if type(value) is not int:
                raise ValueError(
                    f"risk_scores.{section}[{key!r}] "
                    "must be an integer"
                )

            if section == "severity_scores":
                if not 0 <= value <= 100:
                    raise ValueError(
                        f"risk_scores.{section}[{key!r}] "
                        "must be between 0 and 100"
                    )

            elif value < 0:
                raise ValueError(
                    f"risk_scores.{section}[{key!r}] "
                    "must be non-negative"
                )

    # All remaining top-level entries are title-specific scores.
    for title, score in policy.items():
        if title in ("severity_scores", "bonus_scores"):
            continue

        if not isinstance(title, str) or not title.strip():
            raise ValueError(
                "risk_scores contains an invalid finding title"
            )

        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError(
                f"risk_scores[{title!r}] "
                "must be an integer between 0 and 100"
            )


def validate_risk_score_value(
    value: int,
    field_name: str = "risk_score",
) -> None:
    """Validate a normalized Risk Scoring V1 value."""

    if type(value) is not int or not 0 <= value <= 100:
        raise ValueError(
            f"{field_name} must be "
            "an integer between 0 and 100"
        )
