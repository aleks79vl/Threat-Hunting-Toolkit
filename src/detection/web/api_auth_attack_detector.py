from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_api_auth_attacks(
    events: list[WebInfrastructureEvent],
    *,
    minimum_failures: int = 5,
    minimum_accounts: int = 3,
) -> list[ThreatFinding]:
    if minimum_failures < 1:
        raise ValueError(
            "minimum_failures must be at least 1"
        )

    if minimum_accounts < 1:
        raise ValueError(
            "minimum_accounts must be at least 1"
        )

    failures_by_ip_and_account = defaultdict(list)
    failed_accounts_by_ip = defaultdict(set)

    for event in events:
        if event.source != "api_gateway":
            continue

        if event.metadata.get("auth_status") != "failure":
            continue

        principal_id = event.metadata.get("principal_id", "")

        if not principal_id:
            continue

        failures_by_ip_and_account[
            (event.client_ip, principal_id)
        ].append(event)

        failed_accounts_by_ip[event.client_ip].add(principal_id)

    findings = []

    for (
        client_ip,
        principal_id,
    ), failed_events in failures_by_ip_and_account.items():
        if len(failed_events) < minimum_failures:
            continue

        findings.append(
            ThreatFinding(
                title="Potential API Brute Force Attack",
                severity="high",
                description=(
                    f"IP address {client_ip!r} generated "
                    f"{len(failed_events)} failed authentication "
                    f"attempts for account {principal_id!r}."
                ),
                source="API Authentication Attack Detector",
                ip=client_ip,
                hostname=failed_events[0].virtual_host,
                port=failed_events[0].server_port,
                recommendation=(
                    "Apply account-based rate limiting, progressive "
                    "delays, MFA, and alerting for repeated failures."
                ),
            )
        )

    for client_ip, principal_ids in failed_accounts_by_ip.items():
        if len(principal_ids) < minimum_accounts:
            continue

        findings.append(
            ThreatFinding(
                title="Potential API Credential Stuffing Attack",
                severity="high",
                description=(
                    f"IP address {client_ip!r} generated failed "
                    "authentication attempts for "
                    f"{len(principal_ids)} different accounts."
                ),
                source="API Authentication Attack Detector",
                ip=client_ip,
                recommendation=(
                    "Apply IP-based rate limiting, bot protection, "
                    "credential-stuffing controls, and MFA."
                ),
            )
        )

    return findings