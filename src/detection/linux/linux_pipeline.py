from pathlib import Path

from src.parsers.linux_auth_parser import parse_auth_log
from src.parsers.linux_syslog_parser import parse_syslog

from src.detection.linux.advanced_risk_scoring import (
    calculate_advanced_linux_risk_score,
)
from src.detection.linux.advanced_telnet_detector import (
    detect_advanced_telnet_activity,
)
from src.detection.linux.audit_tampering_detector import (
    detect_linux_audit_tampering,
)
from src.detection.linux.cron_activity_detector import (
    detect_suspicious_cron_activity,
)
from src.detection.linux.cron_persistence_detector import (
    detect_linux_cron_persistence,
)
from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.file_permission_detector import (
    detect_suspicious_file_permissions,
)
from src.detection.linux.log_clearing_detector import (
    detect_linux_log_clearing,
)
from src.detection.linux.mitre_mapping import (
    get_linux_mitre_techniques,
)
from src.detection.linux.reverse_shell_detector import (
    detect_linux_reverse_shells,
)
from src.detection.linux.service_manipulation_detector import (
    detect_linux_service_manipulation,
)
from src.detection.linux.ssh_bruteforce_detector import (
    detect_ssh_bruteforce,
)
from src.detection.linux.ssh_failed_login_detector import (
    detect_ssh_failed_logins,
)
from src.detection.linux.ssh_persistence_detector import (
    detect_linux_ssh_persistence,
)
from src.detection.linux.sudo_abuse_detector import detect_sudo_abuse
from src.detection.linux.successful_login_after_failures_detector import (
    detect_successful_login_after_failures,
)
from src.detection.linux.suspicious_process_detector import (
    detect_suspicious_linux_processes,
)
from src.detection.linux.systemd_persistence_detector import (
    detect_linux_systemd_persistence,
)
from src.detection.linux.telnet_detector import detect_telnet_activity
from src.detection.linux.user_privilege_detector import (
    detect_linux_user_privilege_activity,
)
from src.models.domain_pipeline_result import DomainPipelineResult
from src.models.linux_process_execution import LinuxProcessExecution
from src.reporting.linux_execution_statistics import (
    generate_linux_execution_statistics,
)
from src.reporting.linux_statistics import generate_linux_statistics


def run_linux_detection_pipeline(
    linux_auth_file: str,
    linux_syslog_file: str,
) -> DomainPipelineResult:
    linux_auth_events = []
    linux_syslog_events = []

    if Path(linux_auth_file).exists():
        linux_auth_events = parse_auth_log(linux_auth_file)

    if Path(linux_syslog_file).exists():
        linux_syslog_events = parse_syslog(linux_syslog_file)

    linux_events = linux_auth_events + linux_syslog_events
    linux_findings = []
    linux_executions = []
    advanced_linux_findings = []

    if linux_events:
        linux_findings.extend(
            detect_ssh_failed_logins(linux_events)
        )
        linux_findings.extend(
            detect_ssh_bruteforce(linux_events)
        )
        linux_findings.extend(
            detect_successful_login_after_failures(
                linux_events
            )
        )
        linux_findings.extend(
            detect_telnet_activity(linux_events)
        )
        linux_findings.extend(
            detect_sudo_abuse(linux_events)
        )
        linux_findings.extend(
            detect_linux_user_privilege_activity(
                linux_events
            )
        )
        linux_findings.extend(
            detect_suspicious_cron_activity(
                linux_events
            )
        )
        linux_findings.extend(
            detect_linux_service_manipulation(
                linux_events
            )
        )

        for event in linux_events:
            context = LinuxDetectionContext.from_event(event)
            execution = LinuxProcessExecution.from_context(context)

            if execution.searchable_text():
                linux_executions.append(execution)

        for execution in linux_executions:
            execution_findings = []

            execution_findings.extend(
                detect_suspicious_linux_processes([execution])
            )
            execution_findings.extend(
                detect_linux_reverse_shells([execution])
            )
            execution_findings.extend(
                detect_advanced_telnet_activity([execution])
            )
            execution_findings.extend(
                detect_linux_ssh_persistence([execution])
            )
            execution_findings.extend(
                detect_linux_audit_tampering([execution])
            )
            execution_findings.extend(
                detect_linux_log_clearing([execution])
            )
            execution_findings.extend(
                detect_suspicious_file_permissions([execution])
            )
            execution_findings.extend(
                detect_linux_systemd_persistence([execution])
            )
            execution_findings.extend(
                detect_linux_cron_persistence([execution])
            )

            for finding in execution_findings:
                finding.risk_score = calculate_advanced_linux_risk_score(
                    finding,
                    execution,
                )

                techniques = get_linux_mitre_techniques(finding)

                if techniques:
                    primary_technique = techniques[0]
                    finding.technique = primary_technique.technique_id
                    finding.technique_name = (
                        primary_technique.technique_name
                    )
                    finding.tactic = primary_technique.tactic

                advanced_linux_findings.append(finding)

        linux_findings.extend(advanced_linux_findings)

    return DomainPipelineResult(
        events=linux_events,
        findings=linux_findings,
        statistics={
            "linux_statistics": generate_linux_statistics(
                linux_events
            ),
            "linux_execution_statistics": (
                generate_linux_execution_statistics(
                    linux_executions,
                    advanced_linux_findings,
                )
            ),
        },
    )