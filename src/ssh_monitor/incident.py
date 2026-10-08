"""Structured and human-readable alert output."""

import json

from .models import Alert
from .sanitizer import sanitize_username


def detection_type(alert: Alert) -> str:
    return "successful_login_after_brute_force" if alert.correlation else "brute_force"


def alert_reason(alert: Alert) -> str:
    base = (f"{alert.attempt_count} failed authentication attempts from this IP within "
            f"{alert.window_seconds}s (threshold {alert.threshold}).")
    if alert.correlation:
        elapsed = (alert.correlation.success_at - alert.correlation.last_failure_at).total_seconds()
        return (f"{base} Successful {alert.correlation.auth_method} login {elapsed:g}s after "
                "the last qualifying failure. IP-level correlation only; the successful "
                "account may differ from targeted accounts. Investigate; compromise is not established.")
    return base + " Severity uses threshold-relative bands and a privileged-target uplift."


def alert_to_incident(alert: Alert) -> dict[str, object]:
    """Create schema v2 output; all untrusted usernames are sanitized here."""
    evidence = alert.correlation
    return {
        "schema_version": 2,
        "detection": alert.detection_name,
        "detection_type": detection_type(alert),
        "reason": alert_reason(alert),
        "severity": alert.severity.value.upper(),
        "source_ip": str(alert.source_ip),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "attempt_count": alert.attempt_count,
        "threshold": alert.threshold,
        "window_seconds": alert.window_seconds,
        "mitre_attack_technique": alert.mitre_technique_id,
        "latest_username": sanitize_username(alert.latest_username),
        "correlation": None if evidence is None else {
            "last_failure_at": evidence.last_failure_at.isoformat(),
            "success_at": evidence.success_at.isoformat(),
            "successful_username": sanitize_username(evidence.successful_username),
            "auth_method": evidence.auth_method,
            "window_seconds": evidence.window_seconds,
        },
    }


def format_terminal_alert(alert: Alert) -> str:
    """Render one alert as a single terminal-safe line."""
    username = sanitize_username(alert.latest_username)
    user_part = f" | user={json.dumps(username, ensure_ascii=True)}" if username is not None else ""
    evidence = alert.correlation
    correlation_part = ""
    if evidence:
        elapsed = (evidence.success_at - evidence.last_failure_at).total_seconds()
        correlation_part = (f" | successful {evidence.auth_method} login {elapsed:g}s after last failure"
                            " | IP correlation; investigate, compromise not established")
    return (
        f"[{alert.severity.value.upper()}] {alert.detection_name} | "
        f"{alert.source_ip} | {alert.attempt_count} failures / {alert.window_seconds}s "
        f"(threshold {alert.threshold}) | {alert.last_seen.isoformat()}"
        f"{user_part}{correlation_part}"
    )
