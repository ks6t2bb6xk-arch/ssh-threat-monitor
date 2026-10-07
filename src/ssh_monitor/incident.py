"""Structured and human-readable alert output."""

import json

from .models import Alert
from .sanitizer import sanitize_username


def alert_to_incident(alert: Alert) -> dict[str, str | int | None]:
    """Create a JSON-serializable incident with sanitized untrusted text."""
    return {
        "schema_version": 1,
        "detection": alert.detection_name,
        "severity": alert.severity.value.upper(),
        "source_ip": str(alert.source_ip),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "attempt_count": alert.attempt_count,
        "threshold": alert.threshold,
        "window_seconds": alert.window_seconds,
        "mitre_attack_technique": alert.mitre_technique_id,
        "latest_username": sanitize_username(alert.latest_username),
    }


def format_terminal_alert(alert: Alert) -> str:
    """Render one alert as a single terminal-safe line."""
    username = sanitize_username(alert.latest_username)
    user_part = f" | user={json.dumps(username, ensure_ascii=True)}" if username is not None else ""
    return (
        f"[{alert.severity.value.upper()}] {alert.detection_name} | "
        f"{alert.source_ip} | {alert.attempt_count} failures / {alert.window_seconds}s "
        f"(threshold {alert.threshold}) | {alert.last_seen.isoformat()}"
        f"{user_part}"
    )
