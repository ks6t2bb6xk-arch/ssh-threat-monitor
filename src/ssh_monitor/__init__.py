"""Core data structures for SSH Threat Monitor."""

from .detector import BruteForceDetector, SSHThreatDetector, StateCapacityError
from .incident import alert_to_incident, format_terminal_alert
from .models import Alert, AuthEvent, AuthEventKind, AuthOutcome, CorrelationEvidence, Severity
from .parser import parse_line
from .sanitizer import sanitize_username

__all__ = [
    "Alert",
    "AuthEvent",
    "AuthEventKind",
    "AuthOutcome",
    "BruteForceDetector",
    "Severity",
    "SSHThreatDetector",
    "CorrelationEvidence",
    "StateCapacityError",
    "alert_to_incident",
    "format_terminal_alert",
    "parse_line",
    "sanitize_username",
]
