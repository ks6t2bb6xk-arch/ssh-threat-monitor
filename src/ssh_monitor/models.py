"""Log-source-independent authentication and detection data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address


IPAddress = IPv4Address | IPv6Address


def _require_aware_datetime(value: datetime, field_name: str) -> None:
    """Reject times that cannot be compared reliably across log sources."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


def _require_ip_address(value: IPAddress, field_name: str) -> None:
    if not isinstance(value, (IPv4Address, IPv6Address)):
        raise TypeError(f"{field_name} must be an IPv4Address or IPv6Address")


class AuthOutcome(str, Enum):
    """The result of an SSH authentication attempt."""

    FAILURE = "failure"
    SUCCESS = "success"


class AuthEventKind(str, Enum):
    """Whether a line records an attempt or only related SSH context."""

    AUTH_ATTEMPT = "auth_attempt"
    INVALID_USER = "invalid_user"
    MAX_ATTEMPTS = "max_attempts"


class Severity(str, Enum):
    """Severity assigned by a detector, relative to its configured threshold."""

    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One normalized SSH authentication event.

    ``username`` is untrusted log content. Output adapters must sanitize it.
    ``auth_method`` is None when the log line does not identify a method.
    """

    timestamp: datetime
    source_ip: IPAddress
    username: str | None
    outcome: AuthOutcome
    auth_method: str | None
    kind: AuthEventKind = AuthEventKind.AUTH_ATTEMPT

    def __post_init__(self) -> None:
        _require_aware_datetime(self.timestamp, "timestamp")
        _require_ip_address(self.source_ip, "source_ip")
        if self.username is not None and not isinstance(self.username, str):
            raise TypeError("username must be a string or None")
        if not isinstance(self.outcome, AuthOutcome):
            raise TypeError("outcome must be an AuthOutcome")
        if self.auth_method is not None and not isinstance(self.auth_method, str):
            raise TypeError("auth_method must be a string or None")
        if not isinstance(self.kind, AuthEventKind):
            raise TypeError("kind must be an AuthEventKind")


@dataclass(frozen=True, slots=True)
class Alert:
    """A detection emitted for an IP within a configured time window."""

    detection_name: str
    source_ip: IPAddress
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    attempt_count: int
    threshold: int
    window_seconds: int
    mitre_technique_id: str = field(default="T1110")
    latest_username: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.detection_name, str) or not self.detection_name.strip():
            raise ValueError("detection_name must be a nonempty string")
        _require_ip_address(self.source_ip, "source_ip")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        _require_aware_datetime(self.first_seen, "first_seen")
        _require_aware_datetime(self.last_seen, "last_seen")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        for field_name in ("attempt_count", "threshold", "window_seconds"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer")
        if not isinstance(self.mitre_technique_id, str) or not self.mitre_technique_id.strip():
            raise ValueError("mitre_technique_id must be a nonempty string")
        if self.latest_username is not None and not isinstance(self.latest_username, str):
            raise TypeError("latest_username must be a string or None")
