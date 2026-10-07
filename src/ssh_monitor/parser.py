"""Parse supported sshd authentication lines into normalized events."""

import re
from datetime import datetime, timezone, tzinfo
from ipaddress import ip_address

from .models import AuthEvent, AuthEventKind, AuthOutcome


_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_ISO_PREFIX = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+"
    r"sshd(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_AUTHENTICATION = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>password|publickey) "
    r"for (?:invalid user )?(?P<username>.+) from (?P<ip>\S+)"
    r"(?: port \d+)?(?:\s+.*)?$"
)
_INVALID_USER = re.compile(
    r"^Invalid user (?P<username>.+) from (?P<ip>\S+)"
    r"(?: port \d+)?(?:\s+.*)?$"
)
_MAX_ATTEMPTS = re.compile(
    r"^(?:error:\s*)?maximum authentication attempts exceeded "
    r"for (?:invalid user )?(?P<username>.+) from (?P<ip>\S+)"
    r"(?: port \d+)?(?:\s+.*)?$"
)
_MONTHS = {
    month: number
    for number, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


def _parse_timestamp(
    line: str, syslog_year: int | None, syslog_timezone: tzinfo | None
) -> tuple[datetime, str] | None:
    iso_match = _ISO_PREFIX.match(line)
    if iso_match:
        try:
            stamp = datetime.fromisoformat(iso_match.group("stamp"))
            if stamp.tzinfo is None or stamp.utcoffset() is None:
                return None
            return stamp.astimezone(timezone.utc), iso_match.group("message")
        except (ValueError, OverflowError):
            return None

    syslog_match = _SYSLOG_PREFIX.match(line)
    if not syslog_match:
        return None
    if syslog_year is None or syslog_timezone is None:
        raise ValueError("syslog lines require syslog_year and syslog_timezone")
    if isinstance(syslog_year, bool) or not isinstance(syslog_year, int):
        raise ValueError("syslog_year must be an integer year")
    if not isinstance(syslog_timezone, tzinfo):
        raise ValueError("syslog_timezone must be a tzinfo instance")
    try:
        hour, minute, second = map(int, syslog_match.group("clock").split(":"))
        stamp = datetime(
            syslog_year,
            _MONTHS[syslog_match.group("month")],
            int(syslog_match.group("day")),
            hour,
            minute,
            second,
            tzinfo=syslog_timezone,
        )
        if stamp.utcoffset() is None:
            raise ValueError("syslog_timezone must provide a UTC offset")
        return stamp.astimezone(timezone.utc), syslog_match.group("message")
    except (KeyError, ValueError, OverflowError):
        return None


def parse_line(
    line: str, *, syslog_year: int | None = None, syslog_timezone: tzinfo | None = None
) -> AuthEvent | None:
    """Parse one sshd line; return None for unsupported or malformed lines.

    Classic syslog timestamps omit year and timezone, so callers must supply both.
    A recognized syslog prefix without that context raises ValueError. Returned
    event timestamps are converted to UTC.
    """
    parsed = _parse_timestamp(line, syslog_year, syslog_timezone)
    if parsed is None:
        return None
    timestamp, message = parsed

    auth_match = _AUTHENTICATION.match(message)
    if auth_match:
        outcome = AuthOutcome.SUCCESS if auth_match.group("result") == "Accepted" else AuthOutcome.FAILURE
        method = auth_match.group("method")
        kind = AuthEventKind.AUTH_ATTEMPT
        match = auth_match
    else:
        match = _INVALID_USER.match(message)
        kind = AuthEventKind.INVALID_USER
        if match is None:
            match = _MAX_ATTEMPTS.match(message)
            kind = AuthEventKind.MAX_ATTEMPTS
        if match is None:
            return None
        outcome = AuthOutcome.FAILURE
        method = None

    try:
        source_ip = ip_address(match.group("ip"))
    except ValueError:
        return None
    return AuthEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=match.group("username"),
        outcome=outcome,
        auth_method=method,
        kind=kind,
    )
