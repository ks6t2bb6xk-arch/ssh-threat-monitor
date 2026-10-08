"""Event-by-event, bounded-state SSH brute-force detection."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from .models import Alert, AuthEvent, AuthEventKind, AuthOutcome, CorrelationEvidence, Severity


_PRIVILEGED_USERS = frozenset({"root", "admin", "administrator"})
_SEVERITY_RANK = {Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class StateCapacityError(RuntimeError):
    """A new attempt cannot be tracked without exceeding configured limits."""


@dataclass(slots=True)
class _IPState:
    attempts: deque[tuple[datetime, bool]] = field(default_factory=deque)
    privileged_count: int = 0
    highest_alerted: Severity | None = None
    episode: int = 0


class BruteForceDetector:
    """Detect threshold crossings in an exact sliding window per source IP.

    Events must arrive in nondecreasing timestamp order. Context-only lines and
    successful authentications do not add failed attempts. Capacity errors are
    explicit so a caller cannot mistake dropped evidence for a quiet detector.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        *,
        max_ips: int = 4096,
        max_events: int = 100_000,
    ) -> None:
        for name, value in (
            ("threshold", threshold),
            ("window_seconds", window_seconds),
            ("max_ips", max_ips),
            ("max_events", max_events),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_events < threshold:
            raise ValueError("max_events must be at least threshold")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.max_ips = max_ips
        self.max_events = max_events
        try:
            self._window = timedelta(seconds=window_seconds)
        except OverflowError as exc:
            raise ValueError("window_seconds exceeds the supported timedelta range") from exc
        self._states: dict[IPv4Address | IPv6Address, _IPState] = {}
        self._stored_event_count = 0
        self._episode_sequence = 0
        self._last_processed_at: datetime | None = None

    @property
    def active_ip_count(self) -> int:
        """Number of IPs with at least one failure still in the window."""
        return len(self._states)

    @property
    def stored_event_count(self) -> int:
        """Number of failed-attempt timestamps currently retained."""
        return self._stored_event_count

    def _expire(self, now: datetime) -> None:
        try:
            cutoff = now - self._window
        except OverflowError:
            # The cutoff predates datetime.min: no representable event is expired.
            return
        for source_ip, state in list(self._states.items()):
            while state.attempts and state.attempts[0][0] < cutoff:
                _, was_privileged = state.attempts.popleft()
                self._stored_event_count -= 1
                if was_privileged:
                    state.privileged_count -= 1
            if len(state.attempts) < self.threshold:
                state.highest_alerted = None
            if not state.attempts:
                del self._states[source_ip]

    def _severity(self, count: int, has_privileged_target: bool) -> Severity:
        if count >= 5 * self.threshold:
            return Severity.CRITICAL
        if count >= 2 * self.threshold:
            return Severity.CRITICAL if has_privileged_target else Severity.HIGH
        return Severity.HIGH if has_privileged_target else Severity.MEDIUM

    def process(self, event: AuthEvent) -> Alert | None:
        """Consume one event and return a new or escalated alert, if any."""
        if not isinstance(event, AuthEvent):
            raise TypeError("event must be an AuthEvent")
        if self._last_processed_at is not None and event.timestamp < self._last_processed_at:
            raise ValueError("events must arrive in nondecreasing timestamp order")
        self._expire(event.timestamp)
        self._last_processed_at = event.timestamp

        if event.outcome is not AuthOutcome.FAILURE or event.kind is not AuthEventKind.AUTH_ATTEMPT:
            return None

        state = self._states.get(event.source_ip)
        if state is None and len(self._states) >= self.max_ips:
            raise StateCapacityError("maximum tracked IP count reached")
        if self._stored_event_count >= self.max_events:
            raise StateCapacityError("maximum stored failure count reached")
        if state is None:
            state = _IPState()
            self._states[event.source_ip] = state

        was_privileged = event.username is not None and event.username.casefold() in _PRIVILEGED_USERS
        state.attempts.append((event.timestamp, was_privileged))
        self._stored_event_count += 1
        if was_privileged:
            state.privileged_count += 1

        count = len(state.attempts)
        if count < self.threshold:
            return None
        if count == self.threshold:
            self._episode_sequence += 1
            state.episode = self._episode_sequence
        severity = self._severity(count, state.privileged_count > 0)
        if state.highest_alerted is not None and _SEVERITY_RANK[severity] <= _SEVERITY_RANK[state.highest_alerted]:
            return None
        state.highest_alerted = severity
        return Alert(
            detection_name="SSH Brute Force",
            source_ip=event.source_ip,
            severity=severity,
            first_seen=state.attempts[0][0],
            last_seen=event.timestamp,
            attempt_count=count,
            threshold=self.threshold,
            window_seconds=self.window_seconds,
            latest_username=event.username,
        )

    def _correlation_snapshot(self, source_ip: IPv4Address | IPv6Address) -> tuple[int, Alert] | None:
        """Return bounded evidence for the current qualifying window after process()."""
        state = self._states.get(source_ip)
        if state is None or len(state.attempts) < self.threshold:
            return None
        return state.episode, Alert(
            detection_name="SSH Brute Force",
            source_ip=source_ip,
            severity=state.highest_alerted or self._severity(len(state.attempts), state.privileged_count > 0),
            first_seen=state.attempts[0][0],
            last_seen=state.attempts[-1][0],
            attempt_count=len(state.attempts),
            threshold=self.threshold,
            window_seconds=self.window_seconds,
        )


@dataclass(slots=True)
class _AttackSummary:
    episode: int
    alert: Alert
    consumed: bool = False


class SSHThreatDetector:
    """Compose V1 brute-force detection with bounded IP-level success correlation.

    Summary lifetimes use event time, not wall-clock time. Equal timestamps use
    input order. Consumed episodes remain deduplicated while above threshold.
    """

    def __init__(
        self, threshold: int = 10, window_seconds: int = 60, *,
        correlation_window_seconds: int = 300, max_ips: int = 4096,
        max_events: int = 100_000, max_correlation_ips: int = 4096,
    ) -> None:
        for name, value in (("correlation_window_seconds", correlation_window_seconds),
                            ("max_correlation_ips", max_correlation_ips)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        try:
            self._correlation_window = timedelta(seconds=correlation_window_seconds)
        except OverflowError as exc:
            raise ValueError("correlation_window_seconds exceeds the supported timedelta range") from exc
        self.brute_force = BruteForceDetector(threshold, window_seconds, max_ips=max_ips, max_events=max_events)
        self.correlation_window_seconds = correlation_window_seconds
        self.max_correlation_ips = max_correlation_ips
        self._summaries: dict[IPv4Address | IPv6Address, _AttackSummary] = {}

    @property
    def correlation_ip_count(self) -> int:
        return len(self._summaries)

    def process(self, event: AuthEvent) -> Alert | None:
        alert = self.brute_force.process(event)
        for source_ip, summary in list(self._summaries.items()):
            age = event.timestamp - summary.alert.last_seen
            if age > self._correlation_window:
                current = self.brute_force._correlation_snapshot(source_ip)
                # Retain a consumed marker for an ongoing episode, even when a
                # correlation window is shorter than the brute-force window.
                if current is None or current[0] != summary.episode:
                    del self._summaries[source_ip]
        if event.kind is not AuthEventKind.AUTH_ATTEMPT:
            return alert
        if event.outcome is AuthOutcome.FAILURE:
            snapshot = self.brute_force._correlation_snapshot(event.source_ip)
            if snapshot is not None:
                episode, evidence = snapshot
                previous = self._summaries.get(event.source_ip)
                if previous is None and len(self._summaries) >= self.max_correlation_ips:
                    raise StateCapacityError("maximum correlation IP count reached")
                consumed = previous is not None and previous.episode == episode and previous.consumed
                self._summaries[event.source_ip] = _AttackSummary(episode, evidence, consumed)
            return alert
        summary = self._summaries.get(event.source_ip)
        if summary is None or summary.consumed or event.auth_method not in ("password", "publickey"):
            return alert
        if event.timestamp - summary.alert.last_seen > self._correlation_window:
            return alert
        summary.consumed = True
        attack = summary.alert
        return Alert(
            detection_name="SSH Successful Login After Brute Force",
            source_ip=event.source_ip,
            severity=Severity.CRITICAL if attack.severity is Severity.CRITICAL else Severity.HIGH,
            first_seen=attack.first_seen, last_seen=event.timestamp,
            attempt_count=attack.attempt_count, threshold=attack.threshold,
            window_seconds=attack.window_seconds, latest_username=event.username,
            correlation=CorrelationEvidence(
                last_failure_at=attack.last_seen, success_at=event.timestamp,
                successful_username=event.username, auth_method=event.auth_method,
                window_seconds=self.correlation_window_seconds,
            ),
        )
