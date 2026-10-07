import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from ssh_monitor import (
    AuthEvent,
    AuthEventKind,
    AuthOutcome,
    BruteForceDetector,
    Severity,
    StateCapacityError,
    parse_line,
)


START = datetime(2026, 10, 5, 14, 0, 0, tzinfo=timezone.utc)


def event(
    second: int,
    *,
    source_ip: str = "203.0.113.10",
    username: str = "alice",
    outcome: AuthOutcome = AuthOutcome.FAILURE,
    kind: AuthEventKind = AuthEventKind.AUTH_ATTEMPT,
) -> AuthEvent:
    return AuthEvent(
        timestamp=START + timedelta(seconds=second),
        source_ip=ip_address(source_ip),
        username=username,
        outcome=outcome,
        auth_method="password" if kind is AuthEventKind.AUTH_ATTEMPT else None,
        kind=kind,
    )


class BruteForceDetectorTests(unittest.TestCase):
    def test_window_before_datetime_min_keeps_valid_events(self) -> None:
        detector = BruteForceDetector(threshold=2)
        earliest = AuthEvent(
            datetime.min.replace(tzinfo=timezone.utc), ip_address("203.0.113.10"),
            "alice", AuthOutcome.FAILURE, "password",
        )
        self.assertIsNone(detector.process(earliest))
        self.assertEqual(detector.process(earliest).attempt_count, 2)

    def test_unrepresentable_window_is_a_configuration_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "window_seconds"):
            BruteForceDetector(window_seconds=10**21)

    def test_threshold_and_separate_ipv4_ipv6_state(self) -> None:
        detector = BruteForceDetector(threshold=3, window_seconds=60)
        self.assertIsNone(detector.process(event(0)))
        self.assertIsNone(detector.process(event(1, source_ip="2001:db8::10")))
        self.assertIsNone(detector.process(event(2)))
        alert = detector.process(event(3))
        self.assertEqual(alert.source_ip, ip_address("203.0.113.10"))
        self.assertEqual(alert.attempt_count, 3)
        self.assertEqual(alert.severity, Severity.MEDIUM)
        self.assertEqual(detector.active_ip_count, 2)

    def test_window_boundary_and_expiration(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        self.assertIsNone(detector.process(event(0)))
        alert = detector.process(event(60))
        self.assertEqual(alert.attempt_count, 2)  # The exact boundary is included.
        self.assertEqual(detector.process(event(61)).severity, Severity.MEDIUM)
        self.assertEqual(detector.stored_event_count, 2)
        self.assertEqual(detector.process(event(122)), None)
        self.assertEqual(detector.stored_event_count, 1)
        self.assertEqual(detector.active_ip_count, 1)

    def test_deduplication_and_threshold_relative_escalation(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        alerts = [detector.process(event(0))]
        for second in range(1, 11):
            alerts.append(detector.process(event(second)))
        emitted = [(alert.attempt_count, alert.severity) for alert in alerts if alert is not None]
        self.assertEqual(
            emitted,
            [(2, Severity.MEDIUM), (4, Severity.HIGH), (10, Severity.CRITICAL)],
        )

    def test_privileged_target_raises_severity_one_level(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        self.assertIsNone(detector.process(event(0, username="ROOT")))
        self.assertEqual(detector.process(event(1)).severity, Severity.HIGH)
        self.assertIsNone(detector.process(event(2)))
        self.assertEqual(detector.process(event(3)).severity, Severity.CRITICAL)

    def test_deduplication_resets_after_activity_falls_below_threshold(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=10)
        self.assertIsNone(detector.process(event(0)))
        self.assertEqual(detector.process(event(1)).severity, Severity.MEDIUM)
        self.assertIsNone(detector.process(event(12)))
        self.assertEqual(detector.process(event(13)).severity, Severity.MEDIUM)

    def test_context_lines_do_not_double_count_authentication_failure(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        invalid = parse_line(
            "2026-10-05T14:00:00Z host sshd[123]: Invalid user alice "
            "from 203.0.113.10 port 50123"
        )
        failed = parse_line(
            "2026-10-05T14:00:01Z host sshd[123]: Failed password for invalid user alice "
            "from 203.0.113.10 port 50123 ssh2"
        )
        max_attempts = parse_line(
            "2026-10-05T14:00:02Z host sshd[123]: error: maximum authentication attempts exceeded "
            "for invalid user alice from 203.0.113.10 port 50123 ssh2 [preauth]"
        )
        self.assertIsNone(detector.process(invalid))
        self.assertIsNone(detector.process(failed))
        self.assertIsNone(detector.process(max_attempts))
        self.assertEqual(detector.stored_event_count, 1)

    def test_success_does_not_add_a_failure_in_v1(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        self.assertIsNone(detector.process(event(0)))
        self.assertIsNone(detector.process(event(1, outcome=AuthOutcome.SUCCESS)))
        self.assertEqual(detector.stored_event_count, 1)

    def test_inactive_ip_state_is_removed(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=10)
        detector.process(event(0))
        detector.process(event(1, source_ip="2001:db8::10"))
        detector.process(event(12, source_ip="198.51.100.20", outcome=AuthOutcome.SUCCESS))
        self.assertEqual(detector.active_ip_count, 0)
        self.assertEqual(detector.stored_event_count, 0)

    def test_ip_capacity_error_and_recovery_after_expiration(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=10, max_ips=1)
        detector.process(event(0))
        with self.assertRaisesRegex(StateCapacityError, "tracked IP"):
            detector.process(event(1, source_ip="2001:db8::10"))
        self.assertIsNone(detector.process(event(11, source_ip="2001:db8::10")))
        self.assertEqual(detector.active_ip_count, 1)

    def test_event_capacity_error_and_recovery_after_expiration(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=10, max_events=2)
        detector.process(event(0))
        detector.process(event(1))
        with self.assertRaisesRegex(StateCapacityError, "stored failure"):
            detector.process(event(2))
        self.assertIsNone(detector.process(event(12)))
        self.assertEqual(detector.stored_event_count, 1)

    def test_out_of_order_events_are_rejected(self) -> None:
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        detector.process(event(2))
        with self.assertRaisesRegex(ValueError, "nondecreasing"):
            detector.process(event(1))

    def test_invalid_configuration_is_rejected(self) -> None:
        for kwargs in ({"threshold": 0}, {"window_seconds": 0}, {"max_ips": 0}, {"max_events": 1, "threshold": 2}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                BruteForceDetector(**kwargs)


if __name__ == "__main__":
    unittest.main()
