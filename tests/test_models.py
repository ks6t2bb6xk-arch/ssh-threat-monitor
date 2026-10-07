import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from ssh_monitor import Alert, AuthEvent, AuthOutcome, Severity


NOW = datetime(2026, 10, 5, 14, 3, 22, tzinfo=timezone.utc)


class AuthEventTests(unittest.TestCase):
    def test_ipv4_failure_with_known_method(self) -> None:
        event = AuthEvent(NOW, ip_address("203.0.113.10"), "root", AuthOutcome.FAILURE, "password")
        self.assertEqual(event.source_ip.version, 4)
        self.assertEqual(event.outcome, AuthOutcome.FAILURE)
        self.assertEqual(event.auth_method, "password")

    def test_ipv6_success_with_unknown_method(self) -> None:
        event = AuthEvent(NOW, ip_address("2001:db8::10"), None, AuthOutcome.SUCCESS, None)
        self.assertEqual(event.source_ip.version, 6)
        self.assertIsNone(event.auth_method)

    def test_naive_timestamp_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            AuthEvent(NOW.replace(tzinfo=None), ip_address("203.0.113.10"), "root", AuthOutcome.FAILURE, None)

    def test_event_is_immutable(self) -> None:
        event = AuthEvent(NOW, ip_address("203.0.113.10"), "root", AuthOutcome.FAILURE, None)
        with self.assertRaises(FrozenInstanceError):
            event.username = "admin"


class AlertTests(unittest.TestCase):
    def make_alert(self, **overrides: object) -> Alert:
        fields = {
            "detection_name": "SSH Brute Force",
            "source_ip": ip_address("2001:db8::10"),
            "severity": Severity.MEDIUM,
            "first_seen": NOW,
            "last_seen": NOW + timedelta(seconds=30),
            "attempt_count": 10,
            "threshold": 10,
            "window_seconds": 60,
        }
        fields.update(overrides)
        return Alert(**fields)

    def test_alert_carries_detection_context_and_mitre_mapping(self) -> None:
        alert = self.make_alert()
        self.assertEqual(alert.source_ip.version, 6)
        self.assertEqual(alert.attempt_count, alert.threshold)
        self.assertEqual(alert.window_seconds, 60)
        self.assertEqual(alert.mitre_technique_id, "T1110")

    def test_naive_alert_time_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            self.make_alert(last_seen=NOW.replace(tzinfo=None))

    def test_reversed_time_range_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not precede"):
            self.make_alert(last_seen=NOW - timedelta(seconds=1))

    def test_invalid_window_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            self.make_alert(window_seconds=0)


if __name__ == "__main__":
    unittest.main()
