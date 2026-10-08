import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from ssh_monitor import (
    Alert, AuthEvent, AuthEventKind, AuthOutcome, CorrelationEvidence,
    SSHThreatDetector, Severity, StateCapacityError, alert_to_incident,
    format_terminal_alert,
)

START = datetime(2026, 10, 5, 14, tzinfo=timezone.utc)


def event(second, *, success=False, ip="203.0.113.10", username="alice", method="password", kind=AuthEventKind.AUTH_ATTEMPT):
    return AuthEvent(START + timedelta(seconds=second), ip_address(ip), username,
                     AuthOutcome.SUCCESS if success else AuthOutcome.FAILURE, method, kind)


class CorrelationTests(unittest.TestCase):
    def detector(self, **kwargs):
        return SSHThreatDetector(threshold=2, window_seconds=10, **kwargs)

    def attack(self, detector, **kwargs):
        detector.process(event(0, **kwargs))
        return detector.process(event(1, **kwargs))

    def test_below_threshold_and_unrelated_ip_do_not_correlate(self):
        detector = self.detector()
        detector.process(event(0))
        self.assertIsNone(detector.process(event(0, success=True)))
        detector.process(event(1))
        self.assertIsNone(detector.process(event(2, success=True, ip="198.51.100.20")))
        self.assertIsNotNone(detector.process(event(2, success=True)))

    def test_both_methods_and_ipv6_with_a_different_successful_account(self):
        for method in ("password", "publickey"):
            with self.subTest(method=method):
                detector = self.detector()
                self.attack(detector, ip="2001:db8::10")
                alert = detector.process(event(2, success=True, ip="2001:db8::10", username="bob", method=method))
                self.assertEqual(alert.severity, Severity.HIGH)
                self.assertEqual(alert.attempt_count, 2)
                self.assertEqual(alert.correlation.successful_username, "bob")
                self.assertEqual(alert.correlation.auth_method, method)
                self.assertEqual(alert.correlation.last_failure_at, START + timedelta(seconds=1))

    def test_inclusive_correlation_boundary_after_failure_window_has_expired(self):
        for second, expected in ((301, True), (302, False)):
            with self.subTest(second=second):
                detector = self.detector()
                self.attack(detector)
                alert = detector.process(event(second, success=True))
                self.assertEqual(alert is not None, expected)
                self.assertEqual(detector.brute_force.stored_event_count, 0)
                if not expected:
                    self.assertEqual(detector.correlation_ip_count, 0)

    def test_latest_qualifying_failure_refreshes_summary_even_without_new_alert(self):
        detector = self.detector()
        self.attack(detector)
        self.assertIsNone(detector.process(event(9)))
        alert = detector.process(event(309, success=True))
        self.assertEqual(alert.attempt_count, 3)
        self.assertEqual(alert.correlation.last_failure_at, START + timedelta(seconds=9))

    def test_microsecond_past_boundary_is_expired(self):
        detector = self.detector()
        self.attack(detector)
        late = replace(event(301, success=True), timestamp=START + timedelta(seconds=301, microseconds=1))
        self.assertIsNone(detector.process(late))

    def test_subthreshold_failure_does_not_refresh_summary(self):
        detector = self.detector()
        self.attack(detector)
        detector.process(event(100))
        self.assertIsNone(detector.process(event(302, success=True)))

    def test_repeated_success_and_continuing_failures_do_not_rearm_same_episode(self):
        detector = self.detector()
        self.attack(detector)
        self.assertIsNotNone(detector.process(event(2, success=True)))
        self.assertIsNone(detector.process(event(2, success=True)))
        detector.process(event(3))
        self.assertIsNone(detector.process(event(4, success=True)))
        detector.process(event(20))
        detector.process(event(21))
        self.assertIsNotNone(detector.process(event(22, success=True)))

    def test_consumed_marker_survives_short_correlation_window_in_active_episode(self):
        detector = self.detector(correlation_window_seconds=1)
        self.attack(detector)
        detector.process(event(1, success=True))
        detector.process(event(4, success=True))
        detector.process(event(5))
        self.assertIsNone(detector.process(event(5, success=True)))

    def test_critical_severity_is_retained(self):
        detector = self.detector()
        for second in range(4):
            detector.process(event(second, username="root"))
        alert = detector.process(event(4, success=True))
        self.assertEqual(alert.severity, Severity.CRITICAL)

    def test_snapshot_preserves_episode_peak_severity_and_latest_count(self):
        detector = self.detector()
        detector.process(event(0, username="root"))
        detector.process(event(1))
        detector.process(event(2))
        detector.process(event(3))  # CRITICAL at four failures with a root target.
        detector.process(event(11))  # Root expires; the episode remains above threshold.
        alert = detector.process(event(12, success=True))
        self.assertEqual(alert.severity, Severity.CRITICAL)
        self.assertEqual(alert.attempt_count, 4)

    def test_context_and_unknown_success_method_do_not_consume_summary(self):
        detector = self.detector()
        self.attack(detector)
        self.assertIsNone(detector.process(event(2, success=True, kind=AuthEventKind.INVALID_USER)))
        self.assertIsNone(detector.process(event(2, success=True, method=None)))
        self.assertIsNotNone(detector.process(event(2, success=True)))

    def test_same_timestamp_uses_file_order(self):
        detector = self.detector()
        self.assertIsNone(detector.process(event(0, success=True)))
        detector.process(event(0))
        detector.process(event(0))
        self.assertIsNotNone(detector.process(event(0, success=True)))

    def test_summary_capacity_fails_explicitly_and_recovers_after_expiry(self):
        detector = self.detector(max_correlation_ips=1)
        self.attack(detector)
        detector.process(event(12, ip="198.51.100.20"))
        with self.assertRaisesRegex(StateCapacityError, "correlation IP"):
            detector.process(event(13, ip="198.51.100.20"))
        detector.process(event(400, ip="198.51.100.20"))
        self.assertIsNotNone(detector.process(event(401, ip="198.51.100.20")))
        self.assertEqual(detector.correlation_ip_count, 1)

    def test_underlying_capacity_and_event_order_errors_are_preserved(self):
        detector = self.detector(max_events=2, max_ips=1)
        self.attack(detector)
        with self.assertRaisesRegex(ValueError, "nondecreasing"):
            detector.process(event(0))
        with self.assertRaisesRegex(StateCapacityError, "stored failure"):
            detector.process(event(2))
        with self.assertRaisesRegex(StateCapacityError, "tracked IP"):
            detector.process(event(3, ip="198.51.100.20"))
        with self.assertRaises(TypeError):
            detector.process(None)

    def test_brute_force_regression_and_context_counts(self):
        detector = self.detector()
        alerts = []
        for second in range(10):
            detector.process(event(second, kind=AuthEventKind.INVALID_USER))
            alert = detector.process(event(second))
            if alert:
                alerts.append((alert.attempt_count, alert.severity))
        self.assertEqual(alerts, [(2, Severity.MEDIUM), (4, Severity.HIGH), (10, Severity.CRITICAL)])
        self.assertEqual(detector.brute_force.stored_event_count, 10)

    def test_invalid_configuration(self):
        for kwargs in ({"correlation_window_seconds": 0}, {"correlation_window_seconds": True},
                       {"correlation_window_seconds": 10**21}, {"max_correlation_ips": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.detector(**kwargs)

    def test_datetime_extremes(self):
        for stamp in (datetime.min.replace(tzinfo=timezone.utc), datetime.max.replace(tzinfo=timezone.utc)):
            with self.subTest(stamp=stamp):
                detector = self.detector()
                first = replace(event(0), timestamp=stamp)
                detector.process(first)
                detector.process(first)
                self.assertIsNotNone(detector.process(replace(first, outcome=AuthOutcome.SUCCESS)))

    def test_schema_v2_and_terminal_evidence_are_sanitized(self):
        detector = self.detector()
        self.attack(detector)
        alert = detector.process(event(2, success=True, username="bad\n\x1bname"))
        incident = alert_to_incident(alert)
        self.assertEqual(incident["schema_version"], 2)
        self.assertEqual(incident["detection_type"], "successful_login_after_brute_force")
        self.assertEqual(incident["correlation"]["successful_username"], "badname")
        self.assertIn("compromise is not established", incident["reason"])
        terminal = format_terminal_alert(alert)
        self.assertNotIn("\n", terminal)
        self.assertNotIn("\x1b", terminal)
        self.assertIn("successful password login", terminal)


class CorrelationModelTests(unittest.TestCase):
    def evidence(self, **kwargs):
        fields = dict(last_failure_at=START, success_at=START + timedelta(seconds=1),
                      successful_username="alice", auth_method="password", window_seconds=300)
        fields.update(kwargs)
        return CorrelationEvidence(**fields)

    def test_immutable_and_validated(self):
        evidence = self.evidence()
        with self.assertRaises(FrozenInstanceError):
            evidence.auth_method = "publickey"
        for kwargs in ({"last_failure_at": START.replace(tzinfo=None)}, {"success_at": START - timedelta(seconds=1)},
                       {"auth_method": "unknown"}, {"window_seconds": True}, {"window_seconds": 0}, {"window_seconds": 10**21},
                       {"successful_username": 42}, {"success_at": START + timedelta(seconds=301)}):
            with self.subTest(kwargs=kwargs), self.assertRaises((ValueError, TypeError)):
                self.evidence(**kwargs)

    def test_alert_evidence_time_consistency(self):
        fields = dict(detection_name="SSH Successful Login After Brute Force", source_ip=ip_address("203.0.113.10"),
                      severity=Severity.HIGH, first_seen=START, last_seen=START + timedelta(seconds=1),
                      attempt_count=2, threshold=2, window_seconds=10)
        Alert(**fields, correlation=self.evidence())
        with self.assertRaises(TypeError):
            Alert(**fields, correlation="invalid")
        with self.assertRaises(ValueError):
            Alert(**fields, correlation=self.evidence(success_at=START))
        with self.assertRaises(ValueError):
            Alert(**fields, correlation=self.evidence(last_failure_at=START - timedelta(seconds=1)))
