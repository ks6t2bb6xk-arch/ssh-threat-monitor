import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from ssh_monitor import AuthEventKind, AuthOutcome, parse_line


SYSLOG_PREFIX = "Oct  5 14:03:22 host sshd[123]: "
ISO_PREFIX = "2026-10-05T17:03:22+03:00 host sshd[123]: "


class ParserTests(unittest.TestCase):
    def test_utc_conversion_outside_datetime_range_is_skipped(self) -> None:
        message = " host sshd[1]: Failed password for alice from 203.0.113.10 port 22 ssh2"
        for stamp in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(stamp=stamp):
                self.assertIsNone(parse_line(stamp + message))
        self.assertIsNone(parse_line(
            "Jan  1 00:00:00" + message,
            syslog_year=1, syslog_timezone=timezone(timedelta(hours=1)),
        ))

    def parse_syslog(self, message: str):
        return parse_line(SYSLOG_PREFIX + message, syslog_year=2026, syslog_timezone=timezone.utc)

    def test_failed_password_ipv4(self) -> None:
        event = self.parse_syslog("Failed password for root from 203.0.113.10 port 50123 ssh2")
        self.assertEqual(event.timestamp, datetime(2026, 10, 5, 14, 3, 22, tzinfo=timezone.utc))
        self.assertEqual(event.source_ip, ip_address("203.0.113.10"))
        self.assertEqual(event.username, "root")
        self.assertEqual(event.outcome, AuthOutcome.FAILURE)
        self.assertEqual(event.auth_method, "password")
        self.assertEqual(event.kind, AuthEventKind.AUTH_ATTEMPT)

    def test_failed_password_invalid_user(self) -> None:
        event = self.parse_syslog("Failed password for invalid user guest from 198.51.100.20 port 50123 ssh2")
        self.assertEqual(event.username, "guest")
        self.assertEqual(event.outcome, AuthOutcome.FAILURE)

    def test_standalone_invalid_user_has_unknown_method(self) -> None:
        event = self.parse_syslog("Invalid user guest from 198.51.100.20 port 50123")
        self.assertEqual(event.username, "guest")
        self.assertIsNone(event.auth_method)
        self.assertEqual(event.kind, AuthEventKind.INVALID_USER)

    def test_failed_publickey_ipv6(self) -> None:
        event = self.parse_syslog("Failed publickey for root from 2001:db8::10 port 50123 ssh2")
        self.assertEqual(event.source_ip, ip_address("2001:db8::10"))
        self.assertEqual(event.auth_method, "publickey")

    def test_maximum_attempts(self) -> None:
        event = self.parse_syslog(
            "error: maximum authentication attempts exceeded for invalid user guest "
            "from 203.0.113.10 port 50123 ssh2 [preauth]"
        )
        self.assertEqual(event.username, "guest")
        self.assertEqual(event.outcome, AuthOutcome.FAILURE)
        self.assertIsNone(event.auth_method)
        self.assertEqual(event.kind, AuthEventKind.MAX_ATTEMPTS)

    def test_accepted_password_iso_with_offset(self) -> None:
        event = parse_line(ISO_PREFIX + "Accepted password for alice from 203.0.113.10 port 50123 ssh2")
        self.assertEqual(event.timestamp, datetime(2026, 10, 5, 14, 3, 22, tzinfo=timezone.utc))
        self.assertEqual(event.outcome, AuthOutcome.SUCCESS)
        self.assertEqual(event.auth_method, "password")

    def test_accepted_publickey_iso_with_z(self) -> None:
        event = parse_line(
            "2026-10-05T14:03:22Z host sshd[123]: "
            "Accepted publickey for alice from 2001:db8::10 port 50123 ssh2"
        )
        self.assertEqual(event.source_ip.version, 6)
        self.assertEqual(event.outcome, AuthOutcome.SUCCESS)
        self.assertEqual(event.auth_method, "publickey")

    def test_syslog_offset_is_normalized_to_utc(self) -> None:
        event = parse_line(
            SYSLOG_PREFIX + "Failed password for root from 203.0.113.10 port 50123 ssh2",
            syslog_year=2026,
            syslog_timezone=timezone(timedelta(hours=3)),
        )
        self.assertEqual(event.timestamp.hour, 11)
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)

    def test_missing_syslog_context_is_an_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "syslog_year and syslog_timezone"):
            parse_line(SYSLOG_PREFIX + "Failed password for root from 203.0.113.10 port 50123 ssh2")

    def test_invalid_or_unsupported_lines_are_skipped(self) -> None:
        lines = (
            "not a log line",
            ISO_PREFIX + "Disconnected from 203.0.113.10",
            ISO_PREFIX + "Failed password for root from not-an-ip port 50123 ssh2",
            "2026-10-05T14:03:22 host sshd[123]: Failed password for root from 203.0.113.10 port 50123 ssh2",
            "Oct 32 14:03:22 host sshd[123]: Failed password for root from 203.0.113.10 port 50123 ssh2",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line, syslog_year=2026, syslog_timezone=timezone.utc))

    def test_username_is_not_sanitized_by_parser(self) -> None:
        event = self.parse_syslog("Invalid user bad\x1b[31mname from 203.0.113.10 port 50123")
        self.assertEqual(event.username, "bad\x1b[31mname")


if __name__ == "__main__":
    unittest.main()
