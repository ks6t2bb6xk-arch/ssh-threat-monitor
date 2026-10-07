import json
import unittest
from datetime import datetime, timezone
from ipaddress import ip_address

from ssh_monitor import Alert, Severity, alert_to_incident, format_terminal_alert


class IncidentTests(unittest.TestCase):
    def test_terminal_and_json_sanitize_username(self) -> None:
        stamp = datetime(2026, 10, 5, 14, 0, tzinfo=timezone.utc)
        alert = Alert(
            detection_name="SSH Brute Force",
            source_ip=ip_address("2001:db8::10"),
            severity=Severity.HIGH,
            first_seen=stamp,
            last_seen=stamp,
            attempt_count=20,
            threshold=10,
            window_seconds=60,
            latest_username="bad\x1b[31m\n| forged",
        )
        terminal = format_terminal_alert(alert)
        incident = alert_to_incident(alert)
        self.assertEqual(terminal.count("\n"), 0)
        self.assertNotIn("\x1b", terminal)
        self.assertIn('user="bad[31m| forged"', terminal)
        self.assertEqual(incident["latest_username"], "bad[31m| forged")
        self.assertEqual(incident["severity"], "HIGH")
        self.assertEqual(incident["source_ip"], "2001:db8::10")
        self.assertEqual(incident["mitre_attack_technique"], "T1110")
        json.dumps(incident)


if __name__ == "__main__":
    unittest.main()
