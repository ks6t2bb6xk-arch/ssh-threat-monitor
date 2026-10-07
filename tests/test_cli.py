import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = PROJECT_ROOT / "examples"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "ssh_monitor", *args],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


class CLITests(unittest.TestCase):
    def test_invalid_detector_settings_report_errors_without_creating_output(self) -> None:
        for option, value in (("--threshold", "100001"), ("--window", "999999999999999999999")):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "incidents.jsonl"
                result = run_cli(
                    "--file", str(EXAMPLES / "normal_auth.log"), option, value,
                    "--json-output", str(output),
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(output.exists())

    def test_sample_brute_force_file_and_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "incidents.jsonl"
            result = run_cli(
                "--file", str(EXAMPLES / "brute_force.log"),
                "--threshold", "10",
                "--window", "60",
                "--json-output", str(output),
                "--verbose",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.count("[MEDIUM]"), 1)
            self.assertIn("parsed=13 skipped=0 alerts=1", result.stderr)
            incidents = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["attempt_count"], 10)
            self.assertEqual(incidents[0]["latest_username"], "alice")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_normal_file_does_not_alert(self) -> None:
        result = run_cli("--file", str(EXAMPLES / "normal_auth.log"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_syslog_requires_explicit_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "auth.log"
            log_path.write_text("Oct  5 14:03:22 host sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2\n")
            missing = run_cli("--file", str(log_path))
            self.assertEqual(missing.returncode, 2)
            self.assertIn("line 1: syslog lines require", missing.stderr)
            configured = run_cli("--file", str(log_path), "--syslog-year", "2026", "--syslog-timezone", "+03:00")
            self.assertEqual(configured.returncode, 0, configured.stderr)

    def test_existing_json_file_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "incidents.jsonl"
            output.write_text("original")
            result = run_cli("--file", str(EXAMPLES / "brute_force.log"), "--json-output", str(output))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_text(), "original")

    def test_oversized_log_line_fails_with_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "huge.log"
            log_path.write_bytes(b"x" * 65_537)
            result = run_cli("--file", str(log_path))
            self.assertEqual(result.returncode, 2)
            self.assertIn("line 1 exceeds 65536 bytes", result.stderr)

    def test_attacker_controlled_username_is_safe_in_both_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "hostile.log"
            output = Path(temporary_directory) / "incidents.jsonl"
            lines = [
                f"2026-10-05T14:00:0{second}Z host sshd[1]: Failed password "
                "for bad\x1b[31mname from 203.0.113.10 port 22 ssh2"
                for second in (0, 1)
            ]
            log_path.write_text("\n".join(lines) + "\n")
            result = run_cli(
                "--file", str(log_path), "--threshold", "2", "--json-output", str(output)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("\x1b", result.stdout)
            self.assertEqual(result.stdout.count("\n"), 1)
            self.assertEqual(json.loads(output.read_text())["latest_username"], "bad[31mname")


if __name__ == "__main__":
    unittest.main()
