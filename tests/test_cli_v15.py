import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from test_cli import EXAMPLES, run_cli
from test_report import PayloadParser


class CLIV15Tests(unittest.TestCase):
    def test_both_outputs_and_correlation_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / "report.html"
            jsonl = Path(directory) / "incidents.jsonl"
            result = run_cli("--file", str(EXAMPLES / "successful_login_after_attack.log"),
                             "--html-output", str(html), "--json-output", str(jsonl), "--verbose")
            self.assertEqual(result.returncode, 0, result.stderr)
            records = [json.loads(line) for line in jsonl.read_text().splitlines()]
            self.assertEqual(len(records), 2)
            self.assertEqual(records[-1]["schema_version"], 2)
            self.assertEqual(records[-1]["correlation"]["successful_username"], "root")
            self.assertEqual(records[-1]["correlation"]["last_failure_at"], "2026-10-05T14:00:14+00:00")
            self.assertEqual(PayloadParser().payload(html.read_text()), records)
            self.assertIn("parsed=16 skipped=0 alerts=2", result.stderr)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(html.stat().st_mode), 0o600)

    def test_empty_report_is_a_successful_result(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / "empty.html"
            result = run_cli("--file", str(EXAMPLES / "normal_auth.log"), "--html-output", str(html))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(PayloadParser().payload(html.read_text()), [])

    def test_colliding_paths_fail_before_any_outputs_are_created(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "same.html"
            for args in (("--html-output", str(EXAMPLES / "normal_auth.log")),
                         ("--html-output", str(output), "--json-output", str(output))):
                with self.subTest(args=args):
                    result = run_cli("--file", str(EXAMPLES / "normal_auth.log"), *args)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("must differ", result.stderr)
                    self.assertFalse(output.exists())

    def test_existing_html_preserved_without_creating_json(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / "report.html"
            jsonl = Path(directory) / "incidents.jsonl"
            html.write_text("original")
            result = run_cli("--file", str(EXAMPLES / "normal_auth.log"), "--html-output", str(html), "--json-output", str(jsonl))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(html.read_text(), "original")
            self.assertFalse(jsonl.exists())

    def test_symlink_and_hardlink_input_aliases_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            source.write_text("original")
            for link_type in ("symlink", "hardlink"):
                alias = Path(directory) / link_type
                if link_type == "symlink":
                    alias.symlink_to(source)
                else:
                    os.link(source, alias)
                result = run_cli("--file", str(source), "--html-output", str(alias))
                self.assertEqual(result.returncode, 2)
                self.assertIn("must differ", result.stderr)
                self.assertEqual(source.read_text(), "original")

    def test_invalid_correlation_settings_do_not_create_report(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / "report.html"
            for value in ("0", "-1", "999999999999999999999"):
                result = run_cli("--file", str(EXAMPLES / "normal_auth.log"), "--html-output", str(html), "--correlation-window", value)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(html.exists())
                self.assertNotIn("Traceback", result.stderr)

    def test_failed_run_has_no_html_but_json_may_be_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.log"
            html = Path(directory) / "report.html"
            jsonl = Path(directory) / "partial.jsonl"
            text = (EXAMPLES / "brute_force.log").read_text()
            source.write_text(text + text.splitlines()[0] + "\n")
            result = run_cli("--file", str(source), "--html-output", str(html), "--json-output", str(jsonl))
            self.assertEqual(result.returncode, 2)
            self.assertIn("nondecreasing", result.stderr)
            self.assertFalse(html.exists())
            self.assertEqual(len(jsonl.read_text().splitlines()), 1)

    def test_short_configured_window_excludes_later_success(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "delayed.log"
            text = (EXAMPLES / "successful_login_after_attack.log").read_text()
            source.write_text(text.replace("14:00:15", "14:00:20"))
            result = run_cli("--file", str(source), "--correlation-window", "5")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("SSH Successful Login", result.stdout)

    def test_more_than_1000_alerts_keeps_all_json_records(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "many.log"
            html = Path(directory) / "report.html"
            jsonl = Path(directory) / "all.jsonl"
            source.write_text("".join(
                f"2026-10-05T14:00:00Z demo sshd[1]: Failed password for alice from 2001:db8::{i:x} port 22 ssh2\n"
                for i in range(1, 1003)
            ))
            result = run_cli("--file", str(source), "--threshold", "1", "--html-output", str(html), "--json-output", str(jsonl))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(jsonl.read_text().splitlines()), 1002)
            self.assertEqual(len(PayloadParser().payload(html.read_text())), 1000)
            self.assertIn("first 1,000 of 1,002", html.read_text())

    def test_additional_synthetic_scenarios(self):
        for filename, alert_count, correlation_count in (
            ("different_account_after_attack.log", 2, 1),
            ("expired_success_after_attack.log", 1, 0),
            ("portfolio_demo.log", 6, 2),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "incidents.jsonl"
                result = run_cli("--file", str(EXAMPLES / filename), "--json-output", str(output))
                self.assertEqual(result.returncode, 0, result.stderr)
                records = [json.loads(line) for line in output.read_text().splitlines()]
                self.assertEqual(len(records), alert_count)
                correlations = [record for record in records if record["correlation"] is not None]
                self.assertEqual(len(correlations), correlation_count)
                if filename == "different_account_after_attack.log":
                    self.assertEqual(correlations[0]["correlation"]["successful_username"], "bob")
