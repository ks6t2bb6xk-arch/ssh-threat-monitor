import json
import os
import stat
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from ssh_monitor import SSHThreatDetector
from ssh_monitor.report import MAX_REPORT_ALERTS, ReportBuilder, publish_report
from test_correlation import event


class PayloadParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_payload = False
        self.parts = []
        self.script_count = 0

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.script_count += 1
        if tag == "div" and dict(attrs).get("id") == "incident-data":
            self.in_payload = True

    def handle_endtag(self, tag):
        if tag == "div":
            self.in_payload = False

    def handle_data(self, data):
        if self.in_payload:
            self.parts.append(data)

    def payload(self, html):
        self.feed(html)
        return json.loads("".join(self.parts))


def render(report):
    return report.render(parsed=2000, skipped=5, threshold=2, window_seconds=10, correlation_window_seconds=300)


class ReportTests(unittest.TestCase):
    def test_hostile_text_remains_data_and_does_not_create_markup_or_scripts(self):
        detector = SSHThreatDetector(threshold=1)
        detector.process(event(0))
        hostile = '</script><img src=x onerror=alert(1)> & " __COUNTS__ __PAYLOAD__'
        alert = detector.process(event(1, success=True, username=hostile))
        report = ReportBuilder()
        report.add(alert)
        document = render(report)
        parser = PayloadParser()
        payload = parser.payload(document)
        self.assertEqual(payload[0]["correlation"]["successful_username"], hostile[:64])
        self.assertEqual(parser.script_count, 1)
        self.assertNotIn('<img src=x', document)
        self.assertNotIn('innerHTML', document)
        self.assertIn('&lt;/script&gt;', document)
        self.assertIn("textContent", document)

    def test_template_sentinels_in_usernames_are_not_interpolated(self):
        detector = SSHThreatDetector(threshold=1)
        alert = detector.process(event(0, username="__COUNTS__ __PARSED__ __PAYLOAD__"))
        report = ReportBuilder()
        report.add(alert)
        self.assertEqual(PayloadParser().payload(render(report))[0]["latest_username"], "__COUNTS__ __PARSED__ __PAYLOAD__")

    def test_bounded_details_and_exact_full_run_counters(self):
        detector = SSHThreatDetector(threshold=1)
        alert = detector.process(event(0))
        report = ReportBuilder()
        for _ in range(MAX_REPORT_ALERTS + 17):
            report.add(alert)
        self.assertEqual(len(report.incidents), 1000)
        self.assertEqual(report.total_alerts, 1017)
        self.assertEqual(report.severities["MEDIUM"], 1017)
        document = render(report)
        self.assertIn("first 1,000 of 1,017", document)
        self.assertEqual(len(PayloadParser().payload(document)), 1000)

    def test_empty_report_and_metadata(self):
        document = render(ReportBuilder())
        self.assertEqual(PayloadParser().payload(document), [])
        self.assertIn("No matching alerts.", document)
        self.assertIn("2,000", document)
        self.assertIn("Content-Security-Policy", document)
        self.assertIn("not unique attacks", document)

    def test_atomic_no_overwrite_publication_permissions_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            publish_report(output, "complete")
            self.assertEqual(output.read_text(), "complete")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                publish_report(output, "replacement")
            self.assertEqual(output.read_text(), "complete")
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_existing_symlink_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            output.symlink_to(Path(directory) / "missing")
            with self.assertRaises(FileExistsError):
                publish_report(output, "replacement")
            self.assertTrue(output.is_symlink())
            self.assertFalse(output.exists())
