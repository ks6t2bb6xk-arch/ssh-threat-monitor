"""Batch file CLI for SSH Threat Monitor."""

import argparse
import json
import os
import re
import sys
from contextlib import ExitStack
from datetime import timedelta, timezone
from pathlib import Path

from .detector import SSHThreatDetector, StateCapacityError
from .incident import alert_to_incident, format_terminal_alert
from .parser import parse_line
from .report import ReportBuilder, publish_report


MAX_LINE_BYTES = 65_536
_UTC_OFFSET = re.compile(r"^(?P<sign>[+-])(?P<hours>\d{2}):(?P<minutes>\d{2})$")


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _year(value: str) -> int:
    year = _positive_int(value)
    if year > 9999:
        raise argparse.ArgumentTypeError("must be between 1 and 9999")
    return year


def _syslog_timezone(value: str) -> timezone:
    if value.upper() == "Z":
        return timezone.utc
    match = _UTC_OFFSET.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError("use Z or a fixed UTC offset such as +03:00")
    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    if hours > 23 or minutes > 59:
        raise argparse.ArgumentTypeError("invalid UTC offset")
    delta = timedelta(hours=hours, minutes=minutes)
    if match.group("sign") == "-":
        delta = -delta
    try:
        return timezone(delta)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("UTC offset must be less than 24 hours") from exc


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect SSH brute force and suspicious successful logins in a single-host log")
    parser.add_argument("--file", type=Path, required=True, help="SSH authentication log file")
    parser.add_argument("--threshold", type=_positive_int, default=10, help="failed attempts needed for an alert (default: 10)")
    parser.add_argument("--window", type=_positive_int, default=60, help="sliding window in seconds (default: 60)")
    parser.add_argument("--json-output", type=Path, help="new JSON Lines incident file; existing files are not overwritten")
    parser.add_argument("--correlation-window", type=_positive_int, default=300, help="success correlation window in seconds (default: 300)")
    parser.add_argument("--html-output", type=Path, help="new standalone offline HTML report; existing files are not overwritten")
    parser.add_argument("--verbose", action="store_true", help="print processing counts to stderr")
    parser.add_argument("--syslog-year", type=_year, help="year for classic syslog timestamps")
    parser.add_argument("--syslog-timezone", type=_syslog_timezone, help="fixed timezone for classic syslog (Z or ±HH:MM)")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the batch monitor; return an exit status suitable for __main__."""
    args = _argument_parser().parse_args(argv)
    parsed_count = skipped_count = alert_count = 0
    try:
        paths = [("--file", args.file)]
        paths.extend((name, path) for name, path in
                     (("--json-output", args.json_output), ("--html-output", args.html_output))
                     if path is not None)
        for index, (name, path) in enumerate(paths):
            for other_name, other_path in paths[:index]:
                if path.resolve() == other_path.resolve() or (
                    path.exists() and other_path.exists() and path.samefile(other_path)
                ):
                    raise ValueError(f"{name} must differ from {other_name}")
            if index and os.path.lexists(path):
                raise ValueError(f"{name} already exists: {path}")
        detector = SSHThreatDetector(
            threshold=args.threshold, window_seconds=args.window,
            correlation_window_seconds=args.correlation_window,
        )
        report = ReportBuilder() if args.html_output is not None else None
        with ExitStack() as stack:
            source = stack.enter_context(args.file.open("rb"))
            incident_file = None
            if args.json_output is not None:
                descriptor = os.open(args.json_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                incident_file = stack.enter_context(os.fdopen(descriptor, "w", encoding="utf-8"))
            line_number = 0
            while raw_line := source.readline(MAX_LINE_BYTES + 1):
                line_number += 1
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ValueError(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                try:
                    event = parse_line(
                        line,
                        syslog_year=args.syslog_year,
                        syslog_timezone=args.syslog_timezone,
                    )
                    if event is None:
                        skipped_count += 1
                        continue
                    parsed_count += 1
                    alert = detector.process(event)
                except (ValueError, StateCapacityError) as exc:
                    raise ValueError(f"line {line_number}: {exc}") from exc
                if alert is None:
                    continue
                print(format_terminal_alert(alert))
                alert_count += 1
                if report is not None:
                    report.add(alert)
                if incident_file is not None:
                    incident_file.write(json.dumps(alert_to_incident(alert), ensure_ascii=True) + "\n")
        if report is not None:
            publish_report(args.html_output, report.render(
                parsed=parsed_count, skipped=skipped_count,
                threshold=args.threshold, window_seconds=args.window,
                correlation_window_seconds=args.correlation_window,
            ))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.verbose:
        print(
            f"parsed={parsed_count} skipped={skipped_count} alerts={alert_count}",
            file=sys.stderr,
        )
    return 0
