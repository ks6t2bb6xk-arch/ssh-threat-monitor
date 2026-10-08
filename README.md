# SSH Threat Monitor

## Overview

SSH Threat Monitor is a small Python tool for studying SSH detection engineering. It reads Linux `sshd` authentication logs from a file, normalizes supported lines into `AuthEvent` objects, detects bursts of failed authentication by source IP, correlates subsequent successful logins, and emits terminal alerts, JSON Lines incidents, and optional standalone HTML reports. It does not block IP addresses.

**Status: V1.5 complete** (package version `0.1.5`). Brute-force detection, successful-login correlation, bounded evidence, schema v2 JSONL, and an offline analyst report are implemented. Python 3.11+; no third-party runtime dependencies.

![Offline analyst report with a suspicious successful login and evidence timeline](docs/images/v1.5-report-desktop.jpg)

*Screenshot generated from `examples/portfolio_demo.log`; all IPs and accounts are synthetic.*

## Problem

Repeated SSH authentication failures from one address may indicate brute-force activity. Raw logs are difficult to review consistently across timestamp styles and authentication methods. This project turns selected log lines into normalized events and applies an explicit, testable detection rule. An alert is a signal to investigate, not proof that an account was compromised.

## Architecture

```text
Single-host SSH log → parser → AuthEvent → SSHThreatDetector → Alert → terminal / JSONL / HTML
```

The parser handles log formats and IP validation. The detector consumes events one at a time and has no file dependency, so a future stream adapter can use the same interface. Output adapters format alerts and sanitize untrusted usernames. See [Architecture](docs/architecture.md) for component contracts and design details.

## Detection Logic

The detector counts failed `password` and `publickey` authentication attempts per source IP in a sliding window. With `--threshold 10 --window 60`, the tenth failure within 60 seconds triggers an alert. An event exactly 60 seconds old remains in the window; older events expire. Source IPs are tracked independently.

`Invalid user` and `maximum authentication attempts exceeded` lines are parsed as context but do not increase the failure count. This prevents an `Invalid user` line and the following `Failed password for invalid user` line from counting as two attempts. Successful authentications do not add to brute-force counts; they can trigger a separate correlation alert. Events must arrive in nondecreasing timestamp order.

## Successful Login Correlation

Once an IP reaches the failure threshold, the monitor retains a summary of its qualifying window. Every subsequent failure with the active count at or above the threshold refreshes the first/last failure times and attempt count, even when no new brute-force alert is emitted. A failed attempt below threshold does not refresh evidence. The summary survives expiration of the shorter brute-force window.

A subsequent successful `password` or `publickey` login from the same IP within `--correlation-window` seconds (default **300**) emits **SSH Successful Login After Brute Force**. The exact boundary is included. Equal timestamps follow file order. Severity is HIGH, or CRITICAL if the preceding episode had already emitted a CRITICAL brute-force alert. The retained severity is the highest emitted in that episode; the failure count describes the latest qualifying window, not all attempts in the episode.

Only the first successful login in an attack episode emits a correlation alert. Continuing failures do not rearm a consumed episode. A new episode starts when the active failure count falls below threshold and subsequently reaches it again. Expired summaries are removed on new events; consumed markers remain while the same episode is above threshold to prevent duplicate alerts even with a very short correlation window. At most 4,096 summaries are retained; exhaustion is an explicit error.

**Evidence is IP-level only.** The successful account may differ from the accounts previously targeted. Shared/NATed addresses can create false positives. This is a signal to investigate, not proof of account compromise. Supply logs from **one target host per run**: hostname is not part of the event key, so merged logs from multiple hosts can produce misleading correlations. MITRE T1110 maps to the preceding brute-force behavior, not to a proven compromise.

## Offline Analyst Report

`--html-output report.html` creates one self-contained HTML file. Open it directly in a browser: no server, internet, CDN, database, or installation is needed. JavaScript enables local IP, severity, and detection filters and a selected alert's evidence timeline. Processing totals remain visible without JavaScript.

The responsive dark report shows parsed events, skipped lines, total emitted alerts, and severity counts. Alert activity is chronological, with separate records for threshold crossings and severity escalations; the total is **not a count of unique attacks**. Filters affect retained detail records, not full-run counters.

Only the first **1,000** alerts are retained for HTML details. Counters cover the complete run, and a visible notice explains any truncation. Use `--json-output` to retain all emitted alerts. Reports contain account and IP information; treat reports from operational logs as sensitive.

## Supported Log Formats

The parser recognizes `sshd` lines containing `Failed password`, `Failed password for invalid user`, `Invalid user`, `Failed publickey`, `maximum authentication attempts exceeded`, `Accepted password`, and `Accepted publickey`. It validates IPv4 and IPv6 addresses with Python's `ipaddress` module. Unsupported or malformed lines are skipped; `--verbose` reports the total skipped count.

Supported prefixes are ISO 8601 with an explicit offset or `Z` (for example `2026-10-05T14:03:22Z`) and classic syslog (for example `Oct  5 14:03:22`). Classic syslog omits year and timezone, so provide both `--syslog-year` and `--syslog-timezone`; the CLI accepts `Z` or a fixed offset such as `+03:00`. Parsed times are converted to UTC. The parser does not infer year rollover, and local timestamps around daylight-saving transitions can remain ambiguous. Files with out-of-order events stop with an error.

## Severity Model

Severity uses the configured threshold **T**, not fixed attempt counts:

| Failures in the window | Base severity |
| --- | --- |
| Fewer than T | No alert |
| T through fewer than 2T | MEDIUM |
| 2T through fewer than 5T | HIGH |
| 5T or more | CRITICAL |

If `root`, `admin`, or `administrator` was targeted within the active window, severity rises one level, capped at CRITICAL. This is a local scoring choice, not a guarantee that the activity is malicious.

## Alert Deduplication

The detector emits the first alert when the count reaches T and another only when severity rises. For a non-privileged target with T=10, alerts occur at 10 (MEDIUM), 20 (HIGH), and 50 (CRITICAL) attempts if all attempts remain within the window. It rearms after the active count falls below T. A severity decrease alone does not emit an alert.

## Security Considerations

- Usernames come from untrusted logs. The parser preserves them in `AuthEvent`; terminal and JSON output remove Unicode control and format characters and truncate displayed names to 64 characters. Terminal output quotes the displayed name to reduce log-injection and terminal escape risks.
- The CLI rejects input lines larger than 65,536 bytes. The detector retains failure timestamps and privileged-account flags, not raw usernames. It limits state to 4,096 active IPs and 100,000 retained failures by default. Reaching a limit raises `StateCapacityError`; the CLI exits with an error instead of silently undercounting.
- JSON Lines and HTML outputs use owner-only permissions (`0600` on POSIX) and never overwrite an existing path. Input/output aliases and output/output collisions are rejected before processing. A run that fails after producing alerts can leave a partial JSONL file; check the exit status before treating it as complete. HTML is published only after successful processing and output closure, using a flushed temporary file and a same-directory atomic hard link; publication fails safely on filesystems without hard-link support. Temporary files are removed on handled publication errors.
- HTML encodes untrusted values as escaped text; browser rendering uses `textContent`, never `innerHTML`. A restrictive Content Security Policy blocks external resources. No raw log lines are embedded.
- The files in `examples/` use documentation-reserved addresses. Do not commit real `auth.log` files or incident records containing operational data. The repository ignores `*.log` outside `examples/`, JSON Lines outputs, generated HTML reports, the `reports/` directory, and local `.env` files. The documented screenshots contain only synthetic data.
- This tool only detects and reports. It does not change firewall rules or authentication settings.

## MITRE ATT&CK Mapping

The brute-force alert maps to [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). The mapping describes the behavior the rule looks for: repeated authentication attempts. The alert does not establish a specific T1110 sub-technique or prove account compromise.

## Installation

Use Python 3.11 or newer. From the repository root, create a fresh virtual environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

No third-party runtime package is required. The install step downloads the build requirement from PyPI if it is not already available. An editable install lets `python -m ssh_monitor` find the `src/` package.

## Usage

```bash
python3 -m ssh_monitor --file examples/brute_force.log --threshold 10 --window 60
python3 -m ssh_monitor --file examples/brute_force.log --json-output incidents.jsonl --verbose
python3 -m ssh_monitor --file /path/to/auth.log --syslog-year 2026 --syslog-timezone +03:00
```

`--file` is required. The default threshold is 10 failures, the default failure window is 60 seconds, and the default success correlation window is 300 seconds. All three settings must be positive integers. The CLI threshold cannot exceed its 100,000-event state limit. `--json-output` creates a new JSON Lines file with one incident per line; `--html-output` creates a new offline report. Both options can be used together; terminal alerts still print to stdout. Parent directories must already exist. `--verbose` prints processing counts to stderr. Invalid detector settings, timestamp order, capacity, and file errors exit with status 2; malformed or unsupported log lines are skipped. For a negative timezone offset, use `--syslog-timezone=-03:00`. Run `python3 -m ssh_monitor --help` for all options.

### Analyze your own log

Run these commands from the project root. First, install the project as described above and activate its virtual environment if you have not already done so. Then create folders for your input and report:

```bash
mkdir -p logs reports
```

Copy one server's SSH authentication log into `logs/` (or place it there in Finder). For example, replace the source path with the location of your log:

```bash
cp "/path/to/your/auth.log" logs/auth.log
```

Analyze it and create both report formats:

```bash
python3 -m ssh_monitor --file logs/auth.log --html-output reports/my-analysis.html --json-output reports/my-analysis.jsonl --verbose
```

If the log uses classic syslog timestamps such as `Oct  8 14:03:22`, which omit the year and timezone, add the correct year and timezone for that log. For a 2026 log recorded in Istanbul, for example:

```bash
python3 -m ssh_monitor --file logs/auth.log --syslog-year 2026 --syslog-timezone +03:00 --html-output reports/my-analysis.html --json-output reports/my-analysis.jsonl --verbose
```

Open `reports/my-analysis.html` in a browser to review the results. In the terminal, check `parsed=` and `skipped=`: if `parsed=0`, the file did not contain any supported SSH log lines, so an empty report does not mean the log was clean. Use a new output filename for each run; existing reports are never overwritten. Log files outside `examples/` are ignored by Git, but still keep real logs and reports private.

### Three-command demo

After installation, create a `reports` directory once (`mkdir -p reports`), then run:

```bash
python3 -m ssh_monitor --file examples/normal_auth.log --html-output reports/normal.html --verbose
python3 -m ssh_monitor --file examples/brute_force.log --html-output reports/brute-force.html --verbose
python3 -m ssh_monitor --file examples/successful_login_after_attack.log --html-output reports/correlation.html --json-output reports/correlation.jsonl --verbose
```

Expected results: **0**, **1 MEDIUM**, and **1 HIGH brute-force + 1 HIGH successful-login correlation** respectively. Open each HTML file in a browser. Use new output filenames on reruns; existing files are intentionally preserved.

For a richer portfolio demo, run:

```bash
python3 -m ssh_monitor --file examples/portfolio_demo.log --html-output reports/portfolio.html --json-output reports/portfolio.jsonl --verbose
```

This produces 47 parsed events and six alerts (two each at MEDIUM, HIGH, and CRITICAL), including IPv6, severity escalation, password/publickey success, and a different successful account. Select the CRITICAL successful-login alert to see the timeline shown above.

Additional examples: `different_account_after_attack.log` demonstrates IP-level correlation to `bob` after failures against `root`; `expired_success_after_attack.log` has a success 301 seconds after the last qualifying failure and produces only the brute-force alert.

### JSONL schema v2

V1.5 preserves V1 fields and changes `schema_version` from 1 to 2. Consumers that require schema 1 must be updated. Added fields are `detection_type` (`brute_force` or `successful_login_after_brute_force`), `reason`, and `correlation` (null for brute force).

```json
{
  "schema_version": 2,
  "detection": "SSH Successful Login After Brute Force",
  "detection_type": "successful_login_after_brute_force",
  "reason": "...IP-level correlation only; ...compromise is not established.",
  "severity": "HIGH",
  "source_ip": "203.0.113.20",
  "first_seen": "2026-10-05T14:00:00+00:00",
  "last_seen": "2026-10-05T14:00:15+00:00",
  "attempt_count": 15,
  "threshold": 10,
  "window_seconds": 60,
  "mitre_attack_technique": "T1110",
  "latest_username": "root",
  "correlation": {
    "last_failure_at": "2026-10-05T14:00:14+00:00",
    "success_at": "2026-10-05T14:00:15+00:00",
    "successful_username": "root",
    "auth_method": "password",
    "window_seconds": 300
  }
}
```

## Testing

```bash
python -m unittest discover -s tests -v
```

Run this command from the repository root with the virtual environment active. Tests cover parsing, IPv4/IPv6, timestamp requirements, inclusive failure/correlation boundaries, independent IPs, severity escalation, episode deduplication, summary cleanup/caps, schema v2, output sanitization, hostile HTML payloads, atomic publication, path aliases, truncation, and CLI file processing. Browser checks cover desktop/mobile layouts, combined filters, empty results, and evidence selection; see [V1.5 validation](docs/validation-v1.5.md). GitHub Actions runs the same installation and test steps on Python 3.11 through 3.14.

## Design Decisions

- **Event-by-event detector:** `process(event)` keeps detection separate from file input and supports a future streaming source.
- **Explicit syslog time context:** Guessing the missing year or timezone could shift events into the wrong window.
- **Context lines do not count as attempts:** OpenSSH can log multiple lines for one connection; counting only explicit failed authentication lines avoids a known double-counting case.
- **Exact window with explicit capacity failure:** Dropping old-but-active attempts to stay within memory limits could silently change counts. The detector reports capacity exhaustion instead.
- **JSON Lines output:** Incidents are written as they occur, without retaining all results in memory.

### Why not fail2ban?

[Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/README.md) scans logs for repeated authentication errors and can ban source IPs through firewall rules. SSH Threat Monitor is a learning project focused on event normalization, correlation, severity, and incident output. It deliberately has no automatic blocking and is not a replacement for host protection.

## Limitations

- Detection is based on source IP. Distributed brute-force and password-spraying patterns across many addresses may be missed; shared or NATed addresses can also create false positives.
- Only the documented `sshd` line patterns and timestamp prefixes are supported. Other Linux distributions, OpenSSH versions, or log configurations may emit different lines that are skipped.
- Classic syslog year rollover and daylight-saving ambiguity require external context. Out-of-order input is rejected rather than reordered.
- The tool reads a finite single-host file once. It does not watch logs, query `journalctl`, prevent attacks, or establish compromise. Correlation uses source IP only, with no account-match or host-match claim.
- Severity is a heuristic based on count and a small privileged-username list. Operational thresholds need tuning for the environment.

## Future Improvements

V2 candidates include real-time `--watch`, explicit multi-host identity, account-aware correlation, `journalctl`, notifications, GeoIP/ASN, threat intelligence, a hosted dashboard, and deployment packaging. These are outside V1.5.

## License

This project is licensed under the [MIT License](LICENSE).
