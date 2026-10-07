# SSH Threat Monitor

## Overview

SSH Threat Monitor is a small Python tool for studying SSH detection engineering. It reads Linux `sshd` authentication logs from a file, normalizes supported lines into `AuthEvent` objects, detects bursts of failed authentication by source IP, and emits terminal alerts and optional JSON Lines incidents. It does not block IP addresses.

**Status: V1 complete.** The batch CLI, parser, detector, output adapters, examples, and tests are implemented. Successful-login-after-brute-force correlation is planned for V1.5.

## Problem

Repeated SSH authentication failures from one address may indicate brute-force activity. Raw logs are difficult to review consistently across timestamp styles and authentication methods. This project turns selected log lines into normalized events and applies an explicit, testable detection rule. An alert is a signal to investigate, not proof that an account was compromised.

## Architecture

```text
SSH log file → parser → AuthEvent → detector.process(event) → Alert → terminal / JSON Lines
```

The parser handles log formats and IP validation. The detector consumes events one at a time and has no file dependency, so a future stream adapter can use the same interface. Output adapters format alerts and sanitize untrusted usernames. See [Architecture](docs/architecture.md) for component contracts and design details.

## Detection Logic

The detector counts failed `password` and `publickey` authentication attempts per source IP in a sliding window. With `--threshold 10 --window 60`, the tenth failure within 60 seconds triggers an alert. An event exactly 60 seconds old remains in the window; older events expire. Source IPs are tracked independently.

`Invalid user` and `maximum authentication attempts exceeded` lines are parsed as context but do not increase the failure count. This prevents an `Invalid user` line and the following `Failed password for invalid user` line from counting as two attempts. Successful authentications do not affect V1 brute-force counts. Events must arrive in nondecreasing timestamp order.

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
- JSON Lines output is created with owner-only permissions (`0600`) and never overwrites an existing file. A run that fails after producing alerts can leave a partial incident file; check the exit status before treating it as complete.
- The files in `examples/` use documentation-reserved addresses. Do not commit real `auth.log` files or incident records containing operational data. The repository ignores `*.log` outside `examples/`, JSON Lines outputs, and local `.env` files.
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

`--file` is required. The default threshold is 10 failures and the default window is 60 seconds. The CLI threshold cannot exceed its 100,000-event state limit. `--json-output` creates a new JSON Lines file with one incident per line; terminal alerts still print to stdout. `--verbose` prints processing counts to stderr. Invalid detector settings, timestamp order, capacity, and file errors exit with status 2; malformed or unsupported log lines are skipped. For a negative timezone offset, use `--syslog-timezone=-03:00`. Run `python3 -m ssh_monitor --help` for all options.

The `examples/normal_auth.log` fixture stays below the default threshold. `examples/brute_force.log` produces one MEDIUM alert. `examples/successful_login_after_attack.log` currently produces a brute-force alert; its successful-login correlation is reserved for V1.5.

## Testing

```bash
python -m unittest discover -s tests -v
```

Run this command from the repository root with the virtual environment active. Tests cover parsing, IPv4/IPv6, timestamp requirements, window boundaries, independent IPs, severity escalation, deduplication, state cleanup and caps, output sanitization, and CLI file processing. GitHub Actions runs the same installation and test steps on Python 3.11 through 3.14.

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
- The tool reads a finite file once. It does not watch logs, query `journalctl`, prevent attacks, or determine whether a login succeeded after an attack in V1.
- Severity is a heuristic based on count and a small privileged-username list. Operational thresholds need tuning for the environment.

## Future Improvements

V1.5 will correlate a successful login from the same IP after brute-force activity and emit a higher-priority incident. Later possibilities include real-time `--watch`, `journalctl`, notifications, GeoIP/ASN, threat intelligence, a dashboard, and deployment packaging. These are outside the V1 scope.

## License

This project is licensed under the [MIT License](LICENSE).
