# Architecture

## Data flow

```text
SSH authentication log file
          ↓
        Parser
          ↓
      AuthEvent
          ↓
 detector.process(event)
          ↓
        Alert
          ↓
  Terminal / JSON output
```

The parser owns log-format handling, timestamp interpretation, and IP validation with Python's `ipaddress` module. It creates one normalized `AuthEvent` for each supported authentication line. Classic syslog parsing requires an explicit year and timezone; ISO 8601 lines require an embedded offset. The detector accepts events one at a time and has no dependency on files; a later stream or `journalctl` adapter can feed the same interface. Output adapters render alerts and sanitize untrusted usernames before display or serialization. The batch CLI reads bounded lines from a file and writes JSON Lines incidents as alerts occur, without accumulating all incidents in memory.

## Core contracts

- `AuthEvent` contains an aware timestamp, IPv4 or IPv6 source address, optional username, success/failure outcome, optional authentication method, and event kind. A missing method means the source line did not specify one. The kind distinguishes actual authentication attempts from context lines.
- `Alert` contains a detection name, source address, severity, first and last event times, attempt count, configured threshold and window in seconds, and a MITRE ATT&CK technique identifier. V1 brute-force alerts use `T1110`.
- Models are immutable. Timestamps must include timezone information so events from different formats can be compared consistently. The parser converts parsed timestamps to UTC.
- Usernames remain untrusted inside events. The alert carries only the username from the event that triggered it. Sanitization belongs at the output boundary; the event model does not silently change evidence.
- JSON incidents include the detection, severity, source IP, first and last times, attempt count, threshold, window, ATT&CK technique, and sanitized latest username. The CLI creates the output file with owner-only permissions and refuses to overwrite an existing path.

## Detection behavior

The V1 detector keeps an exact sliding window of failed authentication attempts per source IP. It emits an alert when the configured threshold is reached, then another only when severity escalates. Severity bands are relative to the threshold: 1×–<2× medium, 2×–<5× high, and 5× or more critical. Targeting a privileged username raises the band by one level. It removes expired attempts and empty IP states on each event. Configurable caps on active IPs and retained attempts bound state; reaching a cap raises an explicit error. Events must arrive in nondecreasing timestamp order.

## Development sequence

1. Define `AuthEvent` and `Alert`, package metadata, and architecture (complete).
2. Add a parser for supported failed and accepted SSH authentication lines, followed by parser tests (complete).
3. Add event-by-event sliding-window detection, deduplication, threshold-relative severity, and state cleanup (complete).
4. Add terminal alerts, JSON incidents, CLI options, sample logs, and integration tests (complete).
5. Complete the README with security considerations, MITRE mapping, design decisions, and limitations (complete).
6. After V1, add successful-login-after-brute-force correlation as V1.5.

## Counting policy

An `Invalid user` line and a later `Failed password for invalid user` line can describe the same underlying attempt. The parser preserves both as events with distinct kinds. The detector counts only failed authentication-attempt events, so context lines cannot inflate the attempt count. The same policy applies to `maximum authentication attempts exceeded`, which summarizes a connection rather than recording one additional password or key attempt.
