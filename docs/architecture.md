# Architecture

## Data flow

```text
Single-host SSH log file
          ↓
        Parser → AuthEvent
          ↓
     SSHThreatDetector
       ├── BruteForceDetector (exact sliding failure window)
       └── Bounded attack summaries (success correlation)
          ↓
        Alert + optional CorrelationEvidence
          ↓
  Terminal / streaming JSONL v2 / bounded offline HTML
```

The parser owns log formats, timestamp interpretation, and IP validation. Classic syslog requires explicit year and timezone; parsed times normalize to UTC. All detection operates on nondecreasing event timestamps, with input order breaking ties. One run represents one target host: hostname is not retained or part of the detection key.

## Detection and state contracts

- `AuthEvent` is immutable and distinguishes authentication attempts from context. Username remains untrusted. Context never increments failure counts; success never adds a failure.
- `BruteForceDetector.process(event) -> Alert | None` retains the V1 behavior: inclusive sliding window, threshold-relative severity with privileged-target uplift, first alert plus upward escalation, and rearming below threshold. Limits remain 4,096 active IPs and 100,000 retained failures by default. Capacity exhaustion fails explicitly.
- `SSHThreatDetector.process(event) -> Alert | None` composes the brute-force detector. Its constructor accepts `threshold`, `window_seconds`, `correlation_window_seconds=300`, `max_ips=4096`, `max_events=100_000`, and `max_correlation_ips=4096`. The CLI selects this engine; direct V1 detector callers keep V1 behavior.
- The brute-force detector assigns an internal episode token when the count reaches threshold from below and offers an internal snapshot to its wrapper. The snapshot contains only first/last failure times, count, threshold/window, and the episode's highest emitted severity. No failure username history is retained.
- Every qualifying failure refreshes the IP summary, whether or not deduplication emits another brute-force alert. Below-threshold failures do not refresh it. A summary survives expiration of the failure window; correlation compares success to the last qualifying failure, inclusively.
- Successful password/publickey authentication from the same IP emits one correlation alert per episode, at HIGH or the episode's retained CRITICAL severity. The successful account need not have been targeted. The summary is marked consumed; a new episode token resets that marker.
- Expired summaries are cleaned on events. A summary for the same still-active qualifying episode remains as a deduplication marker until that episode falls below threshold, even if the correlation window is shorter than the failure window. There are at most 4,096 summaries, including consumed markers. The monitor fails explicitly if a new summary cannot be retained.
- Both detectors use bounded in-memory state and event-time cleanup; neither uses wall-clock timers, storage, network services, or firewall actions. As in V1, a capacity error may occur after earlier output; CLI aborts the run. Callers should treat failed runs as incomplete.

## Models and output boundaries

`Alert` retains its existing fields and adds optional immutable `CorrelationEvidence`: `last_failure_at`, `success_at`, `successful_username`, `auth_method`, and `window_seconds`. Evidence validates aware, ordered timestamps, a supported success method, and the inclusive correlation interval. Alert evidence must end at the alert's `last_seen`. In correlation alerts, `attempt_count` and `first_seen` describe the last qualifying failure window, while `last_seen` is the successful login time.

`alert_to_incident()` produces schema version 2. Existing fields remain, with `detection_type`, `reason`, and `correlation` added. Correlation is null for brute force. MITRE T1110 describes preceding brute-force behavior, not a proven successful compromise. All displayed/serialized usernames remove Unicode control/format characters and truncate to 64 characters; detection never compares sanitized account strings.

Terminal alerts quote untrusted usernames. HTML stores escaped JSON as hidden HTML text, reads it with `textContent`, and creates DOM text nodes without `innerHTML`. Inline application code and styles are fixed; the payload is never embedded in a script. CSP blocks external resources and forms. No raw logs are embedded.

## CLI and report lifecycle

The CLI validates detector settings and input/output path collisions before output creation. Resolved aliases and existing hard links are rejected; existing paths, including dangling symlinks, are never replaced. JSONL is created exclusively with mode `0600` and streamed throughout processing. It may be partial when a run fails; exit status 2 indicates error.

`ReportBuilder` retains the first 1,000 serialized alerts and exact full-run severity/total counters. The report shows truncation explicitly and filters only retained details. Threshold and escalation records are distinct alerts, not unique attacks. The English responsive interface shows processing totals, chronological activity, filters, and a selected evidence timeline. It works from a file URL without a server; JavaScript is required for interactive details.

HTML is generated only after successful processing and closing JSONL. `publish_report()` writes a same-directory `0600` temporary file, flushes/fsyncs it, closes it, then uses an atomic hard link to claim the destination without overwrite. A concurrent creator or existing symlink causes safe failure. The temporary name is removed in `finally`; filesystems without hard links fail explicitly. Abrupt process termination can leave a temporary file. Parent directories must already exist.

## Version and compatibility

V1.5 is package version `0.1.5`. CLI flags add `--correlation-window` and `--html-output`; defaults remain 10 failures / 60 seconds plus a 300-second success interval. Runtime dependencies remain standard-library-only. JSON consumers must accept schema 2. CI retains Python 3.11–3.14. V2 concerns such as real-time ingestion, multi-host/account matching, a hosted dashboard, and automatic response remain out of scope.
