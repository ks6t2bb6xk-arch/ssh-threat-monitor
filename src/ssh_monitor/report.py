"""Bounded, standalone offline analyst reports without runtime dependencies."""

from collections import Counter
from html import escape
import json
import os
from pathlib import Path
import tempfile

from .incident import alert_to_incident
from .models import Alert


MAX_REPORT_ALERTS = 1000


class ReportBuilder:
    """Keep a bounded detail sample and exact counters for all emitted alerts."""

    def __init__(self) -> None:
        self.incidents: list[dict[str, object]] = []
        self.severities: Counter[str] = Counter()
        self.total_alerts = 0

    def add(self, alert: Alert) -> None:
        self.total_alerts += 1
        self.severities[alert.severity.value.upper()] += 1
        if len(self.incidents) < MAX_REPORT_ALERTS:
            self.incidents.append(alert_to_incident(alert))

    def render(self, *, parsed: int, skipped: int, threshold: int,
               window_seconds: int, correlation_window_seconds: int) -> str:
        payload = json.dumps(self.incidents, ensure_ascii=True)
        # Store JSON as escaped HTML text, never inside a script element. The
        # browser decodes entities once; JSON.parse reads textContent safely.
        payload = escape(payload, quote=True)
        counts = "".join(
            f'<div class="stat {severity.lower()}"><span>{severity}</span><strong>{self.severities[severity]:,}</strong></div>'
            for severity in ("MEDIUM", "HIGH", "CRITICAL")
        )
        truncated = self.total_alerts > len(self.incidents)
        detail_note = (f"Showing the first {len(self.incidents):,} of {self.total_alerts:,} alerts. "
                       "Details are limited; JSONL output includes all alerts." if truncated else
                       f"{self.total_alerts:,} alert records. Escalations are separate records, not unique attacks.")
        return (_TEMPLATE.replace("__COUNTS__", counts)
                .replace("__PARSED__", f"{parsed:,}").replace("__SKIPPED__", f"{skipped:,}")
                .replace("__TOTAL__", f"{self.total_alerts:,}")
                .replace("__THRESHOLD__", str(threshold)).replace("__WINDOW__", str(window_seconds))
                .replace("__CORRELATION_WINDOW__", str(correlation_window_seconds))
                .replace("__DETAIL_NOTE__", detail_note)
                .replace("__PAYLOAD__", payload))


def publish_report(path: Path, content: str) -> None:
    """Publish a complete 0600 report atomically without replacing any path.

    A same-directory hard link atomically claims the destination after the
    temporary file is flushed and closed. A concurrent creator wins safely.
    """
    descriptor, temporary = tempfile.mkstemp(prefix=".ssh-report-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


_TEMPLATE = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>SSH Threat Monitor · Investigation report</title>
<style>
:root{color-scheme:dark;--bg:#0b111a;--panel:#121c29;--line:#263448;--muted:#9faec2;--text:#edf3fa;--cyan:#65dfd2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}
main{max-width:1400px;margin:auto;padding:42px 36px}header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.eyebrow{color:var(--cyan);text-transform:uppercase;letter-spacing:.16em;font-size:12px;font-weight:700}
h1{font-size:clamp(26px,4vw,40px);margin:8px 0;font-weight:650;letter-spacing:-.035em}h2{font-size:18px;margin:0 0 14px}h3{font-size:16px;margin:0 0 10px}p{margin:8px 0}.muted,.note{color:var(--muted)}.tag{border:1px solid var(--line);border-radius:24px;padding:7px 13px;white-space:nowrap;font-size:12px;color:var(--cyan)}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:30px 0 18px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.stat span{font-size:11px;letter-spacing:.07em;color:var(--muted)}.stat strong{display:block;font-size:30px;font-weight:600}.medium strong{color:#f1d18a}.high strong{color:#ffb17c}.critical strong{color:#ff8998}
.rule{display:flex;flex-wrap:wrap;gap:8px 24px;color:var(--muted);font-size:13px;margin-bottom:26px}.rule b{color:var(--text)}.filters{display:flex;flex-wrap:wrap;gap:14px;align-items:end;margin-bottom:18px}label{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--muted)}input,select{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:10px 12px;color:var(--text);font:inherit;min-width:170px}input:focus,select:focus,button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.workspace{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:20px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;min-width:0}.list{max-height:620px;overflow:auto;display:grid;gap:10px}.alert{width:100%;text-align:left;border:1px solid var(--line);border-radius:8px;background:#0e1723;color:var(--text);padding:15px;cursor:pointer;font:inherit}.alert:hover,.alert[aria-pressed="true"]{border-color:var(--cyan);background:#172b36}.alert small{display:block;color:var(--muted);margin-top:5px}.alert-title{display:block;margin-top:7px;font-weight:600}.badge{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.06em;border-radius:4px;padding:3px 7px;margin-right:10px;background:#354035;color:#f1d18a}.badge.high{background:#47352b;color:#ffb17c}.badge.critical{background:#462c39;color:#ff8998}.mono{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.detail-title{font-size:23px;line-height:1.3;margin:12px 0}.reason{padding:14px;border-left:2px solid var(--cyan);background:#0e1723;font-size:14px;margin:20px 0}.timeline{list-style:none;margin:22px 0;padding:0 0 0 18px;border-left:1px solid var(--line)}.timeline li{position:relative;padding:0 0 22px 12px}.timeline li:before{content:"";position:absolute;left:-23px;top:8px;width:9px;height:9px;border-radius:50%;background:var(--cyan)}.timeline small{display:block;color:var(--muted)}dl{display:grid;grid-template-columns:130px 1fr;gap:10px;font-size:13px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}.empty{padding:35px 10px;color:var(--muted);text-align:center}.note{font-size:12px;margin:16px 0}.footer{border-top:1px solid var(--line);padding-top:18px;margin-top:24px;font-size:12px;color:var(--muted)}
@media(max-width:900px){.stats{grid-template-columns:repeat(3,1fr)}.workspace{grid-template-columns:1fr}.list{max-height:440px}}@media(max-width:540px){main{padding:24px 16px}header{display:block}.tag{display:inline-block;margin-top:12px}.stats{grid-template-columns:repeat(2,1fr)}.stat{padding:14px}.filters label,.filters input,.filters select{width:100%}.panel{padding:16px}dl{grid-template-columns:110px 1fr}}
</style>
</head>
<body><main>
<header><div><div class="eyebrow">Detection engineering / V1.5</div><h1>SSH Threat Monitor</h1><p class="muted">Authentication signals, connected into an investigation.</p></div><span class="tag">OFFLINE · SINGLE HOST</span></header>
<section class="stats" aria-label="Processing and severity summary"><div class="stat"><span>PARSED EVENTS</span><strong>__PARSED__</strong></div><div class="stat"><span>SKIPPED LINES</span><strong>__SKIPPED__</strong></div><div class="stat"><span>TOTAL ALERTS</span><strong>__TOTAL__</strong></div>__COUNTS__</section>
<div class="rule"><span>Failure threshold <b>__THRESHOLD__ attempts / __WINDOW__s</b></span><span>Success correlation <b>__CORRELATION_WINDOW__s</b></span><span>Timestamps <b>UTC</b></span></div>
<section aria-label="Alert filters" class="filters"><label>Source IP<input id="ip" type="search" placeholder="Search IPv4 or IPv6" autocomplete="off"></label><label>Severity<select id="severity"><option value="">All severities</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label><label>Detection<select id="type"><option value="">All detections</option><option value="brute_force">Brute force</option><option value="successful_login_after_brute_force">Successful login after brute force</option></select></label></section>
<p class="note">__DETAIL_NOTE__</p>
<div class="workspace"><section class="panel"><h2>Alert activity <span class="muted" id="visible-count"></span></h2><div class="list" id="list" aria-label="Chronological alerts"></div></section><section class="panel" id="detail" aria-label="Selected alert evidence" aria-live="polite"></section></div>
<noscript><p>Enable JavaScript to inspect alert records and filters. Processing totals remain visible above.</p></noscript>
<p class="footer">Evidence scope: one target host per run. Correlation links a source IP, not an attacker identity or a proven account compromise. Shared IPs can produce false positives. MITRE ATT&amp;CK T1110 describes the preceding brute-force behavior.</p>
</main><div id="incident-data" hidden>__PAYLOAD__</div>
<script>
'use strict';
const incidents = JSON.parse(document.getElementById('incident-data').textContent);
const list = document.getElementById('list');
const detail = document.getElementById('detail');
const ip = document.getElementById('ip');
const severity = document.getElementById('severity');
const type = document.getElementById('type');
let selected = null;
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function time(value) { return value.replace('T', ' ').replace('+00:00', ' UTC'); }
function showDetail(a) {
  detail.replaceChildren();
  if (!a) { detail.append(node('h2', 'Evidence timeline'), node('p', 'No matching alerts. Adjust filters or review another log.', 'empty')); return; }
  detail.append(node('div', 'SELECTED SIGNAL', 'eyebrow'), node('h2', a.detection, 'detail-title'), node('p', a.source_ip, 'mono'), node('p', a.reason, 'reason'));
  const timeline = node('ol', undefined, 'timeline');
  function step(label, stamp) { const li = node('li', label); li.append(node('small', time(stamp), 'mono')); timeline.append(li); }
  step('First failure in the qualifying window', a.first_seen);
  if (a.correlation) {
    step(a.attempt_count + ' failures in the qualifying window · last failure', a.correlation.last_failure_at);
    step('Successful ' + a.correlation.auth_method + ' login · account: ' + (a.correlation.successful_username ?? 'unknown'), a.correlation.success_at);
  } else { step('Threshold reached or severity escalated · ' + a.attempt_count + ' failures', a.last_seen); }
  detail.append(timeline);
  const fields = node('dl');
  [['Severity',a.severity],['Detection type',a.detection_type],['Latest account',a.latest_username ?? 'unknown'],['Failure window',a.window_seconds + ' seconds'],['Threshold',a.threshold + ' attempts'],['ATT&CK',a.mitre_attack_technique]].forEach(([key,value]) => fields.append(node('dt',key),node('dd',value)));
  detail.append(fields, node('p', 'Account names are sanitized for display. Same-IP evidence does not establish that the successful account was previously targeted.', 'note'));
}
function render() {
  const visible = incidents.filter(a => a.source_ip.toLowerCase().includes(ip.value.trim().toLowerCase()) && (!severity.value || a.severity === severity.value) && (!type.value || a.detection_type === type.value));
  if (!visible.includes(selected)) selected = visible[0] ?? null;
  list.replaceChildren();
  document.getElementById('visible-count').textContent = '(' + visible.length + ')';
  if (!visible.length) list.append(node('p','No matching alerts.','empty'));
  visible.forEach(a => {
    const button = node('button',undefined,'alert'); button.type = 'button'; button.setAttribute('aria-pressed',String(selected === a));
    button.append(node('span',a.severity,'badge ' + a.severity.toLowerCase()),node('span',a.source_ip,'mono'),node('span',a.detection,'alert-title'),node('small',time(a.last_seen) + ' · ' + a.attempt_count + ' failures'));
    button.addEventListener('click', () => {
      selected = a;
      list.querySelectorAll('button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
      showDetail(a);
    });
    list.append(button);
  });
  showDetail(selected);
}
[ip,severity,type].forEach(element => element.addEventListener('input',render));
render();
</script></body></html>'''
