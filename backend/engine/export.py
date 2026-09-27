"""
Report export.

Produces the formats an analysis actually has to leave in: a standalone
HTML report for people, STIX and MISP for intelligence platforms, and CSV
for spreadsheets.

The HTML report embeds everything it needs and opens with no server, so it
survives being emailed, archived, or attached to a case file years later.
It also carries a print stylesheet, so saving it as PDF from a browser
produces a clean document without a separate rendering dependency.
"""

from __future__ import annotations

import csv
import html
import io
import json
import uuid
from datetime import datetime, timezone

SEVERITY_COLOUR = {
    "critical": "#d81b45",
    "high": "#c25508",
    "medium": "#9a7400",
    "low": "#1565a8",
    "info": "#5b7c96",
}

BAND_COLOUR = {
    "critical": "#d81b45", "high": "#c25508", "elevated": "#9a7400",
    "low": "#1565a8", "clean": "#0f7a4a",
}


def _e(value) -> str:
    return html.escape(str(value if value is not None else "—"))


def _bytes(n) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _num(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "—"


def _clock(epoch) -> str:
    if not epoch:
        return "—"
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (ValueError, OSError, OverflowError):
        return "—"


def _duration(seconds) -> str:
    if not seconds:
        return "0s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def build_html_report(report: dict, logo_data_uri: str | None = None) -> str:
    """Render the whole analysis as one self-contained HTML document."""
    stats = report.get("stats", {})
    capture = report.get("capture", {})
    meta = report.get("meta", {})
    findings = report.get("findings", [])
    profile = report.get("profile", {})

    score = stats.get("risk_score", 0)
    band = stats.get("risk_band", "clean")
    band_colour = BAND_COLOUR.get(band, "#1565a8")

    severity_counts = stats.get("severity_counts", {})
    severity_row = "".join(
        f'<span class="pill" style="color:{SEVERITY_COLOUR[key]};'
        f'border-color:{SEVERITY_COLOUR[key]}55;'
        f'background:{SEVERITY_COLOUR[key]}14">{severity_counts[key]} {key}</span>'
        for key in ("critical", "high", "medium", "low", "info")
        if severity_counts.get(key)
    ) or '<span class="muted">No findings raised.</span>'

    circumference = 2 * 3.14159 * 54
    offset = circumference * (1 - score / 100)

    logo_block = (
        f'<img src="{logo_data_uri}" alt="WireCub" class="logo">'
        if logo_data_uri
        else '<div class="wordmark">WIRECUB</div>'
    )

    # --- findings ---
    finding_blocks = []
    for index, finding in enumerate(findings, 1):
        colour = SEVERITY_COLOUR.get(finding["severity"], "#5b7c96")

        attck = "".join(
            f'<span class="tag">{_e(technique)} · '
            f'{_e((finding.get("mitre_names") or [None])[i] if i < len(finding.get("mitre_names", [])) else "")}</span>'
            for i, technique in enumerate(finding.get("mitre", []))
        )

        hosts = (
            f'<div class="block"><h4>Hosts involved</h4>'
            f'<p class="mono">{_e(", ".join(finding.get("hosts", [])))}</p></div>'
            if finding.get("hosts") else ""
        )

        evidence = ""
        if finding.get("evidence"):
            evidence = (
                '<div class="block"><h4>Evidence</h4><pre>'
                + _e(json.dumps(finding["evidence"], indent=2, default=str))
                + "</pre></div>"
            )

        finding_blocks.append(f"""
      <article class="finding" style="border-left-color:{colour}">
        <header>
          <span class="badge" style="color:{colour};background:{colour}1c">
            {_e(finding['severity'])}</span>
          <h3>{index}. {_e(finding['title'])}</h3>
          <span class="meta">{_num(finding.get('count', 1))} ×
            · {_e(finding.get('confidence'))} confidence</span>
        </header>
        <div class="block"><h4>What was observed</h4><p>{_e(finding['description'])}</p></div>
        <div class="block"><h4>Why it matters</h4><p>{_e(finding['why'])}</p></div>
        <div class="block"><h4>What to do next</h4><p>{_e(finding['recommendation'])}</p></div>
        {f'<div class="block"><h4>MITRE ATT&amp;CK</h4>{attck}</div>' if attck else ''}
        {hosts}
        {evidence}
      </article>""")

    # --- hosts table ---
    host_rows = "".join(
        f"""<tr>
          <td class="mono">{_e(host['ip'])}</td>
          <td>{_e((host.get('hostnames') or ['—'])[0])}</td>
          <td>{_e(host.get('vendor'))}</td>
          <td>{'Internal' if host.get('internal') else 'External'}</td>
          <td class="mono">{_num(host.get('packets'))}</td>
          <td class="mono">{_bytes(host.get('bytes'))}</td>
          <td class="mono" style="color:{_risk_colour(host.get('risk', 0))}">
            {host.get('risk', 0)}</td>
        </tr>"""
        for host in report.get("hosts", [])[:120]
    )

    # --- files table ---
    files = report.get("files", [])
    file_rows = "".join(
        f"""<tr>
          <td>{_e(f.get('filename') or '(unnamed)')}</td>
          <td>{_e(f.get('description'))}</td>
          <td class="mono">{_bytes(f.get('size'))}</td>
          <td class="mono small">{_e(f.get('sha256', '')[:32])}…</td>
          <td class="mono">{_e(f.get('source'))}</td>
          <td>{_e(', '.join(s['name'] for s in f.get('signatures', [])) or '—')}</td>
        </tr>"""
        for f in files[:60]
    )

    # --- credentials ---
    creds = report.get("credentials", [])
    cred_rows = "".join(
        f"""<tr>
          <td>{_e(c.get('protocol'))}</td>
          <td>{_e(c.get('method'))}</td>
          <td class="mono">{_e(c.get('username'))}</td>
          <td class="mono" style="color:#c62828">{_e(c.get('secret'))}</td>
          <td class="mono small">{_e(c.get('client'))} → {_e(c.get('server'))}:{c.get('server_port', '')}</td>
        </tr>"""
        for c in creds[:80]
    )

    credentials_section = f"""
    <section class="page-break">
      <h2>Credentials recovered</h2>
      <p class="muted">Extracted from the traffic itself. Anything listed as
        a password was readable directly from the packets; hashes and
        challenge responses can be attacked offline.</p>
      <table>
        <thead><tr><th>Protocol</th><th>Method</th><th>Account</th>
          <th>Secret</th><th>Between</th></tr></thead>
        <tbody>{cred_rows}</tbody>
      </table>
    </section>""" if creds else ""

    files_section = f"""
    <section class="page-break">
      <h2>Files recovered from traffic</h2>
      <p class="muted">Reconstructed from the packets themselves, so these
        hashes describe exactly what each endpoint received.</p>
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Size</th><th>SHA-256</th>
          <th>From</th><th>Signatures</th></tr></thead>
        <tbody>{file_rows}</tbody>
      </table>
    </section>""" if files else ""

    # --- indicators ---
    iocs = report.get("iocs", {})
    ioc_blocks = []
    for label, key in (
        ("IP addresses", "ip_addresses_defanged"),
        ("Domains", "domains_defanged"),
        ("File hashes (SHA-256)", "file_hashes"),
        ("JA3 fingerprints", "ja3"),
    ):
        values = iocs.get(key) or []
        if values:
            ioc_blocks.append(
                f'<div class="block"><h4>{label} ({len(values)})</h4>'
                f'<pre>{_e(chr(10).join(values))}</pre></div>'
            )

    # --- protocol bars ---
    protocols = report.get("protocols", [])[:12]
    max_protocol = max((p["packets"] for p in protocols), default=1)
    protocol_bars = "".join(
        f"""<div class="bar">
          <span class="bar-label">{_e(p['name'])}</span>
          <span class="bar-track"><span class="bar-fill"
            style="width:{p['packets'] / max_protocol * 100:.1f}%"></span></span>
          <span class="bar-value">{_num(p['packets'])}</span>
        </div>"""
        for p in protocols
    )

    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WireCub report — {_e(meta.get('filename', 'capture'))}</title>
<style>
{_REPORT_CSS}
</style>
</head>
<body>

<header class="report-head">
  <div class="brand">{logo_block}</div>
  <div class="head-meta">
    <div class="file">{_e(meta.get('filename'))}</div>
    <div class="muted small">{_bytes(meta.get('file_size'))} ·
      {_e(capture.get('format'))} · analysed {generated}</div>
  </div>
</header>

<section class="verdict">
  <div class="gauge">
    <svg viewBox="0 0 128 128" width="128" height="128">
      <circle cx="64" cy="64" r="54" fill="none" stroke="#14263d" stroke-width="11"/>
      <circle cx="64" cy="64" r="54" fill="none" stroke="{band_colour}"
              stroke-width="11" stroke-linecap="round"
              stroke-dasharray="{circumference:.1f}"
              stroke-dashoffset="{offset:.1f}"
              transform="rotate(-90 64 64)"/>
    </svg>
    <div class="gauge-text">
      <b style="color:{band_colour}">{score}</b><span>risk</span>
    </div>
  </div>
  <div>
    <div class="band" style="color:{band_colour}">{_e(band)} risk</div>
    <p class="lead">{_e(stats.get('verdict'))}</p>
    <p class="muted">{_e(profile.get('summary'))}</p>
    <div class="pills">{severity_row}</div>
  </div>
</section>

<section>
  <h2>Capture</h2>
  <div class="grid">
    <div class="stat"><b>{_num(capture.get('packets'))}</b><span>Packets</span></div>
    <div class="stat"><b>{_duration(capture.get('duration_seconds'))}</b><span>Span</span></div>
    <div class="stat"><b>{_bytes(capture.get('bytes_on_wire'))}</b><span>Volume</span></div>
    <div class="stat"><b>{_num(stats.get('hosts'))}</b><span>Hosts</span></div>
    <div class="stat"><b>{_num(stats.get('flows'))}</b><span>Flows</span></div>
    <div class="stat"><b>{_num(stats.get('dns_queries'))}</b><span>DNS queries</span></div>
    <div class="stat"><b>{_num(stats.get('http_requests'))}</b><span>HTTP requests</span></div>
    <div class="stat"><b>{_num(stats.get('tls_sessions'))}</b><span>TLS sessions</span></div>
  </div>
  <dl class="kv">
    <dt>Link types</dt><dd>{_e(', '.join(capture.get('link_types') or []))}</dd>
    <dt>First packet</dt><dd>{_clock(capture.get('first_packet'))}</dd>
    <dt>Last packet</dt><dd>{_clock(capture.get('last_packet'))}</dd>
    <dt>Snap length</dt><dd>{_num(capture.get('snaplen'))} bytes</dd>
    <dt>Capture tool</dt><dd>{_e(capture.get('capture_tool') or 'Not recorded')}</dd>
    <dt>Analysis mode</dt><dd>{_e(meta.get('mode'))} scan,
      {_e(meta.get('analysis_seconds'))}s</dd>
  </dl>
</section>

<section>
  <h2>Protocols</h2>
  {protocol_bars}
</section>

<section class="page-break">
  <h2>Findings <span class="muted">({len(findings)})</span></h2>
  {''.join(finding_blocks) if finding_blocks else
   '<p class="muted">No detection raised a finding on this capture.</p>'}
</section>

<section class="page-break">
  <h2>Hosts</h2>
  <table>
    <thead><tr><th>Address</th><th>Name</th><th>Vendor</th><th>Scope</th>
      <th>Packets</th><th>Volume</th><th>Risk</th></tr></thead>
    <tbody>{host_rows}</tbody>
  </table>
</section>

{credentials_section}

{files_section}

<section class="page-break">
  <h2>Indicators</h2>
  <p class="muted">{_e(iocs.get('note', ''))}</p>
  {''.join(ioc_blocks) or '<p class="muted">No indicators extracted.</p>'}
</section>

<footer>
  Generated by WireCub {_e(meta.get('version', '1.0'))} ·
  {generated} · Analysis ID {_e(meta.get('job_id'))}
</footer>

</body>
</html>"""


def _risk_colour(score: int) -> str:
    if score >= 60:
        return "#d81b45"
    if score >= 35:
        return "#c25508"
    if score >= 15:
        return "#9a7400"
    return "#5b7c96"


_REPORT_CSS = """
:root {
  --ink: #0d1b2e; --ink-soft: #4a5f7a; --ink-faint: #8296ad;
  --line: #dbe4ee; --panel: #f6f9fc; --accent: #0891b2;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px 48px 80px; max-width: 1080px;
  margin-inline: auto; background: #fff; color: var(--ink);
  font: 15px/1.6 "IBM Plex Sans", -apple-system, Segoe UI, system-ui, sans-serif;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
h1, h2, h3, h4 { margin: 0; font-weight: 600; letter-spacing: .01em; }
h2 {
  font-size: 20px; margin-bottom: 16px; padding-bottom: 9px;
  border-bottom: 2px solid var(--ink);
}
section { margin-bottom: 40px; }
.mono, pre, td.mono { font-family: "IBM Plex Mono", ui-monospace, monospace; }
.small { font-size: 12px; }
.muted { color: var(--ink-faint); }

.report-head {
  display: flex; justify-content: space-between; align-items: center;
  gap: 24px; padding-bottom: 20px; margin-bottom: 32px;
  border-bottom: 3px solid var(--ink);
}
.logo { height: 52px; width: auto; }
.wordmark {
  font-size: 30px; font-weight: 700; letter-spacing: .06em;
  color: var(--accent);
}
.head-meta { text-align: right; }
.file { font-weight: 600; word-break: break-all; }

.verdict {
  display: grid; grid-template-columns: auto 1fr; gap: 30px;
  align-items: center; padding: 26px 30px; border: 1px solid var(--line);
  border-radius: 12px; background: var(--panel); margin-bottom: 40px;
}
.gauge { position: relative; width: 128px; height: 128px; }
.gauge-text {
  position: absolute; inset: 0; display: grid; place-content: center;
  text-align: center;
}
.gauge-text b {
  display: block; font-family: "IBM Plex Mono", monospace;
  font-size: 34px; line-height: 1;
}
.gauge-text span {
  font-size: 10px; text-transform: uppercase; letter-spacing: .14em;
  color: var(--ink-faint);
}
.band {
  font-size: 12px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .14em; margin-bottom: 6px;
}
.lead { font-size: 17px; margin: 0 0 8px; }
.pills { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }
.pill {
  font-family: "IBM Plex Mono", monospace; font-size: 11.5px;
  padding: 3px 11px; border-radius: 100px; border: 1px solid;
}

.grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 11px; margin-bottom: 20px;
}
.stat {
  border: 1px solid var(--line); border-radius: 9px; padding: 13px 15px;
  background: var(--panel);
}
.stat b {
  display: block; font-family: "IBM Plex Mono", monospace;
  font-size: 21px; color: var(--accent); line-height: 1.2;
}
.stat span {
  font-size: 10.5px; text-transform: uppercase; letter-spacing: .09em;
  color: var(--ink-faint);
}

.kv {
  display: grid; grid-template-columns: max-content 1fr; gap: 5px 20px;
  font-size: 13.5px; margin: 0;
}
.kv dt { color: var(--ink-faint); }
.kv dd { margin: 0; font-family: "IBM Plex Mono", monospace; font-size: 12.5px; }

.bar {
  display: grid; grid-template-columns: 130px 1fr 90px; gap: 12px;
  align-items: center; padding: 4px 0; font-size: 13px;
}
.bar-label { font-family: "IBM Plex Mono", monospace; font-size: 12px; }
.bar-track {
  height: 7px; background: var(--line); border-radius: 100px; overflow: hidden;
}
.bar-fill { display: block; height: 100%; background: var(--accent); }
.bar-value {
  font-family: "IBM Plex Mono", monospace; font-size: 12px;
  text-align: right; color: var(--ink-soft);
}

.finding {
  border: 1px solid var(--line); border-left: 4px solid var(--ink-faint);
  border-radius: 9px; padding: 18px 22px; margin-bottom: 16px;
  break-inside: avoid; page-break-inside: avoid;
}
.finding header {
  display: flex; align-items: center; gap: 12px; margin-bottom: 6px;
  flex-wrap: wrap;
}
.finding h3 { font-size: 16px; flex: 1; min-width: 240px; }
.badge {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .11em; padding: 3px 9px; border-radius: 4px;
}
.finding .meta {
  font-family: "IBM Plex Mono", monospace; font-size: 11.5px;
  color: var(--ink-faint);
}
.block { margin-top: 13px; }
.block h4 {
  font-size: 10px; text-transform: uppercase; letter-spacing: .13em;
  color: var(--accent); margin-bottom: 3px;
}
.block p { margin: 0; color: var(--ink-soft); font-size: 14px; }
.tag {
  display: inline-block; font-family: "IBM Plex Mono", monospace;
  font-size: 11px; border: 1px solid var(--line); border-radius: 4px;
  padding: 2px 8px; margin: 3px 4px 0 0; color: var(--ink-soft);
}
pre {
  background: var(--panel); border: 1px solid var(--line); border-radius: 7px;
  padding: 12px 14px; font-size: 11.5px; line-height: 1.55;
  overflow-x: auto; white-space: pre-wrap; word-break: break-word;
  color: var(--ink-soft); max-height: 340px;
}

table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
thead th {
  text-align: left; padding: 9px 11px; border-bottom: 2px solid var(--ink);
  font-size: 10.5px; text-transform: uppercase; letter-spacing: .08em;
  color: var(--ink-faint); white-space: nowrap;
}
tbody td { padding: 7px 11px; border-bottom: 1px solid var(--line); }
tbody tr:nth-child(even) { background: var(--panel); }

footer {
  margin-top: 50px; padding-top: 18px; border-top: 1px solid var(--line);
  font-size: 11.5px; color: var(--ink-faint); text-align: center;
}

@media print {
  body { padding: 0; font-size: 11pt; }
  .page-break { page-break-before: always; }
  .finding, .verdict, table { page-break-inside: avoid; }
  pre { max-height: none; }
  @page { margin: 16mm; }
}
"""


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def build_stix(report: dict) -> dict:
    """
    Package indicators and findings as a STIX 2.1 bundle.

    Each finding becomes an indicator with a STIX pattern where one can be
    expressed, plus a note carrying the explanation, so the reasoning
    survives the transfer into a platform rather than being reduced to a
    bare address.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict] = []

    identity_id = f"identity--{uuid.uuid4()}"
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "WireCub",
            "identity_class": "system",
            "description": "Packet capture analysis",
        }
    )

    meta = report.get("meta", {})
    stats = report.get("stats", {})

    report_refs: list[str] = []
    iocs = report.get("iocs", {})

    def add_indicator(pattern: str, name: str, description: str,
                      labels: list[str], confidence: int = 60) -> str:
        indicator_id = f"indicator--{uuid.uuid4()}"
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": name,
                "description": description,
                "indicator_types": labels,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "confidence": confidence,
            }
        )
        report_refs.append(indicator_id)
        return indicator_id

    for address in iocs.get("ip_addresses", []):
        version = "ipv6-addr" if ":" in address else "ipv4-addr"
        add_indicator(
            f"[{version}:value = '{_stix_str(address)}']",
            f"Flagged address {address}",
            "Address involved in activity flagged during capture analysis.",
            ["anomalous-activity"],
        )

    for domain in iocs.get("domains", []):
        add_indicator(
            f"[domain-name:value = '{_stix_str(domain)}']",
            f"Flagged domain {domain}",
            "Domain involved in activity flagged during capture analysis.",
            ["anomalous-activity"],
        )

    for sha256 in iocs.get("file_hashes", []):
        add_indicator(
            f"[file:hashes.'SHA-256' = '{_stix_str(sha256)}']",
            f"Transferred file {sha256[:16]}",
            "File reconstructed from captured traffic.",
            ["malicious-activity"],
            confidence=70,
        )

    for fingerprint in iocs.get("ja3", []):
        add_indicator(
            f"[network-traffic:extensions.'tls-ext'.ja3 = '{_stix_str(fingerprint)}']",
            f"TLS fingerprint {fingerprint[:16]}",
            "Rare TLS client fingerprint observed in the capture.",
            ["anomalous-activity"],
            confidence=40,
        )

    # Attack patterns from the ATT&CK techniques the findings named.
    techniques: dict[str, str] = {}
    for finding in report.get("findings", []):
        for index, technique in enumerate(finding.get("mitre", [])):
            names = finding.get("mitre_names", [])
            techniques[technique] = names[index] if index < len(names) else technique

    for technique, name in techniques.items():
        pattern_id = f"attack-pattern--{uuid.uuid4()}"
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": pattern_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique,
                        "url": f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/",
                    }
                ],
            }
        )
        report_refs.append(pattern_id)

    # Notes preserve the human-readable reasoning behind each finding.
    for finding in report.get("findings", [])[:60]:
        note_id = f"note--{uuid.uuid4()}"
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "abstract": finding["title"],
                "content": (
                    f"Severity: {finding['severity']} "
                    f"(confidence: {finding.get('confidence')})\n\n"
                    f"Observed: {finding['description']}\n\n"
                    f"Why it matters: {finding['why']}\n\n"
                    f"Recommended: {finding['recommendation']}"
                ),
                "object_refs": report_refs[:1] or [identity_id],
            }
        )
        report_refs.append(note_id)

    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}",
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": f"WireCub analysis: {meta.get('filename', 'capture')}",
            "description": stats.get("verdict", ""),
            "report_types": ["threat-report"],
            "published": now,
            "object_refs": report_refs or [identity_id],
        }
    )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

MISP_THREAT_LEVEL = {"critical": 1, "high": 2, "elevated": 2, "low": 3, "clean": 4}


def build_misp_event(report: dict) -> dict:
    """Package the analysis as a MISP event ready for import."""
    meta = report.get("meta", {})
    stats = report.get("stats", {})
    iocs = report.get("iocs", {})
    now = datetime.now(tz=timezone.utc)

    attributes: list[dict] = []

    def add(category: str, attr_type: str, value: str, comment: str,
            to_ids: bool = True) -> None:
        attributes.append(
            {
                "uuid": str(uuid.uuid4()),
                "category": category,
                "type": attr_type,
                "value": value,
                "comment": comment,
                "to_ids": to_ids,
                "timestamp": str(int(now.timestamp())),
            }
        )

    for address in iocs.get("ip_addresses", []):
        add(
            "Network activity",
            "ip-dst",
            address,
            "Address involved in flagged activity",
        )

    for domain in iocs.get("domains", []):
        add("Network activity", "domain", domain, "Domain involved in flagged activity")

    for sha256 in iocs.get("file_hashes", []):
        add("Payload delivery", "sha256", sha256,
            "File reconstructed from captured traffic")

    for fingerprint in iocs.get("ja3", []):
        add("Network activity", "ja3-fingerprint-md5", fingerprint,
            "Rare TLS client fingerprint", to_ids=False)

    # Findings become context attributes so an analyst importing the event
    # sees the reasoning, not just a block list.
    for finding in report.get("findings", []):
        if finding["severity"] in ("info", "low"):
            continue
        add(
            "Internal reference",
            "text",
            f"[{finding['severity'].upper()}] {finding['title']}: "
            f"{finding['description']}",
            finding["recommendation"],
            to_ids=False,
        )

    tags = [{"name": f'wirecub:risk="{stats.get("risk_band", "unknown")}"'}]
    for finding in report.get("findings", []):
        for technique in finding.get("mitre", []):
            tag = {"name": f'mitre-attack-pattern:"{technique}"'}
            if tag not in tags:
                tags.append(tag)

    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"WireCub analysis: {meta.get('filename', 'capture')}",
            "date": now.strftime("%Y-%m-%d"),
            "threat_level_id": MISP_THREAT_LEVEL.get(
                stats.get("risk_band", "clean"), 4
            ),
            "analysis": 2,  # completed
            "published": False,
            "distribution": 0,  # organisation only, by default
            "Attribute": attributes,
            "Tag": tags,
            "Object": [],
            "extra": {
                "verdict": stats.get("verdict"),
                "risk_score": stats.get("risk_score"),
                "packets": report.get("capture", {}).get("packets"),
                "generator": "WireCub",
            },
        }
    }


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


class _SafeCsvWriter:
    """
    csv.writer that defuses spreadsheet formulas.

    Hostnames, URLs, usernames and filenames all come from the capture, so a
    cell beginning with = or @ is attacker-chosen text that Excel or Sheets
    would otherwise execute when the analyst opens the export.
    """

    def __init__(self, buffer):
        self._writer = csv.writer(buffer)

    def writerow(self, row):
        self._writer.writerow([
            "'" + value if isinstance(value, str) and value.startswith(_FORMULA_START)
            else value
            for value in row
        ])

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def _stix_str(value) -> str:
    """Escape a value for a single-quoted STIX pattern literal."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def build_csv(report: dict, table: str) -> str:
    """Flatten one table to CSV for spreadsheet work."""
    buffer = io.StringIO()

    if table == "findings":
        writer = _SafeCsvWriter(buffer)
        writer.writerow(
            ["severity", "confidence", "category", "title", "count",
             "description", "why_it_matters", "recommendation",
             "mitre", "hosts"]
        )
        for finding in report.get("findings", []):
            writer.writerow(
                [
                    finding["severity"], finding.get("confidence"),
                    finding.get("category"), finding["title"],
                    finding.get("count", 1), finding["description"],
                    finding["why"], finding["recommendation"],
                    " ".join(finding.get("mitre", [])),
                    " ".join(finding.get("hosts", [])),
                ]
            )

    elif table == "hosts":
        writer = _SafeCsvWriter(buffer)
        writer.writerow(
            ["ip", "ip_version", "hostname", "mac", "vendor", "scope",
             "packets", "bytes", "peers", "services", "risk"]
        )
        for host in report.get("hosts", []):
            writer.writerow(
                [
                    host["ip"], host.get("ip_version"),
                    (host.get("hostnames") or [""])[0],
                    (host.get("macs") or [""])[0], host.get("vendor", ""),
                    "internal" if host.get("internal") else "external",
                    host.get("packets"), host.get("bytes"), host.get("peers"),
                    " ".join(host.get("services", [])), host.get("risk"),
                ]
            )

    elif table == "flows":
        writer = _SafeCsvWriter(buffer)
        writer.writerow(
            ["source", "destination", "port", "protocol", "service",
             "packets", "bytes", "duration", "sni"]
        )
        for flow in report.get("flows", []):
            writer.writerow(
                [
                    flow["source"], flow["destination"],
                    flow.get("destination_port"), flow.get("protocol"),
                    flow.get("service"), flow.get("packets"),
                    flow.get("bytes"), flow.get("duration"),
                    flow.get("sni") or "",
                ]
            )

    elif table == "files":
        writer = _SafeCsvWriter(buffer)
        writer.writerow(
            ["filename", "type", "size", "md5", "sha256", "entropy",
             "source", "destination", "protocol", "url", "signatures"]
        )
        for record in report.get("files", []):
            writer.writerow(
                [
                    record.get("filename") or "", record.get("description"),
                    record.get("size"), record.get("md5"), record.get("sha256"),
                    record.get("entropy"), record.get("source"),
                    record.get("destination"), record.get("protocol"),
                    record.get("url") or "",
                    " | ".join(s["name"] for s in record.get("signatures", [])),
                ]
            )

    elif table == "credentials":
        writer = _SafeCsvWriter(buffer)
        writer.writerow(
            ["protocol", "method", "username", "secret", "secret_kind",
             "realm", "client", "server", "port", "crackable", "note"]
        )
        for c in report.get("credentials", []):
            writer.writerow(
                [
                    c.get("protocol"), c.get("method"), c.get("username"),
                    c.get("secret"), c.get("secret_kind"), c.get("realm"),
                    c.get("client"), c.get("server"), c.get("server_port"),
                    c.get("crackable"), c.get("note"),
                ]
            )

    elif table == "iocs":
        writer = _SafeCsvWriter(buffer)
        writer.writerow(["type", "value", "defanged"])
        iocs = report.get("iocs", {})
        for address in iocs.get("ip_addresses", []):
            writer.writerow(["ip", address, address.replace(".", "[.]")])
        for domain in iocs.get("domains", []):
            writer.writerow(["domain", domain, domain.replace(".", "[.]")])
        for sha256 in iocs.get("file_hashes", []):
            writer.writerow(["sha256", sha256, sha256])
        for fingerprint in iocs.get("ja3", []):
            writer.writerow(["ja3", fingerprint, fingerprint])

    else:
        raise ValueError(f"Unknown table: {table}")

    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

def compare_reports(baseline: dict, current: dict) -> dict:
    """
    Compare a capture against an earlier one from the same network.

    Answers the question a repeat capture is actually taken to answer: what
    is different now. New hosts, new destinations, and newly raised
    findings are what a baseline is for.
    """
    def host_set(report: dict) -> set[str]:
        return {host["ip"] for host in report.get("hosts", [])}

    def finding_set(report: dict) -> dict[str, dict]:
        return {finding["id"]: finding for finding in report.get("findings", [])}

    def external_set(report: dict) -> set[str]:
        return {
            host["ip"] for host in report.get("hosts", [])
            if not host.get("internal")
        }

    def domain_set(report: dict) -> set[str]:
        return {
            entry["name"]
            for entry in report.get("dns", {}).get("top_domains", [])
        }

    baseline_hosts, current_hosts = host_set(baseline), host_set(current)
    baseline_findings, current_findings = finding_set(baseline), finding_set(current)
    baseline_external, current_external = external_set(baseline), external_set(current)
    baseline_domains, current_domains = domain_set(baseline), domain_set(current)

    new_findings = [
        current_findings[key] for key in current_findings.keys() - baseline_findings.keys()
    ]
    resolved = [
        baseline_findings[key] for key in baseline_findings.keys() - current_findings.keys()
    ]

    score_delta = (
        current.get("stats", {}).get("risk_score", 0)
        - baseline.get("stats", {}).get("risk_score", 0)
    )

    return {
        "baseline": {
            "filename": baseline.get("meta", {}).get("filename"),
            "analysed_at": baseline.get("meta", {}).get("analysed_at"),
            "risk_score": baseline.get("stats", {}).get("risk_score"),
        },
        "current": {
            "filename": current.get("meta", {}).get("filename"),
            "analysed_at": current.get("meta", {}).get("analysed_at"),
            "risk_score": current.get("stats", {}).get("risk_score"),
        },
        "risk_delta": score_delta,
        "new_hosts": sorted(current_hosts - baseline_hosts)[:200],
        "missing_hosts": sorted(baseline_hosts - current_hosts)[:200],
        "new_external_destinations": sorted(current_external - baseline_external)[:200],
        "new_domains": sorted(current_domains - baseline_domains)[:200],
        "new_findings": [
            {
                "id": finding["id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "hosts": finding.get("hosts", [])[:8],
            }
            for finding in sorted(
                new_findings,
                key=lambda f: -{"critical": 4, "high": 3, "medium": 2,
                                "low": 1, "info": 0}.get(f["severity"], 0),
            )
        ],
        "resolved_findings": [
            {"id": finding["id"], "title": finding["title"],
             "severity": finding["severity"]}
            for finding in resolved
        ],
        "summary": _comparison_summary(
            score_delta, new_findings,
            len(current_hosts - baseline_hosts),
            len(current_external - baseline_external),
        ),
    }


def _comparison_summary(score_delta, new_findings, new_hosts, new_external) -> str:
    critical = sum(1 for f in new_findings if f["severity"] in ("critical", "high"))

    if critical:
        lead = (
            f"{critical} new finding(s) at high severity or above since the "
            "baseline."
        )
    elif new_findings:
        lead = f"{len(new_findings)} new finding(s), none above medium severity."
    else:
        lead = "No new findings since the baseline."

    changes = []
    if new_hosts:
        changes.append(f"{new_hosts} host(s) appeared that were not there before")
    if new_external:
        changes.append(f"{new_external} external destination(s) are new")

    direction = (
        f"Risk moved {'up' if score_delta > 0 else 'down'} by {abs(score_delta)} points."
        if score_delta else "Risk score is unchanged."
    )

    return " ".join([lead, direction] + ([", ".join(changes) + "."] if changes else []))
