/* WireCub interface logic. */

const $ = (id) => document.getElementById(id);

const state = {
  jobId: null,
  report: null,
  cy: null,
  config: null,
  abort: null,
  reputationLoaded: false,
};

/* ----------------------------------------------------------- formatting */

function bytes(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[i]}`;
}

function num(n) {
  return (n ?? 0).toLocaleString('en-US');
}

function duration(seconds) {
  if (!seconds) return '0s';
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  // Round once, then split, so 43m 59.6s reads 44m 0s rather than 43m 60s.
  if (seconds < 3600) {
    const total = Math.round(seconds);
    return `${Math.floor(total / 60)}m ${total % 60}s`;
  }
  const minutes = Math.round(seconds / 60);
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function clockTime(epoch) {
  if (!epoch) return '—';
  const d = new Date(epoch * 1000);
  // A crafted capture can carry any timestamp; an invalid date must not
  // take the whole report down with it.
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19);
}

function esc(text) {
  return String(text ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

const SEV_COLOR = {
  critical: '#d6336c', high: '#e8590c', medium: '#c48a00',
  low: '#5c7cfa', info: '#5b7c96',
};

const BAND_COLOR = {
  critical: '#d6336c', high: '#e8590c', elevated: '#c48a00',
  low: '#5c7cfa', clean: '#0ca678',
};

function riskColor(score) {
  if (score >= 60) return '#d6336c';
  if (score >= 35) return '#e8590c';
  if (score >= 15) return '#c48a00';
  if (score > 0) return '#3b5bdb';
  return '#0ca678';
}

/* ----------------------------------------------------------------- api */

class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

/* Every call goes through here: non-2xx answers become errors carrying the
   server's explanation, and a 401 opens the access-key prompt. */
async function api(path, options = {}) {
  let res;
  try {
    res = await fetch(path, { credentials: 'same-origin', ...options });
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError('The server could not be reached. Check the connection and try again.', 0);
  }
  if (res.status === 401) {
    const body = await res.json().catch(() => ({}));
    if (body.auth) showAuth();
    throw new ApiError(body.detail || 'Access key required.', 401);
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = typeof body.detail === 'string' ? body.detail
      : res.status === 413 ? 'The request was too large for the server.'
      : res.status === 504 ? 'The server ran out of time on this request.'
      : `The server answered ${res.status}.`;
    throw new ApiError(detail, res.status);
  }
  return res;
}

function showError(message) {
  const error = $('uploadError');
  error.textContent = message;
  error.hidden = false;
  showView('upload');
}

/* -------------------------------------------------------------- access */

function showAuth() {
  const dialog = $('authDialog');
  if (!dialog || dialog.open) return;
  $('authError').hidden = true;
  $('authKey').value = '';
  dialog.showModal();
  setTimeout(() => $('authKey').focus(), 50);
}

function setupAuth() {
  const form = $('authForm');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await api('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: $('authKey').value }),
      });
      $('authDialog').close();
      await loadConfig();
    } catch (err) {
      $('authError').textContent = err.message;
      $('authError').hidden = false;
    } finally {
      button.disabled = false;
    }
  });
}

/* --------------------------------------------------------------- views */

function showView(name) {
  ['Upload', 'Progress', 'Results', 'History'].forEach((view) => {
    $(`view${view}`).hidden = view.toLowerCase() !== name;
  });
  $('newScanBtn').hidden = name === 'upload';
}

/* -------------------------------------------------------------- upload */

async function loadConfig() {
  try {
    const res = await api('/api/config');
    state.config = await res.json();
  } catch { return; }
  const c = state.config;
  $('limitLabel').textContent =
    `.pcap · .pcapng · .cap — gzip, bzip2 and zstd accepted — up to ${c.max_upload_label}`;

  const notice = $('hostedNotice');
  if (notice) {
    const parts = [];
    if (!c.store_ready) {
      parts.push(`<strong>Storage is not set up.</strong> ${esc(c.store_error || '')}`);
    } else if (c.hosted) {
      parts.push(`<strong>Hosted instance.</strong> Captures are processed on
        this server and results are kept privately
        ${c.retention_days ? `for ${c.retention_days} days` : ''}. Up to
        ${esc(c.max_upload_label)} per capture${c.time_budget_seconds
          ? ` and ${Math.round(c.time_budget_seconds / 60)} minutes of analysis` : ''}.
        For larger captures run WireCub locally.`);
      if (c.open_to_public) {
        parts.push(`<strong>No access key is set</strong>, so anyone with the
          address can use this instance and open its history. Set
          <code>WIRECUB_ACCESS_KEY</code> in the Vercel project settings.`);
      }
    }
    notice.innerHTML = parts.map((p) => `<p>${p}</p>`).join('');
    notice.hidden = parts.length === 0;
    notice.classList.toggle('banner-red', !c.store_ready || c.open_to_public);
  }
  $('logoutBtn').hidden = !c.auth_required;
  if (c.auth_required && !c.authenticated) showAuth();
}

function setupUpload() {
  const zone = $('dropZone');
  const input = $('fileInput');

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });

  ['dragenter', 'dragover'].forEach((evt) =>
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add('dragging');
    }));

  ['dragleave', 'drop'].forEach((evt) =>
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      if (evt === 'dragleave' && zone.contains(e.relatedTarget)) return;
      zone.classList.remove('dragging');
    }));

  zone.addEventListener('drop', (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) upload(file);
  });

  input.addEventListener('change', () => {
    if (input.files?.[0]) upload(input.files[0]);
  });

  $('newScanBtn').addEventListener('click', resetToUpload);
  $('historyBtn').addEventListener('click', showHistory);
  $('logoutBtn')?.addEventListener('click', async () => {
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    location.reload();
  });
}

function resetState() {
  state.report = null;
  state.reputationLoaded = false;
  state.repOnline = false;
  if (state.cy) { state.cy.destroy(); state.cy = null; }
  const hostPanel = $('hostPanel');
  if (hostPanel) hostPanel.hidden = true;
  $('panelReputation').innerHTML = '';
}

function resetToUpload() {
  if (state.abort) { state.abort.abort(); state.abort = null; }
  state.jobId = null;
  resetState();
  $('fileInput').value = '';
  $('uploadError').hidden = true;
  $('captureChip').hidden = true;
  showView('upload');
}

function setProgress(percent, message) {
  if (percent !== undefined && percent !== null) {
    $('progressFill').style.width = `${percent}%`;
    $('progressPercent').textContent = `${Math.round(percent)}%`;
  }
  if (message) $('progressMessage').textContent = message;
}

/* Send one piece, retrying a couple of times: on a long upload a single
   dropped request should not cost the whole transfer. */
async function sendChunk(uploadId, index, blob, signal) {
  for (let attempt = 0; ; attempt++) {
    try {
      await api(`/api/uploads/${uploadId}/${index}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: blob,
        signal,
      });
      return;
    } catch (err) {
      if (err.name === 'AbortError' || attempt >= 2
          || (err.status >= 400 && err.status < 500)) throw err;
      await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
    }
  }
}

async function upload(file) {
  $('uploadError').hidden = true;
  const limit = state.config?.max_upload_bytes ?? 10 * 1024 ** 3;
  const label = state.config?.max_upload_label ?? '10 GB';

  if (file.size > limit) {
    return showError(`That capture is ${bytes(file.size)}, over the ${label} limit. `
      + 'Split it with editcap -c and upload each part'
      + (state.config?.hosted ? ', or run WireCub locally.' : '.'));
  }
  if (file.size === 0) {
    return showError('That file is empty. Pick a capture with packets in it.');
  }

  resetState();
  const controller = new AbortController();
  state.abort = controller;
  state.jobId = null;
  $('progressFile').textContent = file.name;
  setProgress(0, `Uploading ${bytes(file.size)}`);
  showView('progress');

  try {
    const res = await api('/api/uploads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: file.name, size: file.size }),
      signal: controller.signal,
    });
    const plan = await res.json();

    // Uploading is shown as the first part of the bar; the analysis fills
    // the rest.
    for (let i = 0; i < plan.chunks; i++) {
      const start = i * plan.chunk_bytes;
      await sendChunk(plan.upload_id, i,
        file.slice(start, start + plan.chunk_bytes), controller.signal);
      const sent = Math.min(file.size, start + plan.chunk_bytes);
      $('progressFill').style.width = `${(sent / file.size) * 100}%`;
      $('progressPercent').textContent = `${Math.round((sent / file.size) * 100)}%`;
      $('progressMessage').textContent = `Uploading — ${bytes(sent)} of ${bytes(file.size)}`;
    }

    setProgress(0, 'Starting the analysis');
    await runAnalysis(plan, file, controller);
  } catch (err) {
    if (err.name === 'AbortError') return;
    if (err.status === 401) { showView('upload'); return; }
    showError(err.message);
  } finally {
    if (state.abort === controller) state.abort = null;
  }
}

/* The analysis answers with one JSON event per line while it works. */
async function runAnalysis(plan, file, controller) {
  const res = await api(`/api/uploads/${plan.upload_id}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename: file.name, size: file.size, chunks: plan.chunks }),
    signal: controller.signal,
  });

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let outcome = null;

  const handle = (event) => {
    if (event.job_id) state.jobId = event.job_id;
    if (event.type === 'progress') setProgress(event.percent, event.message);
    if (['done', 'failed', 'cancelled'].includes(event.type)) outcome = event;
  };

  for (;;) {
    const { value, done } = await reader.read();
    if (value) buffer += decoder.decode(value, { stream: true });
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line) { try { handle(JSON.parse(line)); } catch { /* partial line */ } }
    }
    if (done) break;
  }
  if (buffer.trim()) { try { handle(JSON.parse(buffer)); } catch { /* ignore */ } }

  if (!outcome) {
    throw new ApiError(state.config?.hosted
      ? 'The analysis was cut off before it finished, most likely by the hosting time limit. Try a smaller capture, or run WireCub locally.'
      : 'The connection to the server closed before the analysis finished.', 0);
  }
  if (outcome.type === 'failed') throw new ApiError(outcome.error || 'Analysis failed.', 0);
  if (outcome.type === 'cancelled') { resetToUpload(); return; }
  setProgress(100, 'Loading the report');
  await loadReport(outcome.job_id);
}

$('cancelBtn')?.addEventListener('click', async () => {
  const jobId = state.jobId;
  if (state.abort) state.abort.abort();
  if (jobId) {
    fetch(`/api/jobs/${jobId}/cancel`, { method: 'POST' }).catch(() => {});
  }
  resetToUpload();
});

/* -------------------------------------------------------------- report */

async function loadReport(jobId) {
  let report;
  try {
    const res = await api(`/api/reports/${jobId}`);
    report = await res.json();
  } catch (err) {
    if (err.status !== 401) showError(err.message);
    return;
  }
  resetState();
  state.report = report;
  state.jobId = jobId;
  try {
    renderAll();
  } catch (err) {
    console.error(err);
    showError(`The report loaded but could not be displayed: ${err.message}`);
    return;
  }
  showView('results');
  switchTab('findings');
  window.scrollTo(0, 0);
}

function renderAll() {
  const r = state.report;
  $('tabCountFindings').textContent = r.findings.length;
  $('tabCountHosts').textContent = r.stats.hosts;
  $('captureChip').textContent =
    `${r.meta.filename} · ${bytes(r.meta.file_size)} · ${r.capture.format}`;
  $('captureChip').hidden = false;

  // One failing panel should not blank the others.
  [renderOverview, renderFindings, renderHosts, renderFlows, renderDns,
   renderHttp, renderTls, renderIocs, renderAttacks, renderTimeline,
   renderVoip, renderCredentials, renderFiles, renderStreams, renderWindows,
   renderOt, renderWireless, renderExport].forEach((render) => {
    try { render(); } catch (err) { console.error(`${render.name} failed`, err); }
  });
}

/* A tab appears only when it has something in it. An empty tab is a dead
   end the user only discovers by clicking, so hiding it is kinder than
   showing it greyed out. */
function setTabVisible(name, visible, count) {
  const tab = document.querySelector(`.tab[data-tab="${name}"]`);
  if (!tab) return;
  tab.hidden = !visible;
  if (count !== undefined) {
    const badge = tab.querySelector('.tab-count');
    if (badge) badge.textContent = count;
  }
}

/* ------------------------------------------------------------- attacks */

/* Findings that describe an attempt against a service, as opposed to a
   configuration weakness. These are what an analyst opens first, so they
   get their own view with the payload shown in full. */
const ATTACK_CATEGORIES = new Set([
  'Web attack', 'Credential attack', 'Malicious file', 'Ransomware',
  'Reconnaissance', 'Command and control', 'Exfiltration',
  'Lateral movement', 'Wireless attack', 'Spoofing',
]);

function renderAttacks() {
  const attacks = (state.report.findings || [])
    .filter((f) => ATTACK_CATEGORIES.has(f.category));
  setTabVisible('attacks', attacks.length > 0, attacks.length);
  if (!attacks.length) return;

  const payloadBlock = (e) => {
    if (!e.matched && !e.context && !e.body_preview) return '';
    return `
      <div class="payload">
        ${e.location ? `<span class="payload-where">Arrived in the ${esc(e.location)}</span>` : ''}
        ${e.matched ? `<div class="payload-line">
          <span class="payload-label">Matched</span>
          <code class="payload-hit">${esc(e.matched)}</code></div>` : ''}
        ${e.context ? `<div class="payload-line">
          <span class="payload-label">In context</span>
          <code class="payload-context">${highlightMatch(e.context, e.matched)}</code></div>` : ''}
        ${e.body_preview ? `<div class="payload-line">
          <span class="payload-label">Request body</span>
          <code class="payload-context">${esc(e.body_preview)}</code></div>` : ''}
        ${e.user_agent ? `<div class="payload-line">
          <span class="payload-label">User-Agent</span>
          <code class="payload-context">${esc(e.user_agent)}</code></div>` : ''}
        ${e.status ? `<div class="payload-line">
          <span class="payload-label">Server replied</span>
          <code class="payload-context ${e.status < 300 ? 'landed' : ''}">${e.status}</code></div>` : ''}
      </div>`;
  };

  const card = (f) => {
    const evidence = (f.evidence || []).slice(0, 6);
    return `
      <article class="attack-card" data-sev="${esc(f.severity)}">
        <header>
          <span class="sev-badge" data-sev="${esc(f.severity)}">${esc(f.severity)}</span>
          <h3>${esc(f.title)}</h3>
          <span class="attack-count">${num(f.count || 1)}×</span>
        </header>
        <p class="attack-desc">${esc(f.description)}</p>
        <div class="attack-answer">
          <span class="attack-answer-label">What to look at</span>
          <p>${esc(f.recommendation)}</p>
        </div>
        ${evidence.map((e) => `
          <div class="attack-event">
            <div class="attack-route mono">
              ${esc(e.source || e.client || '?')}
              <span class="arrow">→</span>
              ${esc(e.target || e.server || e.destination || '?')}
              ${e.method ? `<span class="tag">${esc(e.method)}</span>` : ''}
              ${e.uri ? `<span class="attack-uri">${esc(e.uri)}</span>` : ''}
              ${e.packet ? `<span class="attack-pkt">packet ${num(e.packet)}</span>` : ''}
            </div>
            ${payloadBlock(e)}
          </div>`).join('')}
        ${(f.evidence || []).length > 6
          ? `<p class="note">${(f.evidence.length - 6)} more events in the Findings tab.</p>` : ''}
      </article>`;
  };

  $('panelAttacks').innerHTML = `
    <div class="card">
      <h3>Attacks and attempts</h3>
      <p class="note">Every finding that describes something being tried
        against a host, with the payload exactly as it appeared on the wire.
        Configuration weaknesses live in Findings instead.</p>
    </div>
    ${attacks.map(card).join('')}`;
}

/* Marks the matched substring inside its surrounding text so the eye lands
   on the payload rather than reading the whole line. */
function highlightMatch(context, matched) {
  const safe = esc(context);
  if (!matched) return safe;
  const needle = esc(matched);
  const index = safe.indexOf(needle);
  if (index === -1) return safe;
  return safe.slice(0, index)
    + `<mark>${needle}</mark>`
    + safe.slice(index + needle.length);
}

/* ---------------------------------------------------------- reputation */

async function renderReputation() {
  const panel = $('panelReputation');
  panel.innerHTML = '<div class="card"><p class="note">Checking indicators against cached feeds…</p></div>';

  let data;
  try {
    const res = await api(
      `/api/reports/${state.jobId}/reputation?online=${state.repOnline ? 1 : 0}`);
    data = await res.json();
  } catch (err) {
    panel.innerHTML = `<div class="card"><p class="note">Lookup failed: ${esc(err.message)}</p></div>`;
    return;
  }

  const feedTable = (feeds) => table([
    { label: 'Feed', render: (f) => esc(f.name) },
    { label: 'Covers', render: (f) => esc(f.kind) },
    { label: 'Entries', cls: 'mono', render: (f) => f.entries ? num(f.entries) : '—' },
    { label: 'Age', cls: 'mono', render: (f) => (f.age_hours === null || f.age_hours === undefined)
        ? '<span class="muted-inline">never fetched</span>'
        : (f.age_hours > 168 ? `<span style="color:#e8590c">${f.age_hours}h</span>` : `${f.age_hours}h`) },
    { label: 'What a hit means', render: (f) => esc(f.description) },
  ], feeds, 'No feeds configured.');

  if (data.available && data.feeds_ready === false) {
    // Surfaced as a banner rather than a wall: the addresses below are
    // still worth reading without the feeds.
    state.repFeedsMissing = data.feeds_note;
  } else {
    state.repFeedsMissing = null;
  }

  if (!data.available) {
    panel.innerHTML = `
      <div class="card">
        <h3>Reputation feeds not downloaded yet</h3>
        <p class="note">${esc(data.reason || '')}</p>
        <button class="primary-btn" id="refreshFeeds">Download feeds</button>
      </div>
      ${feedTable(data.feeds || [])}`;
    wireFeedRefresh();
    return;
  }

  const verdicts = data.verdicts || [];
  const scoreColour = (n) => n >= 60 ? '#d6336c' : n >= 30 ? '#e8590c'
    : n >= 10 ? '#c48a00' : '#0ca678';

  const flag = (c) => c ? c.replace(/./g, (ch) =>
    String.fromCodePoint(0x1F1E6 - 65 + ch.toUpperCase().charCodeAt(0))) : '';

  const card = (v) => {
    const c = v.context;
    return `
    <article class="rep-card" data-sev="${esc(v.worst_severity)}">
      <header>
        <span class="rep-score" style="background:${scoreColour(v.score || 0)}">
          ${v.score || 0}</span>
        <span class="mono rep-indicator">${esc(v.indicator)}</span>
        ${c && c.country_code ? `<span class="rep-geo">${flag(c.country_code)} ${esc(c.country)}${c.city ? ' · ' + esc(c.city) : ''}</span>` : ''}
        ${v.packets ? `<span class="rep-vol mono">${num(v.packets)} pkts</span>` : ''}
      </header>

      ${c ? `<dl class="kv rep-context">
        ${c.asn ? `<dt>Network</dt><dd>${esc(c.asn)}</dd>` : ''}
        ${c.isp ? `<dt>Operator</dt><dd>${esc(c.isp)}${c.organisation && c.organisation !== c.isp ? ' · ' + esc(c.organisation) : ''}</dd>` : ''}
        ${c.reverse_dns ? `<dt>Reverse DNS</dt><dd>${esc(c.reverse_dns)}</dd>` : ''}
        <dt>Type</dt><dd>${[
          c.hosting ? '<span class="chip chip-amber">Hosting provider</span>' : '',
          c.proxy ? '<span class="chip chip-red">Proxy / VPN / Tor</span>' : '',
          c.mobile ? '<span class="chip">Mobile network</span>' : '',
          (!c.hosting && !c.proxy && !c.mobile) ? '<span class="chip chip-teal">Access network</span>' : '',
        ].join(' ')}</dd>
      </dl>` : ''}

      <div class="rep-reasons">
        ${(v.reasons || []).map((r) => `<div class="rep-reason">${esc(r)}</div>`).join('')}
      </div>

      ${(v.sources || []).map((s) => `
        <div class="rep-source">
          <strong>${esc(s.feed)}</strong>
          <span class="tag" data-sev="${esc(s.severity)}">${esc(s.severity)}</span>
          <p class="note">${esc(s.description || '')}</p>
        </div>`).join('')}

      ${(v.pivots || []).length ? `
        <div class="rep-pivots">
          <span class="rep-pivot-label">Check further</span>
          ${v.pivots.map((p) => `<a class="pivot" href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.name)}</a>`).join('')}
        </div>` : ''}
    </article>`;
  };

  const flagged = verdicts.filter((v) => (v.score || 0) > 0);

  panel.innerHTML = `
    ${state.repFeedsMissing ? `
      <div class="banner banner-amber">
        <strong>No blocklists downloaded</strong>
        <p>${esc(state.repFeedsMissing)}</p>
        <button class="primary-btn small" id="refreshFeedsTop">Download feeds now</button>
      </div>` : ''}
    <div class="card">
      <h3>External address reputation</h3>
      <p class="note">${num(data.addresses_checked)} external addresses and
        ${num(data.domains_checked)} names checked against locally cached
        public blocklists. Turning on live context adds the operator,
        network type and country from a keyless service — it sends the
        addresses only, never the capture.</p>
      <div class="stat-grid" style="margin-top:14px">
        <div class="stat"><b style="color:${flagged.length ? '#d6336c' : '#0ca678'}">${flagged.length}</b><span>Scored above zero</span></div>
        <div class="stat"><b>${num(data.addresses_checked)}</b><span>Addresses</span></div>
        <div class="stat"><b>${num(data.domains_checked)}</b><span>Names</span></div>
      </div>
      <div class="rep-actions">
        <label class="switch">
          <input type="checkbox" id="repOnline" ${state.repOnline ? 'checked' : ''}>
          <span>Live network context (queries a keyless lookup service)</span>
        </label>
        <button class="ghost-btn small" id="refreshFeeds">Update feeds</button>
      </div>
    </div>
    ${verdicts.length ? verdicts.map(card).join('')
      : `<div class="card"><p class="note">Nothing in this capture appears on
          the cached blocklists. A useful negative, not a clean bill of
          health: these lists cover what is already publicly known.</p></div>`}
    <div class="card"><h3>Feeds in use</h3></div>
    ${feedTable(data.feeds || [])}`;

  wireFeedRefresh();
  const topButton = $('refreshFeedsTop');
  if (topButton) {
    topButton.onclick = () => { $('refreshFeeds')?.click(); };
  }
  const toggle = $('repOnline');
  if (toggle) {
    toggle.onchange = () => { state.repOnline = toggle.checked; renderReputation(); };
  }
}


function wireFeedRefresh() {
  const button = document.getElementById('refreshFeeds');
  if (!button) return;
  button.onclick = async () => {
    button.disabled = true;
    button.textContent = 'Downloading…';
    try {
      const res = await api('/api/reputation/refresh', { method: 'POST' });
      const data = await res.json();
      button.textContent = (data.failed && data.failed.length)
        ? `${data.updated} updated, ${data.failed.length} unreachable`
        : `${data.updated} feeds updated`;
      setTimeout(renderReputation, 900);
    } catch (err) {
      button.textContent = err.status ? `Download failed — ${err.message}` : 'Download failed — no network?';
      button.disabled = false;
    }
  };
}

/* ------------------------------------------------------------ timeline */

const EVENT_ICON = {
  finding: '!', credential: 'K', file: 'F', call: 'C', contact: '>',
};

function renderTimeline() {
  const events = state.report.events || [];
  setTabVisible('timeline', events.length > 0);
  if (!events.length) return;

  const first = events[0].ts;

  const row = (e) => {
    const offset = e.ts - first;
    return `
      <li class="event" data-sev="${esc(e.severity)}" data-kind="${esc(e.kind)}">
        <span class="event-time mono">
          <b>${clockOnly(e.ts)}</b>
          <i>+${formatDuration(offset)}</i>
        </span>
        <span class="event-mark">${esc(EVENT_ICON[e.kind] || '.')}</span>
        <span class="event-body">
          <span class="event-title">${esc(e.title)}${
            e.repeats ? `<span class="event-repeat">×${e.repeats}</span>` : ''}</span>
          <span class="event-detail">${esc(e.detail || '')}</span>
          ${(e.hosts || []).filter(Boolean).length
            ? `<span class="event-hosts mono">${esc(e.hosts.filter(Boolean).join(', '))}</span>` : ''}
        </span>
      </li>`;
  };

  const kinds = [...new Set(events.map((e) => e.kind))];

  $('panelTimeline').innerHTML = `
    <div class="card">
      <h3>What happened, in order</h3>
      <p class="note">Findings, credentials, transferred files, calls and
        first contact with each external address, merged into one sequence.
        Grouping by category answers what kind of thing was going on; this
        answers what followed what.</p>
      <div class="event-filters">
        ${kinds.map((k) => `<button class="chip-btn active" data-kind="${esc(k)}">${esc(k)}</button>`).join('')}
      </div>
    </div>
    <ol class="timeline">${events.map(row).join('')}</ol>`;

  $('panelTimeline').querySelectorAll('.chip-btn').forEach((button) => {
    button.onclick = () => {
      button.classList.toggle('active');
      const off = [...$('panelTimeline').querySelectorAll('.chip-btn:not(.active)')]
        .map((b) => b.dataset.kind);
      $('panelTimeline').querySelectorAll('.event').forEach((el) => {
        el.hidden = off.includes(el.dataset.kind);
      });
    };
  });
}

function clockOnly(ts) {
  const full = clockTime(ts);
  return full === '—' ? full : full.slice(11);
}

/* ---------------------------------------------------------------- voip */

function renderVoip() {
  const voip = state.report.voip || {};
  const calls = voip.calls || [];
  const streams = voip.rtp_streams || [];
  setTabVisible('voip', calls.length + streams.length > 0, calls.length);
  if (!calls.length && !streams.length) return;

  const answered = calls.filter((c) => c.answered);
  const encrypted = calls.filter((c) => c.media_encrypted);

  const callCard = (c) => `
    <article class="call-card" data-answered="${c.answered}">
      <header>
        <span class="call-state ${c.answered ? 'answered' : 'unanswered'}">
          ${c.answered ? 'Answered' : (c.final_status || 'No answer')}</span>
        <span class="call-parties mono">
          ${esc(c.caller || 'unknown')}
          <span class="arrow">\u2192</span>
          ${esc(c.callee || 'unknown')}</span>
        ${c.duration ? `<span class="call-duration">${formatDuration(c.duration)}</span>` : ''}
      </header>
      <dl class="kv">
        ${c.caller_ip ? `<dt>Endpoints</dt><dd>${esc(c.caller_ip)} \u2192 ${esc(c.callee_ip || '?')}</dd>` : ''}
        ${c.user_agents.length ? `<dt>Software</dt><dd>${esc(c.user_agents.join(', '))}</dd>` : ''}
        ${c.setup_time ? `<dt>Setup</dt><dd>${c.setup_time}s to answer</dd>` : ''}
        <dt>Signalling</dt><dd>${esc(c.methods.join(', ') || '\u2014')}</dd>
        <dt>Media</dt><dd>${c.media_encrypted
          ? '<span style="color:#0ca678">SRTP \u2014 encrypted</span>'
          : '<span style="color:#e8590c">Plain RTP \u2014 audio recoverable from this capture</span>'}</dd>
        ${c.auth_attempts.length ? `<dt>Auth</dt><dd>${c.auth_attempts.length} digest exchange(s)</dd>` : ''}
      </dl>
      ${c.rtp_streams.length ? `
        <div class="call-media">
          ${c.rtp_streams.map((s) => `
            <div class="media-row mono">
              <span>${esc(s.from)} \u2192 ${esc(s.to)}</span>
              <span class="tag">${esc(s.codec)}</span>
              <span>${num(s.packets)} pkts</span>
              <span>${s.duration}s</span>
              <span style="color:${s.loss_percent > 5 ? '#e8590c' : 'var(--ink-3)'}">
                ${s.loss_percent}% loss</span>
            </div>`).join('')}
        </div>` : ''}
    </article>`;

  $('panelVoip').innerHTML = `
    <div class="card">
      <h3>Calls</h3>
      <p class="note">Rebuilt from SIP signalling and matched to the media
        streams they negotiated. Where media is unencrypted, the audio is
        recoverable from this capture by anyone who holds it.</p>
      <div class="stat-grid" style="margin-top:14px">
        <div class="stat"><b>${calls.length}</b><span>Dialogues</span></div>
        <div class="stat"><b>${answered.length}</b><span>Answered</span></div>
        <div class="stat"><b>${streams.length}</b><span>Media streams</span></div>
        <div class="stat"><b style="color:${encrypted.length === calls.length && calls.length ? '#0ca678' : '#e8590c'}">
          ${encrypted.length}</b><span>Encrypted</span></div>
      </div>
    </div>
    ${calls.map(callCard).join('')}
    ${streams.length ? `
      <div class="card"><h3>All media streams</h3></div>
      ${table([
        { label: 'From', cls: 'mono', render: (s) => `${esc(s.src)}:${s.src_port}` },
        { label: 'To', cls: 'mono', render: (s) => `${esc(s.dst)}:${s.dst_port}` },
        { label: 'Codec', render: (s) => esc(s.codec) },
        { label: 'Packets', cls: 'mono', render: (s) => num(s.packets) },
        { label: 'Seconds', cls: 'mono', render: (s) => s.duration },
        { label: 'Loss', cls: 'mono', render: (s) => s.loss_percent > 5
            ? `<span style="color:#e8590c">${s.loss_percent}%</span>` : `${s.loss_percent}%` },
      ], streams, '')}` : ''}`;
}

function formatDuration(seconds) {
  const total = Math.round(seconds || 0);
  if (total < 60) return `${total}s`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s`;
  return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m`;
}

/* --------------------------------------------------- credentials */

const SECRET_KIND_LABEL = {
  password: 'Password in the clear',
  hash: 'Hash — crackable offline',
  'challenge-response': 'Challenge response — crackable offline',
  token: 'Bearer token',
};

function renderCredentials() {
  const creds = state.report.credentials || [];
  setTabVisible('credentials', creds.length > 0, creds.length);
  if (!creds.length) return;

  const plain = creds.filter((c) => c.secret_kind === 'password');
  const hashes = creds.filter((c) => c.secret_kind === 'hash' || c.secret_kind === 'challenge-response');
  const tokens = creds.filter((c) => c.secret_kind === 'token');

  const card = (c) => `
    <article class="cred-card" data-kind="${esc(c.secret_kind)}">
      <header>
        <span class="cred-proto">${esc(c.protocol)}</span>
        <span class="cred-method">${esc(c.method)}</span>
        <span class="cred-route mono">${esc(c.client)} → ${esc(c.server)}:${c.server_port}</span>
      </header>
      <div class="cred-pair">
        <div>
          <span class="cred-label">Account</span>
          <span class="cred-value mono">${esc(c.username || '(not seen)')}</span>
        </div>
        <div>
          <span class="cred-label">${esc(SECRET_KIND_LABEL[c.secret_kind] || 'Secret')}</span>
          <span class="cred-value mono secret">${esc(c.secret || '—')}</span>
        </div>
      </div>
      ${c.realm ? `<p class="note">Realm: ${esc(c.realm)}</p>` : ''}
      ${c.note ? `<p class="note">${esc(c.note)}</p>` : ''}
    </article>`;

  const section = (title, items, blurb) => items.length ? `
    <div class="card">
      <h3>${esc(title)} <span class="tag">${items.length}</span></h3>
      <p class="note">${esc(blurb)}</p>
    </div>
    ${items.map(card).join('')}` : '';

  $('panelCredentials').innerHTML =
    section('Passwords readable from the traffic', plain,
      'Sent with no encryption, or encoded in a way that is not encryption. '
      + 'These are usable now — there is no cracking step.')
    + section('Hashes and challenge responses', hashes,
      'The password itself was not sent, but these can be attacked offline '
      + 'with no failed logins and no lockouts to alert anyone.')
    + section('Tokens', tokens,
      'Whoever holds a bearer token is authenticated without needing the '
      + 'password.');
}

/* --------------------------------------------------------------- files */

const SIG_COLOR = {
  critical: '#d6336c', high: '#e8590c', medium: '#c48a00', low: '#3b5bdb',
};

function renderFiles() {
  const files = state.report.files || [];
  setTabVisible('files', files.length > 0, files.length);
  if (!files.length) return;

  const cards = files.map((f) => {
    const sigs = (f.signatures || []).map((s) =>
      `<span class="sig" style="color:${SIG_COLOR[s.severity] || '#5b7c96'};
        border-color:${(SIG_COLOR[s.severity] || '#5b7c96')}55"
        title="${esc(s.description)}">${esc(s.name)}</span>`).join('');

    const pe = f.pe_info ? `
      <div class="file-block">
        <h5>Executable detail</h5>
        <dl class="kv">
          <dt>Architecture</dt><dd>${esc(f.pe_info.architecture)}</dd>
          <dt>Type</dt><dd>${f.pe_info.is_dll ? 'DLL' : 'Executable'} ·
            ${esc(f.pe_info.subsystem)}</dd>
          <dt>Imphash</dt><dd>${esc(f.pe_info.imphash || 'not resolvable')}</dd>
          <dt>Imports</dt><dd>${num(f.pe_info.import_count)} from
            ${num((f.pe_info.imported_dlls || []).length)} libraries</dd>
          <dt>Sections</dt><dd>${(f.pe_info.sections || []).map((sec) =>
            `${esc(sec.name)} (${sec.entropy})`).join(', ') || '—'}</dd>
        </dl>
        ${(f.pe_info.suspicious_imports || []).length ? `
          <div class="api-list">
            ${f.pe_info.suspicious_imports.map((i) =>
              `<span class="tag" title="${esc(i.reason)}">${esc(i.api)}</span>`).join('')}
          </div>` : ''}
      </div>` : '';

    const notes = (f.notes || []).length
      ? `<div class="file-block"><h5>Notes</h5>${
          f.notes.map((n) => `<p class="note-line">${esc(n)}</p>`).join('')}</div>`
      : '';

    return `
      <article class="file-card">
        <header>
          <div>
            <strong>${esc(f.filename || '(unnamed)')}</strong>
            <span class="muted-inline">${esc(f.description)} · ${bytes(f.size)}
              ${f.truncated ? ' · truncated' : ''}</span>
          </div>
          <div class="file-sigs">${sigs}</div>
        </header>
        ${f.stored ? `<div class="file-actions">
          <a class="ghost-btn small" download
             href="/api/reports/${state.jobId}/files/${esc(f.sha256)}">
            Download file</a>
          <span class="note" style="margin:0">Handle in an isolated
            environment — this may be live malware.</span>
        </div>` : ''}
        <dl class="kv">
          <dt>SHA-256</dt><dd>${esc(f.sha256)}</dd>
          <dt>MD5</dt><dd>${esc(f.md5)}</dd>
          <dt>Entropy</dt><dd>${f.entropy} bits/byte</dd>
          <dt>From</dt><dd>${esc(f.source)} → ${esc(f.destination)} (${esc(f.protocol)})</dd>
          ${f.url ? `<dt>URL</dt><dd>${esc(f.url)}</dd>` : ''}
          ${f.content_type ? `<dt>Declared as</dt><dd>${esc(f.content_type)}</dd>` : ''}
        </dl>
        ${pe}
        ${notes}
      </article>`;
  }).join('');

  $('panelFiles').innerHTML = `
    <div class="card">
      <h3>Files rebuilt from traffic</h3>
      <p class="note">Reconstructed from the packets themselves, so these
        hashes describe exactly what each endpoint received — not what the
        server claimed to send.</p>
    </div>${cards}`;
}

/* ------------------------------------------------------------- streams */

function renderStreams() {
  const streams = state.report.streams || [];
  setTabVisible('streams', streams.length > 0);
  if (!streams.length) return;

  $('panelStreams').innerHTML = `
    <div class="card">
      <h3>Reassembled conversations</h3>
      <p class="note">Click a row to read the reconstructed stream. Missing
        bytes are shown as gaps rather than closed up, so offsets stay true
        to what was on the wire.</p>
    </div>
    ${table([
      { label: 'Client', cls: 'mono', render: (s) => esc(s.client) },
      { label: 'Server', cls: 'mono', render: (s) => esc(s.server) },
      { label: 'Port', cls: 'mono', render: (s) => s.server_port },
      { label: 'Service', render: (s) => esc(s.service || '—') },
      { label: 'To server', cls: 'mono', render: (s) => bytes(s.bytes_to_server) },
      { label: 'To client', cls: 'mono', render: (s) => bytes(s.bytes_to_client) },
      { label: 'Missing', cls: 'mono', render: (s) =>
          s.missing_bytes ? `<span style="color:#c48a00">${bytes(s.missing_bytes)}</span>` : '—' },
      { label: '', render: (s) =>
          `<button class="ghost-btn small" data-stream="${s.id}">Read</button>` },
    ], streams, 'No streams were reassembled.')}
    <div id="streamViewer"></div>`;

  $('panelStreams').querySelectorAll('[data-stream]').forEach((btn) => {
    btn.onclick = () => showStream(Number(btn.dataset.stream));
  });
}

function showStream(id) {
  const stream = (state.report.streams || []).find((s) => s.id === id);
  if (!stream) return;
  const viewer = $('streamViewer');
  viewer.innerHTML = `
    <div class="card stream-viewer">
      <h3>${esc(stream.client)}:${stream.client_port} ⇄
          ${esc(stream.server)}:${stream.server_port}
        <button class="ghost-btn small" id="closeStream">Close</button></h3>
      <h4 class="stream-dir">Client → server</h4>
      <pre class="json-box">${esc(stream.preview_to_server || '(nothing sent)')}</pre>
      <h4 class="stream-dir">Server → client</h4>
      <pre class="json-box">${esc(stream.preview_to_client || '(nothing returned)')}</pre>
    </div>`;
  $('closeStream').onclick = () => { viewer.innerHTML = ''; };
  viewer.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' });
}

/* ------------------------------------------------------------- windows */

function renderWindows() {
  const w = state.report.windows || {};
  const smb = w.smb || {};
  const ntlm = w.ntlm || [];
  const kerberos = w.kerberos || [];
  const has = (smb.messages || 0) + ntlm.length + kerberos.length > 0;
  setTabVisible('windows', has);
  if (!has) return;

  const smbCard = smb.messages ? `
    <div class="card">
      <h3>SMB</h3>
      <div class="stat-grid">
        <div class="stat"><b>${num(smb.messages)}</b><span>Messages</span></div>
        ${(smb.versions || []).map((v) =>
          `<div class="stat"><b>${num(v.messages)}</b><span>${esc(v.version)}</span></div>`).join('')}
      </div>
      ${barList((smb.top_commands || []).map((c) => ({ label: c.command, value: c.count })))}
    </div>` : '';

  const ntlmTable = ntlm.length ? `
    <div class="card"><h3>NTLM authentications</h3></div>
    ${table([
      { label: 'Account', render: (r) => esc(`${r.domain || ''}\\${r.user || ''}`) },
      { label: 'Workstation', render: (r) => esc(r.workstation || '—') },
      { label: 'Source', cls: 'mono', render: (r) => esc(r.source) },
      { label: 'Target', cls: 'mono', render: (r) => esc(r.target) },
      { label: 'Version', render: (r) => r.version === 'NTLMv1'
          ? `<span style="color:#e8590c">${esc(r.version)}</span>` : esc(r.version) },
      { label: 'Over', render: (r) => esc(r.transport || '—') },
    ], ntlm, '')}` : '';

  const kerbTable = kerberos.length ? `
    <div class="card"><h3>Kerberos</h3></div>
    ${table([
      { label: 'Message', render: (r) => esc(r.message) },
      { label: 'Source', cls: 'mono', render: (r) => esc(r.source) },
      { label: 'Target', cls: 'mono', render: (r) => esc(r.target) },
      { label: 'Service targeted', cls: 'mono truncate',
        render: (r) => esc(r.service || '—') },
      { label: 'Encryption', render: (r) => r.weak
          ? `<span style="color:#e8590c">${esc(r.encryption)}</span>` : esc(r.encryption) },
    ], kerberos, '')}` : '';

  $('panelWindows').innerHTML = smbCard + ntlmTable + kerbTable;
}

/* -------------------------------------------------------------- OT/IoT */

function renderOt() {
  const ics = state.report.ics || [];
  const iot = state.report.iot || [];
  setTabVisible('ot', ics.length + iot.length > 0);
  if (!ics.length && !iot.length) return;

  const icsBlock = ics.length ? `
    <div class="card">
      <h3>Industrial control</h3>
      <p class="note">These protocols carry no authentication. Any host that
        can reach a controller can command it.</p>
    </div>
    ${table([
      { label: 'Protocol', render: (r) => esc(r.protocol) },
      { label: 'Source', cls: 'mono', render: (r) => esc(r.source) },
      { label: 'Controller', cls: 'mono', render: (r) => esc(r.target) },
      { label: 'Command', render: (r) => r.dangerous
          ? `<span style="color:#e8590c">${esc(r.command)}</span>` : esc(r.command) },
      { label: 'Packet', cls: 'mono', render: (r) => num(r.packet) },
    ], ics, '')}` : '';

  const iotBlock = iot.length ? `
    <div class="card"><h3>IoT messaging</h3></div>
    ${table([
      { label: 'Protocol', render: (r) => esc(r.protocol) },
      { label: 'Source', cls: 'mono', render: (r) => esc(r.source) },
      { label: 'Target', cls: 'mono', render: (r) => esc(r.target) },
      { label: 'Type', render: (r) => esc(r.type || '—') },
      { label: 'Detail', cls: 'truncate', render: (r) => esc(r.detail || '—') },
      { label: 'Encrypted', render: (r) => r.encrypted === undefined ? '—'
          : (r.encrypted ? 'Yes' : `<span style="color:#e8590c">No</span>`) },
    ], iot, '')}` : '';

  $('panelOt').innerHTML = icsBlock + iotBlock;
}

/* ------------------------------------------------------------ wireless */

function renderWireless() {
  const wireless = state.report.wireless || {};
  const networks = wireless.networks || [];
  const events = wireless.events || [];
  setTabVisible('wireless', networks.length + events.length > 0);
  if (!networks.length && !events.length) return;

  const netTable = networks.length ? `
    <div class="card"><h3>Networks seen</h3></div>
    ${table([
      { label: 'Network name', render: (n) => esc(n.ssid) },
      { label: 'Access points', cls: 'mono', render: (n) => n.ap_count > 1
          ? `<span style="color:#c48a00">${n.ap_count}</span>` : n.ap_count },
      { label: 'Hardware', cls: 'mono truncate', render: (n) => esc(n.access_points.join(', ')) },
      { label: 'Security', render: (n) => esc(n.security.join(', ') || '—') },
      { label: 'Beacons', cls: 'mono', render: (n) => num(n.beacons) },
    ], networks, '')}` : '';

  const eventTable = events.length ? `
    <div class="card"><h3>Management frames</h3></div>
    ${table([
      { label: 'Type', render: (e) => esc(e.type) },
      { label: 'Source', cls: 'mono', render: (e) => esc(e.source || '—') },
      { label: 'Network', cls: 'mono', render: (e) => esc(e.bssid || '—') },
      { label: 'Reason', render: (e) => esc(e.reason || '—') },
    ], events, '')}` : '';

  $('panelWireless').innerHTML = netTable + eventTable;
}

/* -------------------------------------------------------------- export */

function renderExport() {
  const id = state.jobId;
  const link = (href, title, description) => `
    <a class="export-card" href="${href}" ${href.includes('/view') ? 'target="_blank"' : ''}>
      <strong>${esc(title)}</strong>
      <span>${esc(description)}</span>
    </a>`;

  $('panelExport').innerHTML = `
    <div class="card">
      <h3>Take this analysis elsewhere</h3>
      <p class="note">Every export is generated from the same stored report,
        so the numbers match whichever format you choose.</p>
    </div>
    <div class="export-grid">
      ${link(`/api/reports/${id}/view`, 'Open HTML report',
             'Full report in a new tab. Print it to PDF from the browser.')}
      ${link(`/api/reports/${id}/export/html`, 'Download HTML report',
             'One self-contained file. Opens without a server, keeps its formatting.')}
      ${link(`/api/reports/${id}/download`, 'Download JSON',
             'The complete report, every table and field.')}
      ${link(`/api/reports/${id}/export/stix`, 'STIX 2.1 bundle',
             'Indicators, ATT&CK techniques and findings for a threat platform.')}
      ${link(`/api/reports/${id}/export/misp`, 'MISP event',
             'Ready to import as an event, with attributes and tags.')}
    </div>
    <div class="card">
      <h3>Spreadsheet exports</h3>
      <div class="export-grid">
        ${['findings', 'credentials', 'hosts', 'flows', 'files', 'iocs'].map((t) =>
          link(`/api/reports/${id}/export/csv?table=${t}`,
               `${t.charAt(0).toUpperCase()}${t.slice(1)} CSV`,
               `One row per ${t === 'iocs' ? 'indicator' : t.replace(/s$/, '')}.`)).join('')}
      </div>
    </div>`;
}

/* ------------------------------------------------------------ overview */

function gauge(score, band) {
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  const color = BAND_COLOR[band] || '#5c7cfa';
  return `
    <div class="gauge">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r="${radius}" fill="none"
                stroke="#12233a" stroke-width="11"/>
        <circle cx="66" cy="66" r="${radius}" fill="none"
                stroke="${color}" stroke-width="11" stroke-linecap="round"
                stroke-dasharray="${circumference}"
                stroke-dashoffset="${offset}"/>
      </svg>
      <div class="gauge-value">
        <b style="color:${color}">${score}</b>
        <span>Risk</span>
      </div>
    </div>`;
}

function barList(rows, valueFormat = num) {
  if (!rows.length) return '<p class="note">Nothing recorded.</p>';
  const max = Math.max(...rows.map((r) => r.value)) || 1;
  return rows.map((row) => `
    <div class="bar-row">
      <span class="bar-label" title="${esc(row.label)}">${esc(row.label)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${(row.value / max) * 100}%"></span></span>
      <span class="bar-value">${valueFormat(row.value)}</span>
    </div>`).join('');
}

function timelineChart(points) {
  if (!points.length) return '<p class="note">No timeline available.</p>';
  const width = 900;
  const height = 132;
  const max = Math.max(...points.map((p) => p.bytes)) || 1;
  const step = width / Math.max(1, points.length - 1);

  const line = points.map((p, i) =>
    `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(height - (p.bytes / max) * (height - 16) - 8).toFixed(1)}`
  ).join(' ');

  const area = `${line} L${width},${height} L0,${height} Z`;

  return `
    <svg class="timeline-chart" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <defs>
        <linearGradient id="tlFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#00d4ff" stop-opacity=".42"/>
          <stop offset="100%" stop-color="#00d4ff" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <path d="${area}" fill="url(#tlFill)"/>
      <path d="${line}" fill="none" stroke="#00d4ff" stroke-width="1.8"/>
    </svg>`;
}

function renderOverview() {
  const r = state.report;
  const s = r.stats;
  const sev = s.severity_counts || {};

  const sevPills = ['critical', 'high', 'medium', 'low', 'info']
    .filter((k) => sev[k])
    .map((k) => `<span class="sev-pill" data-sev="${k}">
        ${sev[k]} ${k}</span>`).join('');

  const stats = [
    ['Packets', num(r.capture.packets)],
    ['Capture span', duration(r.capture.duration_seconds)],
    ['Data volume', bytes(r.capture.bytes_on_wire)],
    ['Hosts', num(s.hosts)],
    ['Flows', num(s.flows)],
    ['DNS queries', num(s.dns_queries)],
    ['HTTP requests', num(s.http_requests)],
    ['TLS sessions', num(s.tls_sessions)],
  ].map(([label, value]) => `<div class="stat"><b>${value}</b><span>${label}</span></div>`).join('');

  const protocols = r.protocols.slice(0, 10).map((p) => ({ label: p.name, value: p.packets }));
  const talkers = r.top_talkers.slice(0, 10).map((t) => ({ label: t.ip, value: t.bytes }));
  const conversations = r.conversations.slice(0, 10)
    .map((c) => ({ label: `${c.a} ⇄ ${c.b}`, value: c.bytes }));

  const captureFacts = [
    ['Format', `${r.capture.format}${r.capture.compression ? ` (${r.capture.compression})` : ''}`],
    ['Link types', (r.capture.link_types || []).join(', ') || '—'],
    ['Snap length', r.capture.snaplen ? `${num(r.capture.snaplen)} bytes` : '—'],
    ['First packet', clockTime(r.capture.first_packet)],
    ['Last packet', clockTime(r.capture.last_packet)],
    ['Capture tool', r.capture.capture_tool || 'Not recorded'],
    ['Analysis time', `${r.meta.analysis_seconds}s`],
  ].map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');

  const encap = r.encapsulation.length
    ? `<div class="card"><h3>Encapsulation seen</h3>${barList(
        r.encapsulation.map((e) => ({ label: e.name, value: e.packets })))}</div>`
    : '';

  $('panelOverview').innerHTML = `
    <div class="verdict">
      ${gauge(s.risk_score, s.risk_band)}
      <div>
        <div class="verdict-band" style="color:${BAND_COLOR[s.risk_band]}">${s.risk_band} risk</div>
        <p class="verdict-text">${esc(s.verdict)}</p>
        <p class="verdict-profile">${esc(r.profile.summary || '')}</p>
        <div class="sev-strip">${sevPills || '<span class="note">No findings raised.</span>'}</div>
      </div>
    </div>

    <div class="stat-grid">${stats}</div>

    <div class="card">
      <h3>Traffic over time</h3>
      ${timelineChart(r.timeline)}
      <p class="note">Bytes per interval across the capture window.</p>
    </div>

    <div class="card-grid">
      <div class="card"><h3>Protocols</h3>${barList(protocols)}</div>
      <div class="card"><h3>Busiest hosts</h3>${barList(talkers, bytes)}</div>
    </div>

    <div class="card-grid">
      <div class="card"><h3>Busiest conversations</h3>${barList(conversations, bytes)}</div>
      <div class="card"><h3>Capture details</h3><dl class="kv">${captureFacts}</dl></div>
    </div>

    ${encap}
  `;
}

/* ------------------------------------------------------------ findings */

function renderFindings() {
  const findings = state.report.findings;
  const panel = $('panelFindings');

  if (!findings.length) {
    panel.innerHTML = `<div class="empty">
      <strong>Nothing flagged</strong>
      No detection raised a finding on this capture.</div>`;
    return;
  }

  panel.innerHTML = findings.map((f, index) => {
    const attck = (f.mitre || []).map((id, i) =>
      `<span class="attck">${esc(id)} · ${esc(f.mitre_names?.[i] || '')}</span>`).join('');

    const evidence = f.evidence?.length
      ? `<div class="finding-section">
           <h4>Evidence</h4>
           <div class="json-box">${esc(JSON.stringify(f.evidence, null, 2))}</div>
         </div>`
      : '';

    const hosts = f.hosts?.length
      ? `<div class="finding-section"><h4>Hosts involved</h4>
           <p class="mono">${f.hosts.map(esc).join(', ')}</p></div>`
      : '';

    return `
      <article class="finding" data-sev="${f.severity}" data-index="${index}">
        <div class="finding-head">
          <span class="sev-badge" data-sev="${esc(f.severity)}">${esc(f.severity)}</span>
          <span class="finding-title">${esc(f.title)}</span>
          <span class="finding-meta">${f.count > 1 ? `${num(f.count)} × · ` : ''}${f.confidence} confidence</span>
          <span class="finding-caret">▶</span>
        </div>
        <div class="finding-body">
          <div class="finding-section"><h4>What was observed</h4><p>${esc(f.description)}</p></div>
          <div class="finding-section"><h4>Why it matters</h4><p>${esc(f.why)}</p></div>
          <div class="finding-section"><h4>What to do next</h4><p>${esc(f.recommendation)}</p></div>
          ${attck ? `<div class="finding-section"><h4>MITRE ATT&amp;CK</h4>${attck}</div>` : ''}
          ${hosts}
          ${evidence}
        </div>
      </article>`;
  }).join('');

  panel.querySelectorAll('.finding-head').forEach((head) => {
    head.addEventListener('click', () => head.parentElement.classList.toggle('open'));
  });
}

/* --------------------------------------------------------------- tables */

function table(columns, rows, emptyMessage) {
  if (!rows.length) {
    return `<div class="empty"><strong>Nothing to show</strong>${esc(emptyMessage)}</div>`;
  }
  const head = columns.map((c) => `<th>${esc(c.label)}</th>`).join('');
  const body = rows.map((row) =>
    `<tr>${columns.map((c) => `<td class="${c.cls || ''}">${c.render(row)}</td>`).join('')}</tr>`
  ).join('');
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function riskCell(score) {
  const color = riskColor(score);
  // White on a solid severity colour, rather than the colour on a wash of
  // itself, which is unreadable at every tint that still looks tinted.
  return `<span class="risk-cell" style="background:${color}">${score}</span>`;
}

function renderHosts() {
  $('panelHosts').innerHTML = table([
    { label: 'Host', cls: 'mono', render: (h) => esc(h.ip) },
    { label: 'Name', render: (h) => esc((h.hostnames || [])[0] || '—') },
    { label: 'Vendor', render: (h) => esc(h.vendor || '—') },
    { label: 'Scope', render: (h) => h.internal ? 'Internal' : 'External' },
    { label: 'IP', render: (h) => `v${h.ip_version}` },
    { label: 'Packets', cls: 'mono', render: (h) => num(h.packets) },
    { label: 'Volume', cls: 'mono', render: (h) => bytes(h.bytes) },
    { label: 'Peers', cls: 'mono', render: (h) => num(h.peers) },
    { label: 'Serving', render: (h) => (h.services || []).map((s) => `<span class="tag">${esc(s)}</span>`).join('') || '—' },
    { label: 'Risk', render: (h) => riskCell(h.risk) },
  ], state.report.hosts, 'No hosts were identified in this capture.');
}

function renderFlows() {
  $('panelFlows').innerHTML = table([
    { label: 'Source', cls: 'mono', render: (f) => esc(f.source) },
    { label: 'Destination', cls: 'mono', render: (f) => esc(f.destination) },
    { label: 'Port', cls: 'mono', render: (f) => f.destination_port || '—' },
    { label: 'Service', render: (f) => esc(f.service || '—') },
    { label: 'Protocol', render: (f) => esc(f.protocol) },
    { label: 'Packets', cls: 'mono', render: (f) => num(f.packets) },
    { label: 'Volume', cls: 'mono', render: (f) => bytes(f.bytes) },
    { label: 'Duration', cls: 'mono', render: (f) => duration(f.duration) },
    { label: 'SNI', cls: 'mono truncate', render: (f) => esc(f.sni || '—') },
  ], state.report.flows, 'No transport-layer flows were reconstructed.');
}

function renderDns() {
  const dns = state.report.dns;
  const summary = `
    <div class="stat-grid">
      <div class="stat"><b>${num(dns.total_queries)}</b><span>Queries</span></div>
      <div class="stat"><b>${num(dns.unique_domains)}</b><span>Unique domains</span></div>
    </div>`;

  $('panelDns').innerHTML = summary + table([
    { label: 'Domain', cls: 'mono truncate', render: (d) => esc(d.name) },
    { label: 'Queries', cls: 'mono', render: (d) => num(d.queries) },
  ], dns.top_domains, 'No DNS traffic was present in this capture.');
}

function renderHttp() {
  const http = state.report.http;
  const hosts = http.top_hosts.length
    ? `<div class="card"><h3>Requested hosts</h3>${barList(
        http.top_hosts.slice(0, 15).map((h) => ({ label: h.host, value: h.requests })))}</div>`
    : '';

  $('panelHttp').innerHTML = hosts + table([
    { label: 'Source', cls: 'mono', render: (h) => esc(h.source) },
    { label: 'Method', render: (h) => esc(h.method || '—') },
    { label: 'Host', cls: 'mono truncate', render: (h) => esc(h.host || '—') },
    { label: 'Path', cls: 'mono truncate', render: (h) => esc(h.uri || '—') },
    { label: 'Client', cls: 'truncate', render: (h) => esc(h.user_agent || '—') },
  ], http.requests, 'No plaintext HTTP was present in this capture.');
}

function renderTls() {
  const tls = state.report.tls;
  const sni = tls.top_sni.length
    ? `<div class="card"><h3>Server names requested</h3>${barList(
        tls.top_sni.slice(0, 15).map((s) => ({ label: s.name, value: s.sessions })))}</div>`
    : '';

  $('panelTls').innerHTML = sni + table([
    { label: 'Client', cls: 'mono', render: (t) => esc(t.client) },
    { label: 'Server', cls: 'mono', render: (t) => esc(t.server) },
    { label: 'SNI', cls: 'mono truncate', render: (t) => esc(t.sni || '—') },
    { label: 'Version', render: (t) => esc(t.version || '—') },
    { label: 'ALPN', cls: 'mono', render: (t) => esc((t.alpn || []).join(', ') || '—') },
    { label: 'JA3', cls: 'mono truncate', render: (t) => esc(t.ja3 || '—') },
    { label: 'JA4', cls: 'mono truncate', render: (t) => esc(t.ja4 || '—') },
  ], tls.sessions, 'No TLS handshakes were captured.');
}

function renderIocs() {
  const iocs = state.report.iocs;
  const total = iocs.ip_addresses.length + iocs.domains.length + iocs.ja3.length;

  if (!total) {
    $('panelIocs').innerHTML = `<div class="empty">
      <strong>No indicators extracted</strong>
      Indicators are collected from medium severity findings and above. This capture raised none.</div>`;
    return;
  }

  const block = (title, items, note) => items.length ? `
    <div class="card">
      <h3>${title} <span class="tag">${items.length}</span></h3>
      <div class="json-box">${items.map(esc).join('\n')}</div>
      ${note ? `<p class="note">${esc(note)}</p>` : ''}
    </div>` : '';

  $('panelIocs').innerHTML = `
    ${block('IP addresses (defanged)', iocs.ip_addresses_defanged,
            'Defanged so they can be pasted into a ticket without becoming clickable.')}
    ${block('Domains (defanged)', iocs.domains_defanged)}
    ${block('JA3 fingerprints', iocs.ja3,
            'Client fingerprints that appeared rarely. Match these against known tooling.')}
    <div class="card">
      <h3>Export</h3>
      <p class="note">${esc(iocs.note)}</p>
      <p style="margin-top:12px">
        <a class="ghost-btn" href="/api/reports/${state.jobId}/download"
           style="text-decoration:none;display:inline-block">Download full report (JSON)</a>
      </p>
    </div>`;
}

/* ----------------------------------------------------------------- map */

/* Graph styling for a light background. Matte fills, no glow, and labels
   in dark ink with a white halo so an address stays legible over any node
   colour or a crossing edge. Node size still encodes traffic weight and
   colour still encodes role and risk, but nothing is left faint. */
const GRAPH_STYLE = [
  {
    selector: 'node',
    style: {
      'background-color': (n) => n.data('color'),
      'background-opacity': 1,
      'border-width': (n) => (n.data('risk') > 0 ? 3 : 1.5),
      'border-color': (n) => (n.data('risk') > 0 ? riskColor(n.data('risk')) : '#d3d7dd'),
      'width': (n) => 18 + n.data('weight') * 42,
      'height': (n) => 18 + n.data('weight') * 42,
      'label': 'data(label)',
      'color': '#16202e',
      'font-family': 'IBM Plex Mono, monospace',
      'font-size': '13px',
      'font-weight': 600,
      'text-valign': 'bottom',
      'text-margin-y': 7,
      // A solid white halo, not a translucent box, keeps the address
      // readable wherever it lands.
      'text-outline-color': '#ffffff',
      'text-outline-width': 3.5,
      'text-outline-opacity': 1,
      // Labels stay legible when zoomed out rather than vanishing, which
      // is what made addresses look faded.
      'min-zoomed-font-size': 5,
      'transition-property': 'border-color, background-color, opacity',
      'transition-duration': '140ms',
    },
  },
  {
    selector: 'node:parent',
    style: {
      // Cytoscape ignores the alpha channel of rgba() colours; transparency
      // has to come from the opacity properties or subnets paint solid.
      'background-color': '#7c3aed',
      'background-opacity': 0.05,
      'border-color': '#c4b5fd',
      'border-opacity': 1,
      'border-width': 1.5,
      'label': 'data(label)',
      'font-family': 'Chakra Petch, sans-serif',
      'font-size': '12px',
      'font-weight': 600,
      'color': '#5b21b6',
      'text-valign': 'top',
      'text-margin-y': -6,
      'text-outline-color': '#ffffff',
      'text-outline-width': 2,
      'padding': '24px',
      'shape': 'roundrectangle',
    },
  },
  {
    selector: 'edge',
    style: {
      'width': (e) => 0.8 + e.data('weight') * 4,
      'line-color': (e) => (e.data('suspect') ? '#c62828' : '#8fb4dd'),
      'opacity': (e) => (e.data('suspect') ? .85 : .5),
      'curve-style': 'haystack',
      'haystack-radius': .2,
    },
  },
  {
    selector: 'node.selected',
    style: { 'border-color': '#0d3f80', 'border-width': 4 },
  },
  { selector: '.dimmed', style: { 'opacity': .12 } },
  {
    selector: 'edge.highlight',
    style: { 'line-color': '#1560bd', 'opacity': .95, 'width': 3, 'z-index': 20 },
  },
];

/* Matte palette, no neon. Role for internal hosts, grey for external,
   and risk overrides everything so a dangerous node is never subtle. */
// One hue per kind of host, so the map is readable before anything is
// clicked. Risk overrides role, because a compromised server matters more
// as a risk than as a server.
const NODE_COLOURS = {
  critical: '#d6336c',
  high:     '#e8590c',
  medium:   '#c48a00',
  server:   '#3b5bdb',
  gateway:  '#7c3aed',
  hub:      '#c2255c',
  client:   '#0ca678',
  external: '#a3adbe',
  dns:      '#5c7cfa',
  cloud:    '#38d9a9',
};

function nodeColor(node) {
  if (node.risk >= 60) return NODE_COLOURS.critical;
  if (node.risk >= 35) return NODE_COLOURS.high;
  if (node.risk > 0)   return NODE_COLOURS.medium;

  if (!node.internal) {
    // External hosts split by what they are, which is usually the first
    // question asked about them.
    const services = (node.services || []).join(' ').toLowerCase();
    if (services.includes('dns')) return NODE_COLOURS.dns;
    if ((node.tags || []).some((t) => /cloud|cdn|aws|azure|google/i.test(t))) {
      return NODE_COLOURS.cloud;
    }
    return NODE_COLOURS.external;
  }

  if (node.role === 'gateway') return NODE_COLOURS.gateway;
  if (node.role === 'hub')     return NODE_COLOURS.hub;
  if (node.role === 'server')  return NODE_COLOURS.server;
  return NODE_COLOURS.client;
}


function buildGraph() {
  const graph = state.report.graph;
  if (!graph.nodes.length) {
    $('graph').innerHTML = '<div class="empty"><strong>No hosts to map</strong>This capture contained no IP endpoints.</div>';
    return;
  }

  // Group hosts into subnet compounds so structure is visible at a glance
  // instead of one undifferentiated hairball.
  const subnets = [...new Set(graph.nodes.map((n) => n.subnet))];
  const useGroups = subnets.length > 1 && subnets.length <= 24;

  const elements = [];

  if (useGroups) {
    subnets.forEach((subnet) => {
      elements.push({ data: { id: `grp:${subnet}`, label: subnet } });
    });
  }

  graph.nodes.forEach((node) => {
    elements.push({
      data: {
        ...node,
        parent: useGroups ? `grp:${node.subnet}` : undefined,
        color: nodeColor(node),
      },
    });
  });

  graph.edges.forEach((edge) => elements.push({ data: edge }));

  if (state.cy) state.cy.destroy();

  state.cy = cytoscape({
    container: $('graph'),
    elements,
    style: GRAPH_STYLE,
    minZoom: 0.12,
    maxZoom: 4,
    wheelSensitivity: 0.22,
    layout: layoutOptions('cose'),
    // Render at the display's real pixel density. Left at the default the
    // canvas rasterises at 1x on a HiDPI screen and every label looks soft.
    pixelRatio: window.devicePixelRatio || 1,
    textureOnViewport: false,
    motionBlur: false,
  });

  state.cy.on('tap', 'node', (evt) => {
    const node = evt.target;
    if (node.isParent()) return;
    selectHost(node);
  });

  state.cy.on('tap', (evt) => {
    if (evt.target === state.cy) clearSelection();
  });

  $('mapFit').onclick = () => state.cy.fit(undefined, 45);
  $('layoutPick').onchange = (e) => {
    state.cy.layout(layoutOptions(e.target.value)).run();
  };

  const downloadPng = $('mapPng');
  if (downloadPng) {
    downloadPng.onclick = () => {
      // Full resolution on the page background, so the exported image
      // matches what was on screen rather than inverting to white.
      const png = state.cy.png({ full: true, scale: 3, bg: '#ffffff' });
      triggerDownload(png, `wirecub-network-${state.jobId || 'map'}.png`);
    };
  }

  const downloadSvg = $('mapSvg');
  if (downloadSvg) {
    downloadSvg.onclick = () => {
      // cytoscape-svg is not vendored, so the SVG is assembled directly
      // from node and edge positions. Vector output stays crisp at any
      // size and can be edited in a diagram tool.
      const svg = graphToSvg(state.cy);
      const blob = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
      triggerDownload(blob, `wirecub-network-${state.jobId || 'map'}.svg`);
    };
  }

  ['filterInternal', 'filterExternal', 'filterRiskOnly'].forEach((id) => {
    $(id).onchange = applyFilters;
  });

  $('mapSearch').oninput = (e) => {
    const term = e.target.value.trim().toLowerCase();
    if (!term) { state.cy.nodes().removeClass('dimmed'); return; }
    state.cy.nodes().forEach((node) => {
      if (node.isParent()) return;
      const match = (node.data('ip') || '').toLowerCase().includes(term)
        || (node.data('label') || '').toLowerCase().includes(term)
        || (node.data('hostnames') || []).join(' ').toLowerCase().includes(term);
      node.toggleClass('dimmed', !match);
    });
  };
}

function layoutOptions(name) {
  if (name === 'concentric') {
    return {
      name: 'concentric',
      concentric: (n) => n.data('risk') || 0,
      levelWidth: () => 20,
      minNodeSpacing: 26,
      animate: true,
      animationDuration: 550,
      padding: 45,
    };
  }
  if (name === 'grid') {
    return { name: 'grid', avoidOverlap: true, padding: 45, animate: true, animationDuration: 450 };
  }
  return {
    name: 'cose',
    animate: true,
    animationDuration: 900,
    nodeRepulsion: 9000,
    idealEdgeLength: 90,
    nodeOverlap: 14,
    gravity: 0.28,
    numIter: 1400,
    padding: 45,
    randomize: true,
  };
}

function applyFilters() {
  const showInternal = $('filterInternal').checked;
  const showExternal = $('filterExternal').checked;
  const riskOnly = $('filterRiskOnly').checked;

  state.cy.nodes().forEach((node) => {
    if (node.isParent()) return;
    const internal = node.data('internal');
    let visible = internal ? showInternal : showExternal;
    if (riskOnly && node.data('risk') <= 0) visible = false;
    node.style('display', visible ? 'element' : 'none');
  });
}

function selectHost(node) {
  state.cy.elements().removeClass('selected highlight');
  node.addClass('selected');
  node.connectedEdges().addClass('highlight');

  const d = node.data();
  const panel = $('hostPanel');

  const rows = [
    ['Scope', d.internal ? 'Internal' : 'External'],
    ['IP version', `v${d.ip_version}`],
    ['Role', d.role],
    ['Subnet', d.subnet],
    ['Hardware', (d.macs || []).join(', ') || '—'],
    ['Vendor', d.vendor || '—'],
    ['Names', (d.hostnames || []).join(', ') || '—'],
    ['Sent', bytes(d.bytes_sent)],
    ['Received', bytes(d.bytes_received)],
    ['Packets', `${num(d.packets_sent)} out / ${num(d.packets_received)} in`],
    ['Peers', num(d.peers)],
    ['Serving', (d.services || []).join(', ') || '—'],
    ['Ports contacted', num(d.ports_contacted)],
    ['TTL seen', (d.ttl_values || []).join(', ') || '—'],
    ['JA3', (d.ja3 || []).join(', ') || '—'],
    ['First seen', clockTime(d.first_seen)],
    ['Last seen', clockTime(d.last_seen)],
  ].filter(([, v]) => v && v !== '—').map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');

  const related = state.report.findings.filter((f) => (f.hosts || []).includes(d.ip));
  const findingList = related.length
    ? `<div style="margin-top:14px">
         <h4 style="font-size:10.5px;text-transform:uppercase;letter-spacing:.12em;color:#0891b2;margin-bottom:7px">Findings</h4>
         ${related.map((f) => `<div style="margin-bottom:6px;font-size:12.5px">
             <span class="sev-badge" data-sev="${esc(f.severity)}">${esc(f.severity)}</span>
             ${esc(f.title)}</div>`).join('')}
       </div>`
    : '';

  panel.innerHTML = `
    <button class="close" aria-label="Close">×</button>
    <h4>${esc(d.ip)}</h4>
    ${d.risk > 0 ? `<div>${riskCell(d.risk)} <span class="note" style="margin:0">risk score</span></div>` : ''}
    <dl class="kv">${rows}</dl>
    ${findingList}`;

  panel.hidden = false;
  panel.querySelector('.close').onclick = clearSelection;
}

function clearSelection() {
  state.cy?.elements().removeClass('selected highlight');
  $('hostPanel').hidden = true;
}

/* ---------------------------------------------------------------- tabs */

function switchTab(name) {
  if (name === 'reputation' && !state.reputationLoaded) {
    state.reputationLoaded = true;
    renderReputation();
  }
  document.querySelectorAll('.tab').forEach((tab) =>
    tab.classList.toggle('active', tab.dataset.tab === name));

  const panels = {
    overview: 'panelOverview', findings: 'panelFindings', map: 'panelMap',
    hosts: 'panelHosts', flows: 'panelFlows',
    attacks: 'panelAttacks', reputation: 'panelReputation',
    timeline: 'panelTimeline', voip: 'panelVoip',
    credentials: 'panelCredentials', files: 'panelFiles',
    streams: 'panelStreams', dns: 'panelDns', http: 'panelHttp',
    tls: 'panelTls', windows: 'panelWindows', ot: 'panelOt',
    wireless: 'panelWireless', iocs: 'panelIocs', export: 'panelExport',
  };

  Object.entries(panels).forEach(([key, id]) => { $(id).hidden = key !== name; });

  if (name === 'map') {
    if (!state.cy) {
      // Build after the panel is visible so Cytoscape measures a real size.
      requestAnimationFrame(buildGraph);
    } else {
      state.cy.resize();
      state.cy.fit(undefined, 45);
    }
  }
}

$('tabs').addEventListener('click', (e) => {
  const tab = e.target.closest('.tab');
  if (tab) switchTab(tab.dataset.tab);
});

/* -------------------------------------------------------------- history */

async function showHistory() {
  const list = $('historyList');
  list.innerHTML = '<div class="card"><p class="note">Loading…</p></div>';
  showView('history');

  let rows;
  try {
    const res = await api('/api/history');
    rows = await res.json();
  } catch (err) {
    list.innerHTML = `<div class="card"><p class="note">${esc(err.message)}</p></div>`;
    return;
  }

  state.comparePicks = [];
  $('compareBar').hidden = true;
  $('compareResult').innerHTML = '';

  if (!rows.length) {
    list.innerHTML = `<div class="empty"><strong>No analyses yet</strong>
      Captures you analyse will be listed here.</div>`;
    return;
  }

  list.innerHTML = rows.map((row) => `
    <div class="history-row" data-id="${esc(row.id)}">
      <label class="compare-pick-wrap" title="Select for comparison">
        <input type="checkbox" class="compare-pick" data-id="${esc(row.id)}"
               data-name="${esc(row.filename)}" data-created="${Number(row.created) || 0}">
      </label>
      <span class="history-score" style="color:${riskColor(row.risk_score || 0)}">${num(row.risk_score)}</span>
      <div>
        <div class="history-name">${esc(row.filename)}</div>
        <div class="history-sub">${clockTime(row.created)} · ${num(row.packets)} packets ·
          ${num(row.hosts)} hosts · ${num(row.findings)} findings</div>
      </div>
      <span class="tag" style="color:${BAND_COLOR[row.risk_band] || 'inherit'}">${esc(row.risk_band || '')}</span>
      <button class="ghost-btn small history-delete" data-id="${esc(row.id)}"
              title="Delete this analysis and its files">Delete</button>
    </div>`).join('');

  list.querySelectorAll('.history-row').forEach((row) => {
    row.onclick = (e) => {
      if (e.target.closest('.compare-pick-wrap') || e.target.closest('.history-delete')) return;
      loadReport(row.dataset.id);
    };
  });
  list.querySelectorAll('.compare-pick').forEach((box) => {
    box.onchange = updateComparePicks;
  });
  list.querySelectorAll('.history-delete').forEach((button) => {
    button.onclick = async () => {
      const row = button.closest('.history-row');
      const name = row.querySelector('.history-name').textContent;
      if (!confirm(`Delete the analysis of ${name}? The report and any carved files are removed.`)) return;
      button.disabled = true;
      try {
        await api(`/api/history/${button.dataset.id}`, { method: 'DELETE' });
        row.remove();
        if (state.jobId === button.dataset.id) { state.jobId = null; resetState(); }
        updateComparePicks();
        if (!list.querySelector('.history-row')) showHistory();
      } catch (err) {
        button.disabled = false;
        alert(err.message);
      }
    };
  });
}

/* ------------------------------------------------------------- compare */

state.comparePicks = [];

function updateComparePicks() {
  const picked = [...document.querySelectorAll('.compare-pick:checked')]
    .map((box) => ({ id: box.dataset.id, name: box.dataset.name,
                     created: Number(box.dataset.created) }));

  // Only two captures can be compared at a time, so the oldest selection
  // drops off rather than blocking the click.
  if (picked.length > 2) {
    const oldest = picked[0];
    const box = document.querySelector(`.compare-pick[data-id="${oldest.id}"]`);
    if (box) box.checked = false;
    return updateComparePicks();
  }

  state.comparePicks = picked;
  const bar = $('compareBar');

  if (picked.length === 2) {
    // The earlier capture is the baseline; the later one is what changed.
    const sorted = [...picked].sort((a, b) => a.created - b.created);
    state.compareOrder = sorted;
    $('compareLabel').innerHTML =
      `Baseline <b>${esc(sorted[0].name)}</b> → current <b>${esc(sorted[1].name)}</b>`;
    bar.hidden = false;
  } else {
    bar.hidden = true;
    $('compareResult').innerHTML = '';
  }
}

async function runCompare() {
  const [baseline, current] = state.compareOrder || [];
  if (!baseline || !current) return;

  const result = $('compareResult');
  result.innerHTML = '<div class="card"><p class="note">Comparing…</p></div>';

  try {
    const res = await api(
      `/api/compare?baseline=${encodeURIComponent(baseline.id)}&current=${encodeURIComponent(current.id)}`);
    const data = await res.json();

    const deltaColor = data.risk_delta > 0 ? '#d6336c'
      : data.risk_delta < 0 ? '#0ca678' : '#5b7c96';

    const listBlock = (title, items, renderItem) => items.length ? `
      <div class="card">
        <h3>${esc(title)} <span class="tag">${items.length}</span></h3>
        ${items.slice(0, 40).map(renderItem).join('')}
        ${items.length > 40 ? `<p class="note">…and ${items.length - 40} more.</p>` : ''}
      </div>` : '';

    result.innerHTML = `
      <div class="card">
        <h3>Comparison</h3>
        <p class="verdict-text" style="font-size:15px">${esc(data.summary)}</p>
        <div class="stat-grid" style="margin-top:14px">
          <div class="stat"><b>${data.baseline.risk_score}</b><span>Baseline risk</span></div>
          <div class="stat"><b>${data.current.risk_score}</b><span>Current risk</span></div>
          <div class="stat"><b style="color:${deltaColor}">
            ${data.risk_delta > 0 ? '+' : ''}${data.risk_delta}</b><span>Change</span></div>
          <div class="stat"><b>${data.new_findings.length}</b><span>New findings</span></div>
        </div>
      </div>
      ${listBlock('New findings', data.new_findings, (f) =>
        `<div class="compare-line">
           <span class="sev-badge" data-sev="${esc(f.severity)}">${esc(f.severity)}</span>
           ${esc(f.title)}
           <span class="mono muted-inline">${esc((f.hosts || []).join(', '))}</span>
         </div>`)}
      ${listBlock('Findings no longer present', data.resolved_findings, (f) =>
        `<div class="compare-line"><span class="tag">${esc(f.severity)}</span>
           ${esc(f.title)}</div>`)}
      ${listBlock('Hosts that appeared', data.new_hosts, (h) =>
        `<span class="tag mono">${esc(h)}</span>`)}
      ${listBlock('New external destinations', data.new_external_destinations, (h) =>
        `<span class="tag mono">${esc(h)}</span>`)}
      ${listBlock('Domains not seen before', data.new_domains, (d) =>
        `<span class="tag mono">${esc(d)}</span>`)}`;
  } catch (err) {
    result.innerHTML =
      `<div class="card"><p class="note">Comparison failed: ${esc(err.message)}</p></div>`;
  }
}

$('compareRun')?.addEventListener('click', runCompare);
$('compareClear')?.addEventListener('click', () => {
  document.querySelectorAll('.compare-pick').forEach((b) => { b.checked = false; });
  updateComparePicks();
});

/* ----------------------------------------------------------------- boot */

setupAuth();
setupUpload();
showView('upload');
loadConfig();

/* ------------------------------------------------------------- graph export */

function triggerDownload(dataUrl, filename) {
  const link = document.createElement('a');
  link.href = dataUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
}

/* Build an SVG from the live graph positions. Matches the on-screen theme:
   white background, matte node fills, dark labels with a white halo. */
function graphToSvg(cy) {
  const extent = cy.elements().boundingBox();
  const pad = 40;
  const w = Math.max(200, extent.w + pad * 2);
  const h = Math.max(200, extent.h + pad * 2);
  const ox = extent.x1 - pad;
  const oy = extent.y1 - pad;

  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round(w)}" `
    + `height="${Math.round(h)}" viewBox="0 0 ${Math.round(w)} ${Math.round(h)}" `
    + `font-family="IBM Plex Mono, monospace">`,
    `<rect width="100%" height="100%" fill="#ffffff"/>`,
  ];

  // Subnet compounds first, behind everything.
  cy.nodes(':parent').forEach((node) => {
    const b = node.boundingBox();
    parts.push(
      `<rect x="${(b.x1 - ox).toFixed(1)}" y="${(b.y1 - oy).toFixed(1)}" `
      + `width="${b.w.toFixed(1)}" height="${b.h.toFixed(1)}" rx="10" `
      + `fill="#eef3f9" fill-opacity="0.6" stroke="#c3d4e6" stroke-width="1.5"/>`,
      `<text x="${(b.x1 - ox + 8).toFixed(1)}" y="${(b.y1 - oy + 16).toFixed(1)}" `
      + `fill="#46596c" font-size="12" font-weight="600">${escapeXml(node.data('label') || '')}</text>`);
  });

  cy.edges().forEach((edge) => {
    const s = edge.source().position();
    const t = edge.target().position();
    const suspect = edge.data('suspect');
    parts.push(
      `<line x1="${(s.x - ox).toFixed(1)}" y1="${(s.y - oy).toFixed(1)}" `
      + `x2="${(t.x - ox).toFixed(1)}" y2="${(t.y - oy).toFixed(1)}" `
      + `stroke="${suspect ? '#c62828' : '#8fb4dd'}" `
      + `stroke-width="${(0.8 + (edge.data('weight') || 0) * 4).toFixed(1)}" `
      + `stroke-opacity="${suspect ? 0.85 : 0.5}"/>`);
  });

  cy.nodes().forEach((node) => {
    if (node.isParent()) return;
    const p = node.position();
    const r = (18 + (node.data('weight') || 0) * 42) / 2;
    const risk = node.data('risk') || 0;
    parts.push(
      `<circle cx="${(p.x - ox).toFixed(1)}" cy="${(p.y - oy).toFixed(1)}" `
      + `r="${r.toFixed(1)}" fill="${node.data('color')}" `
      + `stroke="${risk > 0 ? riskColor(risk) : '#5b7a9c'}" `
      + `stroke-width="${risk > 0 ? 3 : 1.5}"/>`);
    // Label with a white halo drawn as a stroked copy underneath.
    const label = escapeXml(node.data('label') || '');
    const lx = (p.x - ox).toFixed(1);
    const ly = (p.y - oy + r + 14).toFixed(1);
    parts.push(
      `<text x="${lx}" y="${ly}" text-anchor="middle" font-size="11" `
      + `font-weight="600" stroke="#ffffff" stroke-width="3" `
      + `paint-order="stroke">${label}</text>`,
      `<text x="${lx}" y="${ly}" text-anchor="middle" font-size="11" `
      + `font-weight="600" fill="#12222f">${label}</text>`);
  });

  parts.push('</svg>');
  return parts.join('\n');
}

function escapeXml(value) {
  return String(value).replace(/[<>&'"]/g, (c) => (
    { '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]
  ));
}


/* Show which build is answering. A container that was not rebuilt serves
   an older interface and is otherwise indistinguishable from a current
   one, so the running version is put on screen rather than left to be
   inferred from what the page looks like. */
(async () => {
  try {
    const res = await fetch('/api/version', { cache: 'no-store' });
    const data = await res.json();
    const el = document.getElementById('buildStamp');
    if (el) {
      el.textContent = `v${data.version} · ${data.asset_hash}`;
      el.title = data.hosted ? 'Hosted build'
        : `Interface build ${data.asset_hash}. If this does not change after `
          + 'an upgrade, the container was not rebuilt.';
    }
  } catch (err) {
    /* Version display is a convenience; never let it break the page. */
  }
})();
