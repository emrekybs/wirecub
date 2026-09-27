const fs = require('fs');
const { JSDOM } = require('jsdom');

const STATIC = require('path').join(__dirname, '..', 'public', 'app');
const html = fs.readFileSync(`${STATIC}/index.html`, 'utf8');
const appJs = fs.readFileSync(`${STATIC}/app.js`, 'utf8');

const reports = fs.readdirSync((process.env.WIRECUB_FETEST || '/tmp/fetest'))
  .filter(f => f.startsWith('report_'))
  .map(f => JSON.parse(fs.readFileSync(require('path').join(process.env.WIRECUB_FETEST || '/tmp/fetest', f), 'utf8')));
const history = JSON.parse(fs.readFileSync(require('path').join(process.env.WIRECUB_FETEST || '/tmp/fetest', 'history.json'), 'utf8'));

let failures = [], checks = 0;
const check = (n, c, d) => { checks++; if (!c) failures.push(`${n}${d ? ' — ' + d : ''}`); };

// Runs inside the same scope as app.js so it can reach state and the
// render functions, exactly as the real page does.
const probe = `
(() => {
  const out = { tabs: [], errors: [] };
  try {
    state.report = REPORTREF; state.jobId = JOBID;
    renderAll(); showView('results');
    out.rendered = true;
  } catch (e) { out.rendered = false; out.errors.push('renderAll: ' + e.message); return out; }

  const panelFor = t => document.getElementById('panel' + t.charAt(0).toUpperCase() + t.slice(1));
  document.querySelectorAll('.tab').forEach(tabEl => {
    const t = tabEl.dataset.tab;
    const entry = { tab: t, hidden: tabEl.hidden };
    if (!tabEl.hidden) {
      try { switchTab(t); entry.ok = true; }
      catch (e) { entry.ok = false; entry.error = e.message; }
      const p = panelFor(t);
      entry.chars = p ? p.innerHTML.trim().length : -1;
    }
    out.tabs.push(entry);
  });

  out.overview = document.getElementById('panelOverview').innerHTML;
  out.findingCount = document.querySelectorAll('#panelFindings .finding').length;
  out.filesHtml = document.getElementById('panelFiles').innerHTML;
  out.exportLinks = [...document.querySelectorAll('#panelExport a')].map(a => a.getAttribute('href'));
  out.streamsHtml = document.getElementById('panelStreams').innerHTML;

  const head = document.querySelector('#panelFindings .finding-head');
  if (head) {
    head.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    out.expanded = document.querySelector('#panelFindings .finding').classList.contains('open');
  }
  const btn = document.querySelector('#panelStreams [data-stream]');
  if (btn) {
    try { btn.click(); out.streamViewer = document.getElementById('streamViewer').innerHTML.length; }
    catch (e) { out.errors.push('stream viewer: ' + e.message); }
  }
  out.escaped = esc('<img src=x onerror=alert(1)>');
  return out;
})()`;

(async () => {
for (const report of reports) {
  const label = report.meta.filename;
  const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true, url: 'http://localhost/' });
  const { window } = dom;
  const consoleErrors = [];
  window.console.error = (...a) => consoleErrors.push(a.join(' '));

  window.cytoscape = () => ({ on(){}, nodes:()=>({forEach(){}, removeClass(){}}),
    elements:()=>({removeClass(){}}), destroy(){}, resize(){}, fit(){}, layout:()=>({run(){}}) });
  window.fetch = async (url) => ({ ok:true, json: async () =>
    url.includes('/api/config') ? { max_upload_bytes: 10737418240, max_upload_label: '10 GB' }
    : url.includes('/api/history') ? history
    : url.includes('/api/reports/') ? report : {} });
  window.WebSocket = function(){ this.close = () => {}; };
  window.requestAnimationFrame = fn => fn();
  window.__REPORT__ = report;

  let out;
  try {
    out = window.eval(appJs + '\n' + probe
      .replace('REPORTREF', 'window.__REPORT__')
      .replace('JOBID', JSON.stringify(report.meta.job_id)));
  } catch (e) {
    check(`${label}: page script runs`, false, e.message);
    continue;
  }
  check(`${label}: page script runs`, true);
  check(`${label}: renderAll succeeds`, out.rendered, (out.errors || []).join('; '));
  if (!out.rendered) continue;

  for (const t of out.tabs) {
    if (t.hidden) continue;
    check(`${label}: tab "${t.tab}" switches`, t.ok, t.error);
    check(`${label}: tab "${t.tab}" has content`, t.tab === 'map' || t.chars > 40, `${t.chars} chars`);
  }

  check(`${label}: risk score shown`, out.overview.includes(String(report.stats.risk_score)));
  check(`${label}: verdict shown`, out.overview.includes(report.stats.verdict.slice(0, 30)));
  check(`${label}: findings all rendered`, out.findingCount === report.findings.length,
        `${out.findingCount} vs ${report.findings.length}`);
  check(`${label}: finding expands on click`, out.expanded !== false);

  if (report.files?.length) {
    check(`${label}: file hash shown`, out.filesHtml.includes(report.files[0].sha256));
    if (report.files[0].stored)
      check(`${label}: download link present`, out.filesHtml.includes(`/files/${report.files[0].sha256}`));
  }
  if (report.streams?.length) {
    check(`${label}: stream viewer opens`, out.streamViewer > 100, `${out.streamViewer} chars`);
  }

  check(`${label}: export links built`, out.exportLinks.length >= 8, `${out.exportLinks.length}`);
  check(`${label}: export links target this job`,
        out.exportLinks.every(h => h.includes(report.meta.job_id)));
  check(`${label}: markup is escaped`, !out.escaped.includes('<img'), out.escaped);
  check(`${label}: no console errors`, consoleErrors.length === 0, consoleErrors.join('; '));

  const visible = out.tabs.filter(t => !t.hidden).map(t => t.tab);
  console.log(`  ${label.padEnd(20)} tabs shown: ${visible.join(', ')}`);
  window.close();
}

console.log(`\n${checks} checks run`);
if (failures.length) { console.log(`${failures.length} FAILURES:`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
console.log('ALL PASSED');
})();
