// Verifies the panel-switching bug is actually fixed by applying the real
// stylesheet and reading computed styles — the check the earlier jsdom
// suite could not make, because it never applied CSS at all.
const fs = require('fs');
const { JSDOM } = require('jsdom');
const S = require('path').join(__dirname, '..', 'public', 'app');
const html = fs.readFileSync(`${S}/index.html`, 'utf8');
const css = fs.readFileSync(`${S}/styles.css`, 'utf8');
const appJs = fs.readFileSync(`${S}/app.js`, 'utf8');
const report = JSON.parse(fs.readFileSync(
  fs.readdirSync((process.env.WIRECUB_FETEST || '/tmp/fetest')).filter(f => f.startsWith('report_')).map(f => require('path').join(process.env.WIRECUB_FETEST || '/tmp/fetest', f))[0], 'utf8'));

const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true, url: 'http://localhost/' });
const { window } = dom;
const style = window.document.createElement('style');
style.textContent = css;
window.document.head.appendChild(style);

window.cytoscape = () => ({ on(){}, nodes:()=>({forEach(){},removeClass(){}}),
  elements:()=>({removeClass(){}}), destroy(){}, resize(){}, fit(){}, layout:()=>({run(){}}), png:()=>'' });
window.fetch = async () => ({ ok:true, json: async()=>report });
window.WebSocket = function(){ this.close=()=>{}; };
window.requestAnimationFrame = fn => fn();
window.__REPORT__ = report;
  window.__REPORT__ = report;

const probe = `
(() => {
  state.report = REPORTREF; state.jobId = 'x';
  renderAll(); showView('results');
  const results = [];
  document.querySelectorAll('.tab').forEach(t => {
    if (t.hidden) return;
    const name = t.dataset.tab;
    switchTab(name);
    const visible = [];
    document.querySelectorAll('.panel').forEach(p => {
      const cs = getComputedStyle(p);
      if (cs.display !== 'none') visible.push(p.id);
    });
    results.push({ tab: name, visible });
  });
  return results;
})()`;

const out = window.eval(appJs + '\n' + probe.replace('REPORTREF', 'window.__REPORT__'));
let bad = 0;
for (const r of out) {
  const expected = 'panel' + r.tab.charAt(0).toUpperCase() + r.tab.slice(1);
  const ok = r.visible.length === 1 && r.visible[0] === expected;
  if (!ok) { bad++; console.log(`  FAIL tab "${r.tab}" -> visible panels: ${r.visible.join(', ') || 'none'}`); }
  else console.log(`  ok   tab "${r.tab}" -> ${r.visible[0]}`);
}
console.log(bad ? `\n${bad} TABS BROKEN` : `\nAll ${out.length} tabs show exactly their own panel`);
process.exit(bad ? 1 : 0);
