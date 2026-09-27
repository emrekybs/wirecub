/*
 * Measure contrast on the rendered page, not on the stylesheet.
 *
 * jsdom does not resolve custom properties, so getComputedStyle returns
 * the literal "var(--ink)" and every check passes while the page is
 * unreadable. Substituting the variables into the stylesheet before
 * injecting it makes the computed values real, which is the only way to
 * see what a browser would actually paint — including inherited
 * backgrounds, which no stylesheet-level check can follow.
 */
const fs = require('fs');
const { JSDOM } = require('jsdom');

const S = require('path').join(__dirname, '..', 'public', 'app');
const reportFile = fs.readdirSync((process.env.WIRECUB_FETEST || '/tmp/fetest'))
  .filter((f) => f.startsWith('report_'))
  .map((f) => require('path').join(process.env.WIRECUB_FETEST || '/tmp/fetest', f))[0];
const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));

let css = fs.readFileSync(`${S}/styles.css`, 'utf8');

// Expand the custom properties, repeatedly, so chained references resolve.
const vars = {};
for (const m of css.matchAll(/--([\w-]+):\s*([^;]+);/g)) vars[m[1]] = m[2].trim();
for (let pass = 0; pass < 6; pass++) {
  css = css.replace(/var\(--([\w-]+)\)/g, (whole, name) =>
    vars[name] !== undefined && !/var\(/.test(vars[name]) ? vars[name] : whole);
  for (const k of Object.keys(vars)) {
    vars[k] = vars[k].replace(/var\(--([\w-]+)\)/g, (w, n) => vars[n] ?? w);
  }
}

const dom = new JSDOM(fs.readFileSync(`${S}/index.html`, 'utf8'),
  { runScripts: 'outside-only', pretendToBeVisual: true, url: 'http://localhost/' });
const { window } = dom;
const style = window.document.createElement('style');
style.textContent = css;
window.document.head.appendChild(style);

window.cytoscape = () => ({ on(){}, nodes:()=>({forEach(){},removeClass(){}}),
  elements:()=>({removeClass(){}}), destroy(){}, resize(){}, fit(){},
  layout:()=>({run(){}}), png:()=>'' });
window.fetch = async () => ({ ok: true, json: async () => report });
window.WebSocket = function () { this.close = () => {}; };
window.requestAnimationFrame = (fn) => fn();
window.__REPORT__ = report;

const app = fs.readFileSync(`${S}/app.js`, 'utf8');

function rgb(value) {
  if (!value) return null;
  let m = value.match(/^#([0-9a-f]{3,8})$/i);
  if (m) {
    let d = m[1];
    if (d.length === 3) d = [...d].map((c) => c + c).join('');
    return [0, 2, 4].map((i) => parseInt(d.slice(i, i + 2), 16));
  }
  m = value.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?/);
  if (!m) return null;
  if (m[4] !== undefined && parseFloat(m[4]) === 0) return null;  // transparent
  return [m[1], m[2], m[3]].map((n) => Math.round(parseFloat(n)));
}

const lum = (c) => {
  const [r, g, b] = c.map((v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

const tabs = ['findings', 'attacks', 'timeline', 'overview', 'hosts',
              'reputation', 'files', 'flows', 'dns', 'http', 'tls',
              'iocs', 'export', 'credentials', 'voip'];

let checked = 0;
const failures = [];

window.eval(app + `
  state.report = window.__REPORT__; state.jobId = 'x';
  renderAll(); showView('results');`);

for (const tab of tabs) {
  const tabEl = window.document.querySelector(`.tab[data-tab="${tab}"]`);
  if (!tabEl || tabEl.hidden) continue;
  window.eval(`switchTab(${JSON.stringify(tab)});`);

  const panel = window.document.getElementById(
    'panel' + tab.charAt(0).toUpperCase() + tab.slice(1));
  if (!panel) continue;

  for (const el of panel.querySelectorAll('*')) {
    const text = [...el.childNodes]
      .filter((n) => n.nodeType === 3 && n.textContent.trim().length > 1)
      .map((n) => n.textContent.trim()).join(' ');
    if (!text) continue;

    const cs = window.getComputedStyle(el);
    const fg = rgb(cs.color);
    if (!fg) continue;

    // Walk up for the first ancestor that actually paints a background.
    let bg = null;
    for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
      const candidate = rgb(window.getComputedStyle(node).backgroundColor);
      if (candidate) { bg = candidate; break; }
    }
    if (!bg) bg = rgb(vars['page']) || [255, 255, 255];

    checked++;
    const r = ratio(fg, bg);
    if (r < 3.0) {
      failures.push({ tab, text: text.slice(0, 46),
        tag: el.tagName.toLowerCase() + (el.className ? '.' + String(el.className).split(' ')[0] : ''),
        ratio: r.toFixed(2), fg: cs.color, bg: `rgb(${bg.join(',')})` });
    }
  }
}

console.log(`${checked} rendered text nodes measured across ${tabs.length} tabs`);
if (failures.length) {
  console.log(`\n${failures.length} unreadable:`);
  const seen = new Set();
  for (const f of failures) {
    const key = f.tag + f.ratio;
    if (seen.has(key)) continue;
    seen.add(key);
    console.log(`  ${f.ratio}:1  [${f.tab}] ${f.tag}`);
    console.log(`          "${f.text}"  ${f.fg} on ${f.bg}`);
  }
  process.exit(1);
}
console.log('every rendered text node clears 3.0:1');
