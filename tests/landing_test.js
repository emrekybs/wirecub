const fs=require('fs'); const {JSDOM}=require('jsdom');
const S=require('path').join(__dirname, '..', 'public', 'app');
const report=JSON.parse(fs.readFileSync(fs.readdirSync((process.env.WIRECUB_FETEST || '/tmp/fetest')).filter(f=>f.startsWith('report_')).map(f=>require('path').join(process.env.WIRECUB_FETEST || '/tmp/fetest', f))[0],'utf8'));
const dom=new JSDOM(fs.readFileSync(`${S}/index.html`,'utf8'),{runScripts:'outside-only',pretendToBeVisual:true,url:'http://localhost/'});
const {window}=dom;
const st=window.document.createElement('style'); st.textContent=fs.readFileSync(`${S}/styles.css`,'utf8'); window.document.head.appendChild(st);
window.cytoscape=()=>({on(){},nodes:()=>({forEach(){},removeClass(){}}),elements:()=>({removeClass(){}}),destroy(){},resize(){},fit(){},layout:()=>({run(){}}),png:()=>''});
window.fetch=async()=>({ok:true,json:async()=>report}); window.WebSocket=function(){this.close=()=>{}};
window.requestAnimationFrame=fn=>fn(); window.__REPORT__=report;
const out=window.eval(fs.readFileSync(`${S}/app.js`,'utf8')+`
(()=>{ state.report=window.__REPORT__; state.jobId='x'; renderAll(); showView('results'); switchTab('findings');
  const vis=[...document.querySelectorAll('.panel')].filter(p=>getComputedStyle(p).display!=='none').map(p=>p.id);
  const active=document.querySelector('.tab.active');
  const findingsTop = document.getElementById('panelFindings').getBoundingClientRect;
  return { visible: vis, active: active?active.dataset.tab:null,
           findingCount: document.querySelectorAll('#panelFindings .finding').length,
           firstTab: document.querySelector('.tab').dataset.tab }; })()`);
console.log('first tab in bar :', out.firstTab);
console.log('active on load   :', out.active);
console.log('visible panel    :', out.visible.join(', '));
console.log('findings rendered:', out.findingCount);
console.log(out.firstTab==='findings' && out.visible.length===1 && out.visible[0]==='panelFindings'
  ? '\nPASS - findings lead and are the first thing shown' : '\nFAIL');
