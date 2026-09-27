/* WireCub site: the hero sequence, the screen switcher, and the real limits
   of this deployment read from the server rather than written in by hand. */

(() => {
  // Connection times (seconds from the first packet) of the 45 callbacks in
  // the sample capture: the pattern the hero finding is about.
  const BEATS = [0, 60.62, 119.8, 180.73, 240.56, 299.96, 360.93, 419.98,
    481.09, 540.05, 601.04, 660.83, 721.14, 780.9, 840.94, 899.5, 960.16,
    1019.89, 1080.22, 1139.42, 1200.64, 1260.11, 1321.38, 1380.75, 1439.61,
    1499.59, 1561.32, 1620.1, 1680.38, 1739.86, 1800.88, 1861.25, 1920.52,
    1979.8, 2040.98, 2100.88, 2159.75, 2220.72, 2280.81, 2341.12, 2401.5,
    2461.39, 2520.54, 2581.02, 2639.83];

  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const svgNS = 'http://www.w3.org/2000/svg';

  /* ------------------------------------------------------ timing strip */
  const svg = document.getElementById('beat');
  const ticks = [];
  if (svg) {
    const span = 2640;
    const base = document.createElementNS(svgNS, 'line');
    Object.entries({ x1: 0, x2: 600, y1: 38, y2: 38, stroke: '#16295a', 'stroke-width': 2 })
      .forEach(([k, v]) => base.setAttribute(k, v));
    svg.appendChild(base);
    BEATS.forEach((t) => {
      const x = 3 + (t / span) * 594;
      const line = document.createElementNS(svgNS, 'line');
      Object.entries({ x1: x, x2: x, y1: 38, y2: 8, stroke: '#3ec3f5',
        'stroke-width': 2, 'stroke-linecap': 'round', 'vector-effect': 'non-scaling-stroke' })
        .forEach(([k, v]) => line.setAttribute(k, v));
      svg.appendChild(line);
      ticks.push(line);
    });
  }

  /* ------------------------------------------------------- hero sequence */
  const rows = [...document.querySelectorAll('#pktRows tr')];
  const answer = document.getElementById('demoAnswer');
  const show = (el) => el && el.classList.add('in');

  if (reduce) {
    rows.forEach(show); ticks.forEach(show); show(answer);
  } else {
    rows.forEach((row, i) => setTimeout(() => show(row), 250 + i * 90));
    const after = 250 + rows.length * 90;
    ticks.forEach((tick, i) => setTimeout(() => show(tick), after + i * 18));
    setTimeout(() => show(answer), after + ticks.length * 18 + 150);
  }

  /* ------------------------------------------------------ screen switcher */
  const tabs = [...document.querySelectorAll('.view-tabs [role="tab"]')];
  const shot = document.getElementById('viewShot');
  const text = document.getElementById('viewText');

  const select = (tab, focus) => {
    tabs.forEach((t) => {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
    });
    shot.src = `/assets/shots/${tab.dataset.shot}.webp`;
    shot.alt = `WireCub ${tab.textContent.trim().toLowerCase()} screen for the sample capture`;
    text.textContent = tab.dataset.text;
    if (focus) tab.focus();
  };

  tabs.forEach((tab, i) => {
    tab.tabIndex = i === 0 ? 0 : -1;
    tab.addEventListener('click', () => select(tab));
    tab.addEventListener('keydown', (e) => {
      const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (!step) return;
      e.preventDefault();
      select(tabs[(i + step + tabs.length) % tabs.length], true);
    });
  });

  // Warm the other screens once the page is idle, so switching is instant.
  const warm = () => tabs.forEach((t) => { new Image().src = `/assets/shots/${t.dataset.shot}.webp`; });
  if ('requestIdleCallback' in window) requestIdleCallback(warm); else setTimeout(warm, 1500);

  /* ------------------------------------------- this deployment's limits */
  fetch('/api/config', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : null))
    .then((c) => {
      if (!c) return;
      const set = (id, value) => { const el = document.getElementById(id); if (el && value) el.textContent = value; };
      set('factSize', c.max_upload_label);
      if (c.time_budget_seconds) {
        const minutes = Math.floor(c.time_budget_seconds / 60 + 0.5);
        set('factTime', `${minutes} minute${minutes === 1 ? '' : 's'}`);
      }
      if (c.report_ttl_minutes) {
        const m = c.report_ttl_minutes;
        const ttl = m === 60 ? 'an hour' : m % 60 === 0 ? `${m / 60} hours` : `${m} minutes`;
        set('factKeep', ttl);
        document.querySelectorAll('.ttl').forEach((el) => { el.textContent = ttl; });
      }
      const key = document.getElementById('factKey');
      if (key) key.hidden = !c.auth_required;
      if (!c.hosted) {
        // Served by a local install: describe this machine, not Vercel.
        set('runHostedTitle', 'This instance');
        document.querySelectorAll('.hosted-only').forEach((el) => el.remove());
        const list = document.querySelector('#runHosted .facts');
        if (list) {
          const li = document.createElement('li');
          li.textContent = 'Running locally: captures and reports stay on this machine';
          list.appendChild(li);
        }
      }
    })
    .catch(() => {});

})();
