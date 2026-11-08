// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Dashboard KPI paneli: /api/dashboard/stats verisiyle kartlar + halka/trend grafikleri. Veri yoksa ilgili kutu gizlenir.
(function () {
  const panel = document.getElementById('kpiPanel');
  if (!panel) return;
  const PALETTE = ['#2563eb', '#16a34a', '#f59e0b', '#9333ea', '#dc2626', '#0891b2', '#64748b'];
  const charts = {};
  let range = '24h';
  let inFlight = false;

  function show(id, on) { const el = document.getElementById(id); if (el) el.hidden = !on; }

  function draw(key, canvasId, config) {
    if (charts[key]) charts[key].destroy();
    charts[key] = new Chart(document.getElementById(canvasId), config);
  }

  function doughnut(key, boxId, canvasId, d, colors) {
    show(boxId, !!d);
    if (!d) { if (charts[key]) { charts[key].destroy(); delete charts[key]; } return; }
    draw(key, canvasId, {
      type: 'doughnut',
      data: { labels: d.labels, datasets: [{ data: d.data, backgroundColor: colors || PALETTE, borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom' } } }
    });
  }

  function renderCards(cards) {
    const wrap = document.getElementById('kpiCards');
    wrap.textContent = '';
    cards.forEach(c => {
      const card = document.createElement('div'); card.className = 'stat-card ' + c.color;
      const info = document.createElement('div'); info.className = 'info';
      const lbl = document.createElement('div'); lbl.className = 'lbl'; lbl.textContent = c.label;
      const val = document.createElement('div'); val.className = 'val'; val.textContent = c.value;
      if (c.suffix) { const s = document.createElement('small'); s.textContent = c.suffix; val.appendChild(s); }
      info.append(lbl, val);
      const box = document.createElement('div'); box.className = 'icon-box';
      const i = document.createElement('i'); i.className = 'fa-solid ' + c.icon; box.appendChild(i);
      card.append(info, box); wrap.appendChild(card);
    });
  }

  function renderAlarms(list) {
    show('boxAlarms', !!list);
    const ul = document.getElementById('kpiAlarms'); ul.textContent = '';
    (list || []).forEach(a => {
      const li = document.createElement('li');
      const sev = document.createElement('span'); sev.className = 'kpi-sev ' + String(a.severity).replace(/[^A-Z]/g, ''); sev.textContent = a.severity;
      const msg = document.createElement('span'); msg.textContent = a.message + (a.device_ip ? ' (' + a.device_ip + ')' : '');
      li.append(sev, msg); ul.appendChild(li);
    });
  }

  function renderNasBars(rows) {
    show('boxNasBars', !!rows);
    const wrap = document.getElementById('kpiNasBars'); wrap.textContent = '';
    if (!rows) return;
    const max = Math.max.apply(null, rows.map(r => r.sessions)) || 1;
    rows.forEach(r => {
      const row = document.createElement('div'); row.className = 'kpi-bar-row';
      const name = document.createElement('span'); name.textContent = r.name;
      const track = document.createElement('div'); track.className = 'kpi-bar-track';
      const fill = document.createElement('div'); fill.className = 'kpi-bar-fill'; fill.style.width = (r.sessions * 100 / max) + '%';
      track.appendChild(fill);
      const n = document.createElement('strong'); n.textContent = r.sessions;
      row.append(name, track, n); wrap.appendChild(row);
    });
  }

  function render(d) {
    renderCards(d.cards);
    panel.hidden = !d.cards.length;
    doughnut('auth', 'boxAuth', 'chAuth', d.auth_result, ['#16a34a', '#dc2626']);
    doughnut('nas', 'boxNas', 'chNas', d.nas_dist);
    doughnut('ep', 'boxEp', 'chEp', d.endpoint_dist);
    show('boxTrend', !!d.trend);
    if (d.trend) {
      const short = d.range === '1h' || d.range === '24h';
      draw('trend', 'chTrend', {
        type: 'line',
        data: {
          labels: d.trend.labels.map(l => short ? l.slice(11) : l.slice(5, 10)),
          datasets: [
            { label: 'Kabul', data: d.trend.accept, borderColor: '#16a34a', backgroundColor: '#16a34a22', fill: true, tension: .3 },
            { label: 'Ret', data: d.trend.reject, borderColor: '#dc2626', backgroundColor: '#dc262622', fill: true, tension: .3 }
          ]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
      });
    }
    renderAlarms(d.alarms);
    renderNasBars(d.nas_sessions);
  }

  function load() {
    if (inFlight) return;
    inFlight = true;
    fetch('/api/dashboard/stats?range=' + encodeURIComponent(range), { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(render)
      .catch(() => { panel.hidden = true; })
      .finally(() => { inFlight = false; });
  }

  document.getElementById('kpiRanges').addEventListener('click', e => {
    const b = e.target.closest('.kpi-range'); if (!b) return;
    range = b.dataset.range;
    document.querySelectorAll('.kpi-range').forEach(x => x.classList.toggle('active', x === b));
    load();
  });
  document.getElementById('kpiRefresh').addEventListener('click', load);
  load();
})();
