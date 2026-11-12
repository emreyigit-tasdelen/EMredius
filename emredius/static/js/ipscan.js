// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// IP tarama sayfası: sayfa yenilemeden başlat / görüntüle / sil; çalışan taramayı yoklayıp canlı gösterir.
(function () {
  const STATUS = { running: 'Taranıyor', done: 'Tamamlandı', cancelled: 'Durduruldu', error: 'Hata' };
  const METHOD = { 'icmp-socket': 'ICMP soketi', ping: 'ping komutu (yedek yöntem)' };
  const form = document.getElementById('ipscanForm');
  const card = document.getElementById('ipscanResult');
  const content = document.querySelector('.content-body');
  if (!content || !(form || card)) return;

  // port modu: özel liste ve zaman aşımı alanlarını göster/gizle
  const mode = document.getElementById('isPortMode');
  if (mode) {
    mode.addEventListener('change', function () {
      document.getElementById('isCustomWrap').hidden = mode.value !== 'custom';
      document.getElementById('isTimeoutWrap').hidden = mode.value === 'off';
    });
  }

  // Port taraması hesaplayıcı: ağ boyutu x port sayısı, sınır aşılırsa kırmızı (Süper Yönetici için sınır yok)
  const calc = document.getElementById('isCalc');
  if (calc && mode) {
    const limit = parseInt(calc.dataset.limit, 10) || 0;
    const isSuper = calc.dataset.super === '1';
    const target = document.getElementById('isTarget');
    const portsInput = document.getElementById('isPorts');
    const fmt = n => n >= 1e15 ? '> 10¹⁵' : Math.round(n).toLocaleString('tr-TR');
    const hostCount = function (raw) {
      const t = (raw || '').trim(), m = t.match(/^([0-9a-fA-F:.]+)(?:\/(\d{1,3}))?$/);
      if (!m) return null;
      const v6 = m[1].indexOf(':') >= 0, bits = v6 ? 128 : 32;
      const p = m[2] === undefined ? bits : parseInt(m[2], 10);
      if (p > bits) return null;
      const n = Math.pow(2, bits - p);
      if (v6) return p < 127 ? n - 1 : n;
      return p < 31 ? n - 2 : n;
    };
    const portCount = function () {
      if (mode.value === 'off') return 0;
      if (mode.value !== 'custom') return parseInt(mode.selectedOptions[0].dataset.count, 10) || 0;
      const iv = [];
      (portsInput.value || '').split(',').forEach(function (part) {
        const m = part.trim().match(/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/);
        if (!m) return;
        let lo = parseInt(m[1], 10), hi = m[2] === undefined ? lo : parseInt(m[2], 10);
        lo = Math.max(lo, 1); hi = Math.min(hi, 65535);
        if (lo <= hi) iv.push([lo, hi]);
      });
      iv.sort((a, b) => a[0] - b[0]);
      let total = 0, end = 0;
      iv.forEach(function (r) {
        if (r[1] <= end) return;
        total += r[1] - Math.max(r[0], end + 1) + 1;
        end = r[1];
      });
      return total;
    };
    const update = function () {
      const ports = portCount();
      if (mode.value === 'off') { calc.style.display = 'none'; return; }
      calc.style.display = 'block';
      const hosts = hostCount(target.value);
      if (hosts === null) { calc.style.color = '#64748b'; calc.textContent = 'Hesap: geçerli bir hedef ağ girin.'; return; }
      const probes = hosts * ports;
      const over = !isSuper && probes > limit;
      calc.style.color = over ? '#dc2626' : '#15803d';
      calc.style.fontWeight = over ? '600' : '400';
      calc.textContent = 'Hesap: ' + fmt(hosts) + ' adres × ' + fmt(ports) + ' port = ' + fmt(probes) +
        (isSuper ? ' (Süper Yönetici: sınır yok)' : ' / sınır ' + fmt(limit) + (over ? ' — sınır aşıldı; ağı daraltın veya daha az port seçin.' : ''));
    };
    [mode, target, portsInput].forEach(el => el && el.addEventListener('input', update));
    mode.addEventListener('change', update);
    update();
  }

  // Görüntüle / Sil: sayfa içinde
  content.addEventListener('click', function (e) {
    const view = e.target.closest('a.js-view');
    if (view) {
      e.preventDefault();
      window.EM.go(view.getAttribute('href'));
      return;
    }
    const del = e.target.closest('button.js-del');
    if (del) {
      if (!window.confirm('Bu tarama kaydı silinsin mi?')) return;
      del.disabled = true;
      window.EM.post(del.getAttribute('data-url')).then(function () { del.disabled = false; });
    }
  });

  // sonuç kartına kaydır (Görüntüle / yeni tarama sonrası)
  function reveal() {
    const c = document.getElementById('ipscanResult');
    if (!c) return;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    c.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    c.classList.remove('flash-focus'); void c.offsetWidth; c.classList.add('flash-focus');
    // yumuşak kaydırma engellenirse veya içerik kayarsa kartı kesin göster
    setTimeout(function () {
      var t = c.getBoundingClientRect().top;
      if (t < -20 || t > window.innerHeight - 140) c.scrollIntoView({ behavior: 'auto', block: 'start' });
    }, 900);
  }
  if (new URLSearchParams(location.search).get('job')) setTimeout(reveal, 60);

  if (!card) return;
  const jobId = card.getAttribute('data-job-id');
  const badge = document.getElementById('isBadge');
  const summary = document.getElementById('isSummary');
  const bar = document.getElementById('isBar');
  const rows = document.getElementById('isRows');
  const empty = document.getElementById('isEmpty');
  const cancelBtn = document.getElementById('isCancel');
  const search = document.getElementById('isSearch');
  const byIp = {};
  let shown = 0;

  function portsCell(td, ports) {
    td.textContent = '';
    (ports || []).forEach(function (p) {
      const s = document.createElement('span');
      s.className = 'port-chip';
      s.textContent = p.port + (p.service ? '/' + p.service : '');
      td.appendChild(s);
    });
    if (!td.firstChild) td.textContent = '-';
  }

  function addRow(h) {
    const tr = document.createElement('tr');
    [h.ip, h.rtt_ms === null ? 'ARP' : h.rtt_ms + ' ms', h.mac || '-', h.vendor || '-', h.hostname || '-']
      .forEach(function (v) { const td = document.createElement('td'); td.textContent = v; tr.appendChild(td); });
    const pt = document.createElement('td');
    portsCell(pt, h.ports);
    tr.appendChild(pt);
    byIp[h.ip] = pt;
    rows.appendChild(tr);
  }

  function filterRows() {
    const q = (search ? search.value : '').toLowerCase();
    Array.prototype.forEach.call(rows.children, function (tr) { tr.style.display = tr.textContent.toLowerCase().indexOf(q) < 0 ? 'none' : ''; });
  }
  if (search) search.addEventListener('input', filterRows);

  function render(job) {
    if (job.status !== 'running') { rows.textContent = ''; shown = 0; }
    job.alive.forEach(addRow);
    shown = job.since + job.alive.length;
    Object.keys(job.ports_map || {}).forEach(function (ip) { if (byIp[ip]) portsCell(byIp[ip], job.ports_map[ip]); });
    const scanning = job.phase === 'ports' && job.port_total;
    const done = scanning ? job.port_done : job.done, total = scanning ? job.port_total : job.total;
    const pct = total ? Math.floor((done / total) * 100) : 0;
    bar.style.width = (job.status === 'running' ? pct : 100) + '%';
    summary.textContent = job.network + ' · ' + (scanning ? 'port taraması ' : '') + done.toLocaleString('tr-TR') + ' / ' +
      total.toLocaleString('tr-TR') + (scanning ? ' bağlantı' : ' adres') + ' (%' + pct + ') · ' + job.elapsed + ' sn' +
      (job.method ? ' · ' + (METHOD[job.method] || job.method) : '');
    badge.textContent = (job.status === 'running' && scanning ? 'Port taranıyor' : STATUS[job.status]) + ' · ' + job.alive_count + ' aktif host';
    badge.className = 'status-pill ' + (job.alive_count ? 'online' : (job.status === 'running' ? '' : 'offline'));
    document.getElementById('isTruncated').style.display = job.truncated ? 'block' : 'none';
    empty.style.display = (job.status !== 'running' && !job.alive_count) ? 'block' : 'none';
    cancelBtn.style.display = job.status === 'running' ? 'inline-flex' : 'none';
    filterRows();
  }

  function poll() {
    if (!document.body.contains(card)) return;
    fetch('/ip-scan/job/' + encodeURIComponent(jobId) + '?since=' + shown, { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.success) { summary.textContent = data.error || 'Tarama bulunamadı.'; return; }
        render(data.job);
        if (data.job.status === 'running') setTimeout(poll, 1000);
      })
      .catch(function () { setTimeout(poll, 3000); });
  }

  cancelBtn.addEventListener('click', function () {
    cancelBtn.disabled = true;
    fetch('/ip-scan/job/' + encodeURIComponent(jobId) + '/cancel', { method: 'POST', headers: { 'Accept': 'application/json' } });
  });
  poll();
})();

// geçmiş tablosu: başlangıç zamanı yerel saatte
document.querySelectorAll('.is-ts').forEach(function (td) {
  td.textContent = new Date(parseInt(td.getAttribute('data-ts'), 10) * 1000).toLocaleString('tr-TR');
});
