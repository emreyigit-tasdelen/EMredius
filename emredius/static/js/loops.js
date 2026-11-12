// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function sev(s) { return '<span class="status-pill ' + (s === 'high' ? 'offline' : 'online') + '">' + (s === 'high' ? 'Yüksek' : s === 'medium' ? 'Orta' : 'Düşük') + '</span>'; }
  function load() {
    fetch('/loops/data').then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      document.getElementById('lStats').textContent = j.stats.rings + ' halka · ' + j.stats.macs + ' taşınan MAC';
      document.getElementById('lRings').innerHTML = j.rings.map(function (r) {
        return '<tr><td>' + sev(r.severity) + '</td><td>' + r.ring + '</td><td>' + r.length + '</td><td>' +
          r.nodes.map(function (n) { return esc(n.label); }).join(' → ') + '</td></tr>';
      }).join('') || '<tr><td colspan="4" style="color:var(--text-muted);">Halka yok.</td></tr>';
      document.getElementById('lMacs').innerHTML = j.macs.map(function (m) {
        return '<tr><td>' + sev(m.severity) + '</td><td><a href="/equipment?q=' + encodeURIComponent(m.mac) + '">' + esc(m.mac) + '</a></td><td>' + esc(m.vendor) +
          '</td><td>' + esc(m.radius_user || '-') + '</td><td>' + m.locations.map(function (l) { return esc(l.device_ip + ':' + l.port); }).join(', ') + '</td></tr>';
      }).join('') || '<tr><td colspan="5" style="color:var(--text-muted);">MAC taşınması yok.</td></tr>';
    }).catch(function () {});
  }
  load();
  setInterval(load, 15000);
})();
