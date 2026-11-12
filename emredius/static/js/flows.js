// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function sz(v) { v = +v || 0; var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0; while (v >= 1024 && i < 4) { v /= 1024; i++; } return v.toFixed(i ? 1 : 0) + ' ' + u[i]; }
  function qs() { return 'group=' + q('fGroup').value + '&range=' + q('fRange').value + '&q=' + encodeURIComponent(q('fQ').value); }
  function load() {
    q('fCsv').href = '/flows/export.csv?' + qs();
    q('fJson').href = '/flows/export.json?' + qs();
    fetch('/flows/data?' + qs()).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      var s = j.stats;
      q('fStats').textContent = s.flows_24h + ' akış (24 sa) · ' + s.exporters + ' ihracatçı' + (s.sflow_packets ? ' · sFlow ' + s.sflow_packets + ' paket' : '');
      q('fInfo').textContent = 'Alınan paket: ' + s.packets_rx + ' · hata: ' + s.errors + ' · son paket: ' + (s.last_packet || '-') + (s.packets_rx || s.rows ? '' : ' · henüz akış gelmedi (UDP 2055 açık mı, cihaz ihracatı açık mı?)');
      var tot = j.top.reduce(function (a, r) { return a + r.bytes; }, 0) || 1;
      q('fBody').innerHTML = j.top.map(function (r, i) {
        return '<tr><td>' + (i + 1) + '</td><td>' + esc(r.key) + '</td><td>' + esc(r.name || '-') + '</td><td>' + sz(r.bytes) + '</td><td>' + r.packets + '</td><td>' + r.flows +
          '</td><td><div style="background:var(--border);border-radius:3px;min-width:80px;"><div style="background:#2563eb;height:8px;border-radius:3px;width:' + Math.round(r.bytes / tot * 100) + '%;"></div></div></td></tr>';
      }).join('') || '<tr><td colspan="7" style="color:var(--text-muted);">Kayıt yok.</td></tr>';
      var cv = q('fChart'), rows = j.timeline;
      cv.style.display = rows.length > 1 ? '' : 'none';
      if (rows.length < 2) return;
      var w = cv.width = cv.clientWidth || 600, h = cv.height = 120, x = cv.getContext('2d');
      var max = Math.max.apply(null, rows.map(function (r) { return r.bytes; })) || 1;
      x.clearRect(0, 0, w, h); x.beginPath(); x.strokeStyle = '#2563eb'; x.lineWidth = 1.5;
      rows.forEach(function (r, i) { var px = i / (rows.length - 1) * w, py = h - 4 - r.bytes / max * (h - 8); if (i) x.lineTo(px, py); else x.moveTo(px, py); });
      x.stroke();
    }).catch(function () {});
  }
  ['fGroup', 'fRange'].forEach(function (id) { q(id).addEventListener('change', load); });
  var t; q('fQ').addEventListener('input', function () { clearTimeout(t); t = setTimeout(load, 300); });
  load();
  setInterval(load, 15000);
})();
