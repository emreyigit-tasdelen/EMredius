// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function bps(v) { v = +v || 0; var u = ['bit/s', 'Kb/s', 'Mb/s', 'Gb/s'], i = 0; while (v >= 1000 && i < 3) { v /= 1000; i++; } return v.toFixed(i ? 1 : 0) + ' ' + u[i]; }
  function up(s) { if (s == null) return '-'; s = +s; return Math.floor(s / 86400) + 'g ' + Math.floor(s % 86400 / 3600) + 's'; }
  function v(x) { return x == null ? '-' : esc(x); }
  var sel = null;
  function load() {
    var qs = encodeURIComponent(q('hQ').value);
    fetch('/health/data/health?q=' + qs).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('hStats').textContent = j.stats.devices + ' cihaz · ' + j.stats.warn + ' uyarı';
      q('hBody').innerHTML = j.rows.map(function (r) {
        var c = r.state === 'warn' ? 'offline' : 'online';
        return '<tr data-id="' + r.id + '" data-name="' + esc(r.name) + '" style="cursor:pointer;"><td><span class="status-pill ' + c + '">' +
          (r.state === 'warn' ? 'Uyarı' : r.state === 'nodata' ? 'Veri yok' : 'Normal') + '</span></td><td>' + esc(r.name) + '</td><td>' + esc(r.ip) +
          '</td><td>' + v(r.cpu) + '</td><td>' + v(r.ram) + '</td><td>' + v(r.temp) + '</td><td>' + up(r.uptime_s) + '</td><td>' + esc(r.ts) + '</td></tr>';
      }).join('') || '<tr><td colspan="8" style="color:var(--text-muted);">Veri yok.</td></tr>';
    }).catch(function () {});
    fetch('/health/data/traffic?q=' + qs).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('tBody').innerHTML = j.rows.map(function (r) {
        return '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.ip) + '</td><td>' + esc(r.if_index) + '</td><td>' + bps(r.in_bps) + '</td><td>' +
          bps(r.out_bps) + '</td><td>' + esc(r.ts) + '</td></tr>';
      }).join('') || '<tr><td colspan="6" style="color:var(--text-muted);">Veri yok.</td></tr>';
    }).catch(function () {});
    if (sel) hist(sel.id, sel.name);
  }
  function hist(id, name) {
    sel = {id: id, name: name};
    fetch('/health/data/history?device=' + id).then(function (r) { return r.json(); }).then(function (j) {
      var cv = q('hChart'), rows = j.rows || [];
      cv.style.display = rows.length ? '' : 'none';
      q('hChartLbl').textContent = name + ' · 24 saat · mavi CPU, yeşil bellek, turuncu sıcaklık';
      if (!rows.length) return;
      var w = cv.width = cv.clientWidth || 600, h = cv.height = 140, x = cv.getContext('2d');
      x.clearRect(0, 0, w, h);
      [['cpu', '#2563eb'], ['ram', '#16a34a'], ['temp', '#f59e0b']].forEach(function (s) {
        x.beginPath(); x.strokeStyle = s[1]; x.lineWidth = 1.5;
        rows.forEach(function (r, i) {
          var y = h - 4 - Math.min(100, +r[s[0]] || 0) / 100 * (h - 8), px = i / Math.max(1, rows.length - 1) * w;
          if (i) x.lineTo(px, y); else x.moveTo(px, y);
        });
        x.stroke();
      });
    }).catch(function () {});
  }
  document.addEventListener('click', function (e) { var t = e.target.closest('tr[data-id]'); if (t) hist(t.dataset.id, t.dataset.name); });
  var t;
  q('hQ').addEventListener('input', function () { clearTimeout(t); t = setTimeout(load, 300); });
  load();
  setInterval(load, 10000);
})();
