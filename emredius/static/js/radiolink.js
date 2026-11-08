// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function v(x) { return x == null ? '-' : esc(x); }
  var sel = null;
  function load() {
    fetch('/health/radiolink/data?q=' + encodeURIComponent(q('rQ').value)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('rStats').textContent = j.stats.links + ' hat · ' + j.stats.warn + ' uyarı' + (j.stats.enabled ? '' : ' · otomatik kapalı');
      q('rBody').innerHTML = j.rows.map(function (r) {
        return '<tr data-id="' + r.id + '" data-name="' + esc(r.name) + '" style="cursor:pointer;"><td><span class="status-pill ' + (r.state === 'warn' ? 'offline' : 'online') + '">' +
          (r.state === 'warn' ? 'Uyarı' : r.state === 'nodata' ? 'Veri yok' : 'Normal') + '</span></td><td>' + esc(r.name) + '</td><td>' + esc(r.ip) + '</td><td>' + esc(r.vendor) +
          '</td><td>' + v(r.rssi) + '</td><td>' + v(r.noise) + '</td><td>' + v(r.snr) + '</td><td>' + v(r.ccq) + '</td><td>' + v(r.tx_rate) + ' / ' + v(r.rx_rate) +
          '</td><td>' + esc(r.ts) + '</td></tr>';
      }).join('') || '<tr><td colspan="10" style="color:var(--text-muted);">Radyolink verisi yok. Envanterde SNMP açık Ubiquiti/Cambium/MikroTik/Siklu cihazı olmalı.</td></tr>';
    }).catch(function () {});
    if (sel) hist(sel.id, sel.name);
  }
  function hist(id, name) {
    sel = {id: id, name: name};
    fetch('/health/radiolink/data?history=' + id).then(function (r) { return r.json(); }).then(function (j) {
      var cv = q('rChart'), rows = j.rows || [];
      cv.style.display = rows.length ? '' : 'none';
      q('rChartLbl').textContent = name + ' · 24 saat · mavi sinyal (dBm), yeşil SNR, turuncu CCQ';
      if (!rows.length) return;
      var w = cv.width = cv.clientWidth || 600, h = cv.height = 140, x = cv.getContext('2d');
      x.clearRect(0, 0, w, h);
      [['rssi', '#2563eb', -100, -30], ['snr', '#16a34a', 0, 60], ['ccq', '#f59e0b', 0, 100]].forEach(function (s) {
        x.beginPath(); x.strokeStyle = s[1]; x.lineWidth = 1.5; var first = true;
        rows.forEach(function (r, i) {
          if (r[s[0]] == null) return;
          var px = rows.length > 1 ? i * (w - 4) / (rows.length - 1) + 2 : w / 2,
              py = h - 4 - (Math.max(s[2], Math.min(s[3], r[s[0]])) - s[2]) / (s[3] - s[2]) * (h - 8);
          if (first) { x.moveTo(px, py); first = false; } else x.lineTo(px, py);
        });
        x.stroke();
      });
    }).catch(function () {});
  }
  document.addEventListener('click', function (e) {
    if (e.target.closest('#rPoll')) { fetch('/health/radiolink/poll', {method: 'POST'}).then(function () { setTimeout(load, 5000); }); return; }
    var tr = e.target.closest('#rBody tr[data-id]');
    if (tr) hist(tr.getAttribute('data-id'), tr.getAttribute('data-name'));
  });
  q('rQ').addEventListener('input', load);
  load(); setInterval(load, 15000);
})();
