// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function empty(n, t) { return '<tr><td colspan="' + n + '" style="color:var(--text-muted);">' + t + '</td></tr>'; }
  function load() {
    var s = 'q=' + encodeURIComponent(q('mhQ').value) + '&days=' + encodeURIComponent(q('mhDays').value);
    q('mhCsv').href = '/machist/export.csv?' + s;
    fetch('/machist/data?' + s).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('mhInfo').textContent = j.macs.length + ' MAC · ' + j.ports.length + ' port kaydı · ' + j.sessions.length + ' oturum';
      q('mhPorts').innerHTML = j.ports.map(function (p) {
        return '<tr><td>' + esc(p.mac) + '</td><td>' + (p.radius_user ? '<a href="/machist?q=' + encodeURIComponent(p.radius_user) + '">' + esc(p.radius_user) + '</a>' : '-') +
          '</td><td>' + esc(p.device_ip) + '</td><td>' + esc(p.port) + '</td><td>' + esc(p.vlan) + '</td><td>' + esc(p.first_seen) +
          '</td><td>' + esc(p.last_seen) + '</td><td>' + esc(p.seen_count) + '</td></tr>';
      }).join('') || empty(8, q('mhQ').value ? 'Kayıt yok.' : 'Aramak için kullanıcı, MAC veya cihaz IP yazın.');
      q('mhSess').innerHTML = j.sessions.map(function (x) {
        return '<tr><td>' + esc(x.user) + '</td><td>' + esc(x.mac) + '</td><td>' + esc(x.nas) + '</td><td>' + esc(x.nas_port) + '</td><td>' + esc(x.ip) +
          '</td><td>' + esc(x.start) + '</td><td>' + (esc(x.stop) || '<b>açık</b>') + '</td></tr>';
      }).join('') || empty(7, 'Oturum yok.');
    }).catch(function () {});
  }
  q('mhGo').addEventListener('click', load);
  q('mhQ').addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
  q('mhDays').addEventListener('change', load);
  load();
})();
