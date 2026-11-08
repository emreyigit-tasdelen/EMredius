// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function empty(n, t) { return '<tr><td colspan="' + n + '" style="color:var(--text-muted);">' + t + '</td></tr>'; }
  var KIND = {blacklist: 'Kara liste', quarantine: 'Karantina'};
  function chips(list) {
    return list.map(function (v) { return '<a class="btn" href="/correlation?q=' + encodeURIComponent(v) + '">' + esc(v) + '</a> '; }).join('');
  }
  function load() {
    var term = q('coQ').value;
    fetch('/correlation/data?q=' + encodeURIComponent(term) + '&days=' + encodeURIComponent(q('coDays').value)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('coInfo').textContent = j.kind ? (j.users.length + ' kullanıcı · ' + j.macs.length + ' MAC · ' + j.ips.length + ' IP') : '-';
      q('coIds').innerHTML = chips(j.users) + chips(j.macs) + chips(j.ips);
      q('coMarks').innerHTML = j.marks.map(function (m) {
        return '<tr><td>' + esc(KIND[m.kind] || m.kind) + '</td><td>' + esc(m.mac) + '</td><td>' + esc(m.username) + '</td><td>' + esc(m.reason) + '</td><td>' + esc(m.created_at) + '</td></tr>';
      }).join('') || empty(5, 'İşaret yok.');
      q('coAuth').innerHTML = j.auth.map(function (a) {
        return '<tr><td>' + esc(a.authdate) + '</td><td>' + esc(a.username) + '</td><td>' + (a.reply === 'Access-Accept' ? 'Kabul' : 'Ret') + '</td></tr>';
      }).join('') || empty(3, term ? 'Kayıt yok.' : 'Aramak için kullanıcı, MAC veya IP yazın.');
      q('coSess').innerHTML = j.sessions.map(function (x) {
        return '<tr><td>' + esc(x.user) + '</td><td>' + esc(x.mac) + '</td><td>' + esc(x.nas) + '</td><td>' + esc(x.nas_port) + '</td><td>' + esc(x.ip) +
          '</td><td>' + esc(x.start) + '</td><td>' + (esc(x.stop) || '<b>açık</b>') + '</td></tr>';
      }).join('') || empty(7, 'Oturum yok.');
      q('coPorts').innerHTML = j.ports.map(function (p) {
        return '<tr><td>' + esc(p.mac) + '</td><td>' + esc(p.device_ip) + '</td><td>' + esc(p.port) + '</td><td>' + esc(p.vlan) + '</td><td>' + esc(p.first_seen) + '</td><td>' + esc(p.last_seen) + '</td></tr>';
      }).join('') || empty(6, 'Kayıt yok.');
    }).catch(function () {});
  }
  q('coGo').addEventListener('click', load);
  q('coQ').addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
  q('coDays').addEventListener('change', load);
  load();
})();
