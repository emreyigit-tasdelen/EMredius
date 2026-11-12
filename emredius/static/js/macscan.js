// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function poe(r) {
    if (!r.poe_state) return '-';
    return esc(r.poe_state) + (r.poe_class !== '' ? ' · sınıf ' + esc(r.poe_class) : '') + (r.poe_w !== '' ? ' · ' + esc(r.poe_w) + ' W' : '');
  }
  function row(r) {
    return '<tr><td>' + esc(r.device_ip) + '</td><td>' + esc(r.port) + (r.uplink ? ' <small>(uplink)</small>' : '') + '</td><td>' + esc(r.vlan) +
      '</td><td>' + esc(r.mac) + '</td><td>' + esc(r.vendor) + '</td><td>' + esc(r.kind) + '</td><td>' + esc(r.ip) + '</td><td>' +
      (r.radius_user ? '<a href="/sessions">' + esc(r.radius_user) + '</a>' + (r.radius_active ? ' ●' : '') : '-') + '</td><td>' + esc(r.neighbor) +
      '</td><td>' + poe(r) + '</td><td>' + esc(r.last_seen) + '</td></tr>';
  }
  function load() {
    var u = '/macscan/data?q=' + encodeURIComponent(q('msQ').value) + '&vlan=' + encodeURIComponent(q('msVlan').value) +
      '&access=' + (q('msAccess').checked ? 1 : 0) + '&poe=' + (q('msPoe').checked ? 1 : 0);
    fetch(u).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      var s = j.stats;
      q('msStats').textContent = s.macs + ' MAC · ' + s.arp + ' ARP · PoE ' + s.poe_on + '/' + s.poe_ports + ' port' + (s.running ? ' · taranıyor…' : '');
      q('msCount').textContent = j.total + ' kayıt' + (j.total > j.rows.length ? ' (ilk ' + j.rows.length + ')' : '');
      q('msPoeMain').textContent = j.poe.length ? 'PoE bütçesi: ' + j.poe.map(function (m) { return m.device_ip + ' #' + m.grp + ' ' + m.used_w + '/' + m.budget_w + ' W'; }).join(' · ') : '';
      q('msRows').innerHTML = j.rows.map(row).join('') || '<tr><td colspan="11" style="color:var(--text-muted);">Kayıt yok. Önce Tara düğmesine basın.</td></tr>';
    }).catch(function () {});
  }
  ['msQ', 'msVlan'].forEach(function (id) { q(id).addEventListener('input', load); });
  ['msAccess', 'msPoe'].forEach(function (id) { q(id).addEventListener('change', load); });
  q('msScan').addEventListener('click', function () {
    fetch('/macscan/scan', {method: 'POST'}).then(function (r) { return r.json(); }).then(function (j) { if (!j.success) alert(j.error); });
  });
  load(); setInterval(load, 15000);
})();
