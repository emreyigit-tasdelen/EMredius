// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  var dev = '', port = '', ports = [];
  function q(id) { return document.getElementById(id); }
  function stats(s) { q('eqStats').textContent = s.ports_up + '/' + s.ports + ' port · ' + s.macs + ' MAC · ' + s.modules + ' modül' + (s.running ? ' · taranıyor…' : ''); }
  function macRow(r) {
    return '<tr><td>' + esc(r.mac) + '</td><td>' + esc(r.vendor) + '</td><td>' + esc(r.vlan) + '</td><td>' + esc(r.device_ip) + '</td><td>' +
      esc(r.port) + (r.uplink ? ' <small>(uplink)</small>' : '') + '</td><td>' +
      (r.inv_ip ? '<a href="/inventory?q=' + encodeURIComponent(r.inv_ip) + '">' + esc(r.inv_name || r.inv_ip) + '</a>' : '-') +
      '</td><td>' + (r.radius_user ? '<a href="/sessions">' + esc(r.radius_user) + '</a>' + (r.radius_active ? ' ●' : '') : '-') +
      '</td><td>' + esc(r.last_seen) + '</td></tr>';
  }
  function loadMacs() {
    var u = '/equipment/data/macs?q=' + encodeURIComponent(q('eqQ').value) + '&vlan=' + encodeURIComponent(q('eqVlan').value) +
      '&device=' + encodeURIComponent(dev) + '&port=' + encodeURIComponent(port);
    fetch(u).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      stats(j.stats);
      q('eqMacCount').textContent = j.total + ' kayıt' + (j.total > j.rows.length ? ' (ilk ' + j.rows.length + ')' : '');
      q('eqMacs').innerHTML = j.rows.map(macRow).join('') || '<tr><td colspan="8" style="color:var(--text-muted);">Kayıt yok.</td></tr>';
    }).catch(function () {});
  }
  function loadDevs() {
    fetch('/equipment/data/summary').then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      stats(j.stats);
      q('eqDevs').innerHTML = j.devices.map(function (d) {
        return '<tr><td>' + esc(d.name) + '</td><td>' + esc(d.ip) + '</td><td>' + esc(d.vendor + ' ' + d.model) + '</td><td>' + d.ports_up + '/' + d.ports +
          '</td><td>' + d.macs + '</td><td>' + d.modules + '</td><td><button class="btn" data-dev="' + esc(d.ip) + '">Ön panel</button></td></tr>';
      }).join('') || '<tr><td colspan="7">SNMP cihaz yok.</td></tr>';
    }).catch(function () {});
  }
  function color(p) { return p.admin_status === 'down' ? '#94a3b8' : p.oper_status === 'up' ? '#16a34a' : '#dc2626'; }
  function short(n) { return String(n).replace(/^(Gigabit|TenGigabit|Fast)?Ethernet/i, function (m) { return m.replace(/ethernet/i, '').slice(0, 2) + 'e'; }).slice(-9); }
  function loadPanel() {
    if (!dev) return;
    fetch('/equipment/data/panel?device=' + encodeURIComponent(dev)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      ports = j.ports;
      q('eqPanelCard').style.display = '';
      q('eqPanelDev').textContent = dev;
      q('eqPanel').innerHTML = ports.map(function (p, i) {
        return '<button type="button" data-port="' + i + '" title="' + esc(p.name + ' ' + p.alias + ' ' + p.oper_status) +
          '" style="width:56px;height:44px;border-radius:4px;border:2px solid ' + (port === p.name ? '#f59e0b' : 'transparent') +
          ';background:' + color(p) + ';color:#fff;font-size:0.62rem;cursor:pointer;line-height:1.1;">' + esc(short(p.name)) +
          (p.mac_count ? '<br>' + p.mac_count : '') + '</button>';
      }).join('') || '<span style="color:var(--text-muted);">Port verisi yok.</span>';
      q('eqChassis').innerHTML = j.chassis.map(function (c) {
        return '<tr><td>' + esc(c.ent_class) + '</td><td>' + esc(c.name || c.descr) + '</td><td>' + esc(c.model) + '</td><td>' + esc(c.serial) +
          '</td><td>' + esc((c.hw_rev || '-') + ' / ' + (c.sw_rev || c.fw_rev || '-')) + '</td></tr>';
      }).join('') || '<tr><td colspan="5" style="color:var(--text-muted);">Şasi bilgisi yok (cihaz ENTITY-MIB desteklemiyor olabilir).</td></tr>';
    }).catch(function () {});
  }
  function showPort(p) {
    port = p.name;
    q('eqPortInfo').innerHTML = '<b>' + esc(p.name) + '</b> · ' + esc(p.oper_status) + ' / <span>yönetsel</span> ' + esc(p.admin_status) + ' · ' +
      (p.speed_mbps ? p.speed_mbps + ' Mb/s' : '-') + (p.alias ? ' · ' + esc(p.alias) : '') + (p.mac ? ' · ' + esc(p.mac) : '') +
      (p.neighbor ? '<br>Komşu: <a href="/topology">' + esc(p.neighbor) + '</a>' : '') + ' · <a href="#" id="eqClear">tüm portlar</a>';
    loadPanel();
    loadMacs();
  }
  document.addEventListener('click', function (e) {
    var d = e.target.closest('[data-dev]'), p = e.target.closest('[data-port]');
    if (d) { dev = d.dataset.dev; port = ''; q('eqPortInfo').innerHTML = ''; loadPanel(); loadMacs(); }
    else if (p) showPort(ports[+p.dataset.port]);
    else if (e.target.id === 'eqClear') { e.preventDefault(); port = ''; q('eqPortInfo').innerHTML = ''; loadPanel(); loadMacs(); }
    else if (e.target.closest('#eqScan')) fetch('/equipment/discover', {method: 'POST'}).then(function (r) { return r.json(); }).then(function (j) { if (!j.success) alert(j.error); });
  });
  var t;
  function deb() { clearTimeout(t); t = setTimeout(loadMacs, 300); }
  q('eqQ').addEventListener('input', deb);
  q('eqVlan').addEventListener('input', deb);
  loadMacs();
  setInterval(function () { loadDevs(); loadMacs(); loadPanel(); }, 15000);
})();
