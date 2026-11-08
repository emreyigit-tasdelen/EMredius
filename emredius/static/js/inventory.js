// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function row(d) {
    var on = d.status === 'ONLINE';
    return '<tr><td><span class="status-pill ' + (on ? 'online' : 'offline') + '">' + (on ? 'Aktif' : 'Pasif') + '</span></td><td>' + esc(d.ip) +
      '</td><td>' + esc(d.sys_name || d.hostname || '-') + '</td><td>' + esc(d.mac || '-') + (d.mac_vendor ? '<br><small>' + esc(d.mac_vendor) + '</small>' : '') +
      '</td><td>' + esc(d.vendor || '-') + '</td><td>' + esc(d.model || '-') + '</td><td>' + esc(d.os_version || '-') + '</td><td>' + esc(d.device_type) +
      '</td><td>' + (d.snmp_ok ? '✔' : '–') + '</td><td>' + (d.ssh_ok ? '✔' : '–') + '</td><td>' + esc(d.last_seen) + '</td></tr>';
  }
  function refresh() {
    fetch('/inventory/data' + location.search).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      document.getElementById('stats').textContent = j.stats.online + ' aktif / ' + j.stats.total + ' cihaz · ' + j.stats.snmp + ' SNMP · ' + j.stats.ssh + ' SSH';
      document.getElementById('devBody').innerHTML = j.devices.slice(0, 500).map(row).join('') || '<tr><td colspan="11">Kayıt yok.</td></tr>';
    }).catch(function () {});
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('.inv-scan');
    if (!b) return;
    fetch('/inventory/range/' + encodeURIComponent(b.dataset.scan) + '/scan', { method: 'POST' }).then(function (r) { return r.json(); })
      .then(function (j) { if (!j.success) alert(j.error); else setTimeout(refresh, 1000); });
  });
  document.addEventListener('submit', function (e) {
    if (e.target.classList.contains('inv-del') && !window.confirm('Aralık silinsin mi?')) e.preventDefault();
  });
  setInterval(refresh, 10000);
})();
