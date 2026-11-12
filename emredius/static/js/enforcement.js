// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  var KIND = {blacklist: 'Kara liste', quarantine: 'Karantina'}, ACT = {add: 'Eklendi', release: 'Kaldırıldı', expire: 'Süresi doldu'};
  fetch('/enforcement/data').then(function (r) { return r.json(); }).then(function (j) {
    if (!j.success) return;
    document.getElementById('enInfo').textContent = j.events.length + ' kayıt';
    document.getElementById('enRows').innerHTML = j.events.map(function (e) {
      return '<tr><td>' + esc(e.at) + '</td><td>' + esc(KIND[e.kind] || e.kind) + '</td><td>' + esc(ACT[e.action] || e.action) + '</td><td>' + esc(e.mac) +
        '</td><td>' + esc(e.username) + '</td><td>' + esc(e.actor) + '</td><td>' + esc(e.detail) + '</td></tr>';
    }).join('') || '<tr><td colspan="7" style="color:var(--text-muted);">Kayıt yok.</td></tr>';
  }).catch(function () {});
})();
