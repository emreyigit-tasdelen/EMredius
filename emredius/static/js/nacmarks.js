// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  var kind = q('nmRoot').dataset.kind;
  function load() {
    fetch('/' + kind + '/data').then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('nmInfo').textContent = j.marks.length + ' etkin kayıt';
      q('nmRows').innerHTML = j.marks.map(function (m) {
        return '<tr><td>' + (m.match === 'regex' ? 'Regex' : 'Tam') + '</td><td>' + esc(m.mac) + '</td><td>' + esc(m.username) + '</td><td>' + esc(m.reason) + '</td><td>' + esc(m.created_by) +
          '</td><td>' + esc(m.created_at) + '</td><td>' + (esc(m.expires_at) || 'süresiz') +
          '</td><td><button class="btn" type="button" data-release="' + esc(m.id) + '">Kaldır</button></td></tr>';
      }).join('') || '<tr><td colspan="8" style="color:var(--text-muted);">Kayıt yok.</td></tr>';
    }).catch(function () {});
  }
  q('nmAdd').addEventListener('click', function () {
    var fd = new FormData();
    fd.append('mac', q('nmMac').value); fd.append('username', q('nmUser').value);
    fd.append('reason', q('nmReason').value); fd.append('match', q('nmMatch').value); fd.append('hours', q('nmHours').value);
    fetch('/' + kind + '/add', {method: 'POST', body: fd}).then(function (r) { return r.json(); }).then(function (j) {
      q('nmMsg').textContent = j.success ? 'Eklendi.' : (j.error || 'Hata');
      if (j.success) { q('nmMac').value = ''; q('nmUser').value = ''; q('nmReason').value = ''; q('nmHours').value = ''; load(); }
    }).catch(function () { q('nmMsg').textContent = 'İstek başarısız.'; });
  });
  q('nmRows').addEventListener('click', function (e) {
    var id = e.target.getAttribute && e.target.getAttribute('data-release');
    if (!id) return;
    fetch('/' + kind + '/' + id + '/release', {method: 'POST'}).then(function () { load(); });
  });
  q('nmImport').addEventListener('click', function () {
    var f = q('nmFile').files[0];
    if (!f) { q('nmMsg').textContent = 'CSV dosyası seçin.'; return; }
    var fd = new FormData(); fd.append('file', f);
    fetch('/' + kind + '/import', {method: 'POST', body: fd}).then(function (r) { return r.json(); }).then(function (j) {
      q('nmMsg').textContent = j.success ? (j.added + ' eklendi' + (j.errors.length ? ', hatalar: ' + j.errors.join('; ') : '')) : (j.error || 'Hata');
      load();
    }).catch(function () { q('nmMsg').textContent = 'İstek başarısız.'; });
  });
  load();
})();
