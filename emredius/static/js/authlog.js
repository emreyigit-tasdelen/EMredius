// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  function load() {
    var s = 'q=' + encodeURIComponent(q('alQ').value) + '&result=' + encodeURIComponent(q('alResult').value) + '&days=' + encodeURIComponent(q('alDays').value);
    q('alCsv').href = '/authlog/export.csv?' + s;
    fetch('/authlog/data?' + s).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('alInfo').textContent = j.accept + ' kabul · ' + j.reject + ' ret';
      q('alRows').innerHTML = j.rows.map(function (r) {
        var ok = r.reply === 'Access-Accept';
        return '<tr><td>' + esc(r.authdate) + '</td><td>' + esc(r.username) + '</td><td><span class="status-pill ' + (ok ? 'online' : 'offline') + '">' +
          (ok ? 'Kabul' : 'Ret') + '</span></td><td><a href="/correlation?q=' + encodeURIComponent(r.username) + '">Korelasyon</a></td></tr>';
      }).join('') || '<tr><td colspan="4" style="color:var(--text-muted);">Kayıt yok.</td></tr>';
    }).catch(function () {});
  }
  q('alGo').addEventListener('click', load);
  q('alQ').addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
  q('alResult').addEventListener('change', load);
  q('alDays').addEventListener('change', load);
  load();
})();
