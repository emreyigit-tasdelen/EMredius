// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  var hist = document.getElementById('cfgHist'), view = document.getElementById('cfgView'), cur = '';
  function showHist(ip) {
    cur = ip;
    fetch('/configs/' + encodeURIComponent(ip) + '/versions').then(function (r) { return r.json(); }).then(function (j) {
      var v = j.versions || [];
      hist.innerHTML = '<h4>' + esc(ip) + ' sürümleri</h4>' + (v.length ? '<table><thead><tr><th>Sürüm</th><th>Tarih</th><th>Kaynak</th><th>Boyut</th><th>Not</th><th></th></tr></thead><tbody>' +
        v.map(function (x, i) {
          return '<tr><td>v' + x.version + '</td><td>' + esc(x.created) + '</td><td>' + esc(x.source) + '</td><td>' + x.size + '</td><td>' + esc(x.note) + '</td><td><button class="btn" data-view="' + x.version + '">Göster</button> ' +
            (v[i + 1] ? '<button class="btn" data-diff="' + v[i + 1].version + ',' + x.version + '">Öncekiyle fark</button>' : '') + '</td></tr>';
        }).join('') + '</tbody></table>' : '<div style="color:var(--text-muted);">Sürüm yok.</div>');
      view.style.display = 'none';
    });
  }
  document.addEventListener('click', function (e) {
    var h = e.target.closest('[data-hist]'), v = e.target.closest('[data-view]'), d = e.target.closest('[data-diff]');
    if (h) showHist(h.dataset.hist);
    if (v) fetch('/configs/' + encodeURIComponent(cur) + '/v/' + v.dataset.view).then(function (r) { return r.json(); }).then(function (j) { view.style.display = ''; view.textContent = j.success ? j.content : j.error; });
    if (d) {
      var p = d.dataset.diff.split(',');
      fetch('/configs/' + encodeURIComponent(cur) + '/diff?a=' + p[0] + '&b=' + p[1]).then(function (r) { return r.json(); }).then(function (j) {
        view.style.display = ''; view.textContent = j.success ? ('+' + j.added + ' / -' + j.removed + '\n' + j.lines.join('\n')) : j.error;
      });
    }
  });
  var up = document.getElementById('cfgUp');
  if (up) up.addEventListener('submit', function () { up.action = '/configs/' + encodeURIComponent(document.getElementById('cfgUpIp').value) + '/upload'; });
  document.addEventListener('submit', function (e) { if (e.target.classList.contains('cfg-del') && !window.confirm('Silinsin mi?')) e.preventDefault(); });
})();
