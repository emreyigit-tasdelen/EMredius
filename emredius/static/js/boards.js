// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  var grid = document.getElementById('bGrid');
  var TONE = {bad: '#dc2626', ok: '#16a34a', '': 'var(--text-primary)'};
  function card(w) {
    var body = '';
    if (w.kind === 'stats') {
      body = '<div style="display:flex;gap:1rem;flex-wrap:wrap;">' + w.items.map(function (i) {
        return '<a href="' + esc(i.href) + '" style="text-decoration:none;text-align:center;flex:1;"><div style="font-size:1.6rem;font-weight:700;color:' + (TONE[i.tone] || TONE['']) + ';">' +
          esc(i.value) + '</div><div style="font-size:0.78rem;color:var(--text-muted);">' + esc(i.label) + '</div></a>';
      }).join('') + '</div>';
    } else {
      body = w.items.length ? w.items.map(function (i) {
        return '<div style="padding:0.3rem 0;border-bottom:1px solid var(--border);font-size:0.85rem;">' + esc(i.text) +
          (i.sub ? '<br><small style="color:var(--text-muted);">' + esc(i.sub) + '</small>' : '') + '</div>';
      }).join('') : '<div style="color:var(--text-muted);font-size:0.85rem;">Kayıt yok.</div>';
    }
    return '<div style="border:1px solid var(--border);border-radius:8px;padding:1rem;background:var(--bg-subtle);"><div style="font-weight:600;margin-bottom:0.6rem;">' +
      (w.href ? '<a href="' + esc(w.href) + '" style="text-decoration:none;color:inherit;">' + esc(w.title) + '</a>' : esc(w.title)) + '</div>' + body + '</div>';
  }
  function load() {
    fetch('/boards/' + grid.dataset.board + '/data').then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      grid.innerHTML = j.widgets.map(card).join('') || '<div style="color:var(--text-muted);">Bileşen seçilmedi. Aşağıdan ekleyin.</div>';
    }).catch(function () {});
  }
  document.addEventListener('submit', function (e) { if (e.target.classList.contains('b-del') && !window.confirm('Pano silinsin mi?')) e.preventDefault(); });
  load();
  setInterval(load, 15000);
})();
