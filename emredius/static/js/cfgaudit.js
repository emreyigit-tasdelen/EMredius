// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  var cur = '';
  function el(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function fill(sel, vs, val) { sel.innerHTML = vs.map(function (v) { return '<option value="' + v.version + '"' + (v.version == val ? ' selected' : '') + '>v' + v.version + ' · ' + esc(v.created) + '</option>'; }).join(''); }
  function render(d) {
    if (!d) { el('caOut').innerHTML = '<p>Karşılaştırılacak en az iki sürüm gerekli.</p>'; return; }
    var h = '<p><b>v' + d.a + '</b> → <b>v' + d.b + '</b> · +' + d.added + ' / -' + d.removed + ' / ~' + d.changed + (d.same ? ' · fark yok' : '') + '</p><div style="overflow:auto;max-height:560px;"><table class="ca-t">';
    d.rows.forEach(function (r) {
      if (r.op === 'skip') { h += '<tr class="ca-skip"><td colspan="4">… ' + r.n + ' aynı satır …</td></tr>'; return; }
      var cl = r.op === 'add' ? 'ca-add' : r.op === 'del' ? 'ca-del' : r.op === 'chg' ? 'ca-chg' : '';
      h += '<tr class="' + cl + '"><td class="n">' + r.ln + '</td><td>' + esc(r.l) + '</td><td class="n">' + r.rn + '</td><td>' + esc(r.r) + '</td></tr>';
    });
    el('caOut').innerHTML = h + '</table></div>';
  }
  function load(ip, a, b) {
    var q = '?ws=' + (el('caWs').checked ? 1 : 0) + '&nc=' + (el('caNc').checked ? 1 : 0);
    if (a && b) q += '&a=' + encodeURIComponent(a) + '&b=' + encodeURIComponent(b);
    fetch('/configs/audit/diff/' + encodeURIComponent(ip) + q, {credentials: 'same-origin'}).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) { el('caOut').textContent = j.error || 'Hata'; return; }
      cur = ip; el('caTitle').textContent = ip; el('caCtl').style.display = 'flex';
      var d = j.diff;
      fill(el('caA'), j.versions, d ? d.a : 0); fill(el('caB'), j.versions, d ? d.b : 0);
      render(d); el('caOut').scrollIntoView({behavior: 'smooth', block: 'nearest'});
    });
  }
  document.querySelectorAll('[data-diff]').forEach(function (b) {
    b.addEventListener('click', function () { load(b.dataset.diff, b.dataset.a, b.dataset.b); });
  });
  el('caPrint').addEventListener('click', function () { window.print(); });
  el('caGo').addEventListener('click', function () { if (cur) load(cur, el('caA').value, el('caB').value); });
})();
