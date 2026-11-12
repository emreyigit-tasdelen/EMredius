// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  var sel = null;
  function csrf() { var m = document.querySelector('input[name="_csrf_token"]'); return m ? m.value : ''; }
  function load() {
    fetch('/watch/data?q=' + encodeURIComponent(q('wQ').value)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('wStats').textContent = j.stats.up + ' açık / ' + j.stats.total + ' hedef · ' + j.stats.down + ' kapalı';
      q('wBody').innerHTML = j.targets.map(function (t) {
        var c = t.status === 'UP' ? 'online' : 'offline';
        return '<tr data-id="' + t.id + '" data-name="' + esc(t.ip) + '" style="cursor:pointer;"><td><span class="status-pill ' + c + '">' +
          (t.status === 'UP' ? 'Açık' : t.status === 'DOWN' ? 'Kapalı' : 'Bekliyor') + '</span></td><td>' + esc(t.ip) + '</td><td>' + esc(t.name) +
          '</td><td>' + esc(t.inv_name || '-') + '</td><td>' + (t.rtt_ms == null ? '-' : esc(t.rtt_ms) + ' ms') + '</td><td>' + esc(t.loss_pct) +
          '%</td><td>' + esc(t.last_check) + '</td><td>' + esc(t.last_change) + '</td><td><form method="POST" action="/watch/' + t.id +
          '/delete" class="w-del" style="display:inline;"><input type="hidden" name="_csrf_token" value="' + esc(csrf()) +
          '"><button class="btn btn-danger" style="padding:0.3rem 0.7rem;"><i class="fa-solid fa-trash"></i></button></form></td></tr>';
      }).join('') || '<tr><td colspan="9" style="color:var(--text-muted);">Henüz hedef yok.</td></tr>';
    }).catch(function () {});
    if (sel) hist(sel.id, sel.name);
  }
  function hist(id, name) {
    sel = {id: id, name: name};
    fetch('/watch/history/' + id).then(function (r) { return r.json(); }).then(function (j) {
      var cv = q('wChart'), rows = j.rows || [];
      cv.style.display = rows.length ? '' : 'none';
      q('wChartLbl').textContent = name + ' · gecikme (ms), kırmızı çizgi = yanıt yok';
      if (!rows.length) return;
      var w = cv.width = cv.clientWidth || 600, h = cv.height = 120, x = cv.getContext('2d');
      var max = Math.max.apply(null, rows.map(function (r) { return r.rtt_ms || 0; }).concat([1]));
      x.clearRect(0, 0, w, h);
      x.beginPath(); x.strokeStyle = '#2563eb'; x.lineWidth = 1.5;
      var first = true;
      rows.forEach(function (r, i) {
        var px = i / Math.max(1, rows.length - 1) * w;
        if (!r.up) { x.stroke(); x.beginPath(); x.strokeStyle = '#dc2626'; x.moveTo(px, 0); x.lineTo(px, h); x.stroke(); x.beginPath(); x.strokeStyle = '#2563eb'; first = true; return; }
        var y = h - 4 - (r.rtt_ms / max) * (h - 8);
        if (first) { x.moveTo(px, y); first = false; } else x.lineTo(px, y);
      });
      x.stroke();
    }).catch(function () {});
  }
  document.addEventListener('click', function (e) {
    if (e.target.closest('form')) return;
    var t = e.target.closest('tr[data-id]');
    if (t && t.dataset.name) hist(t.dataset.id, t.dataset.name);
    if (e.target.closest('#wCheck')) fetch('/watch/check', {method: 'POST'}).then(function () { setTimeout(load, 4000); });
  });
  document.addEventListener('submit', function (e) { if (e.target.classList.contains('w-del') && !window.confirm('Hedef silinsin mi?')) e.preventDefault(); });
  var t;
  q('wQ').addEventListener('input', function () { clearTimeout(t); t = setTimeout(load, 300); });
  setInterval(load, 10000);
})();
