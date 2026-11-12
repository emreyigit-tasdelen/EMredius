// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  var COL = {CRITICAL: '#dc2626', WARNING: '#f59e0b', INFO: '#3b82f6'}, ST = {active: 'Aktif', ack: 'Onaylı', resolved: 'Çözüldü'};
  function qs() { return 'status=' + q('aStatus').value + '&severity=' + q('aSev').value + '&source=' + q('aSrc').value + '&q=' + encodeURIComponent(q('aQ').value); }
  function load() {
    q('aCsv').href = '/alarms/export.csv?' + qs();
    q('aJson').href = '/alarms/export.json?' + qs();
    fetch('/alarms/data?' + qs()).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      var s = j.stats;
      q('aStats').textContent = s.active + ' aktif · ' + s.critical + ' kritik · ' + s.ack + ' onaylı';
      q('aBody').innerHTML = j.events.map(function (e) {
        var id = String(e.id), mine = /^\d+$/.test(id), btn = '';
        if (mine && e.status === 'active') btn += '<button class="btn" data-ack="' + id + '" style="padding:0.2rem 0.6rem;">Onayla</button> ';
        if (mine && e.status !== 'resolved') btn += '<button class="btn" data-res="' + id + '" style="padding:0.2rem 0.6rem;">Çöz</button>';
        return '<tr><td><span style="color:' + (COL[e.severity] || '#64748b') + ';font-weight:600;">' + esc(e.severity) + '</span></td><td>' + (ST[e.status] || esc(e.status)) +
          (e.ack_by ? ' <small>(' + esc(e.ack_by) + ')</small>' : '') + '</td><td>' + esc(e.device_ip) + '</td><td>' + esc(e.message) +
          (e.ai_comment ? '<br><small>' + esc(e.ai_comment) + '</small>' : '') + '</td><td>' + esc(e.source) + '</td><td>' + esc(e.first_seen) +
          '</td><td>' + esc(e.last_seen) + '</td><td>' + e.count + '</td><td style="white-space:nowrap;">' + btn + '</td></tr>';
      }).join('') || '<tr><td colspan="9" style="color:var(--text-muted);">Alarm yok.</td></tr>';
    }).catch(function () {});
  }
  function post(url) {
    var t = document.querySelector('input[name="_csrf_token"]');
    fetch(url, {method: 'POST', headers: t ? {'X-CSRFToken': t.value} : {}}).then(function () { load(); });
  }
  document.addEventListener('click', function (e) {
    var a = e.target.closest('[data-ack]'), r = e.target.closest('[data-res]');
    if (a) post('/alarms/' + a.dataset.ack + '/ack');
    if (r) post('/alarms/' + r.dataset.res + '/resolve');
  });
  document.addEventListener('submit', function (e) { if (e.target.classList.contains('a-del') && !window.confirm('Kural silinsin mi?')) e.preventDefault(); });
  ['aStatus', 'aSev', 'aSrc'].forEach(function (id) { q(id).addEventListener('change', load); });
  var t;
  q('aQ').addEventListener('input', function () { clearTimeout(t); t = setTimeout(load, 300); });
  load();
  setInterval(load, 10000);
})();
