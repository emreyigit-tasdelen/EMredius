// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  var cur = '';
  var ST = {ok: ['Tamam', 'online'], planned_only: ['Görünmüyor', 'offline'], unplanned: ['Kayıtsız', 'offline'], offline: ['Pasif', 'offline']};
  function csrf() { var m = document.querySelector('input[name="_csrf_token"]'); return m ? m.value : ''; }
  function detail(cidr) {
    cur = cidr;
    fetch('/ipam/detail?cidr=' + encodeURIComponent(cidr)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('iDetailCard').style.display = '';
      q('iDetailTitle').textContent = cidr + ' adresleri';
      q('iDetailInfo').textContent = j.total + ' kayıt';
      q('iFree').innerHTML = '<b>İlk boş adresler:</b> ' + (j.free.length ? j.free.map(function (ip) { return '<a href="#" data-pick="' + esc(ip) + '">' + esc(ip) + '</a>'; }).join(', ') : 'yok');
      q('iDetail').innerHTML = j.rows.map(function (r) {
        var s = ST[r.state] || [r.state, 'offline'];
        return '<tr><td><span class="status-pill ' + s[1] + '">' + s[0] + '</span></td><td>' + esc(r.ip) + '</td><td>' + esc(r.name) + '</td><td>' + esc(r.kind || '-') + '</td><td>' + esc(r.owner) +
          '</td><td>' + esc(r.mac) + '</td><td>' + esc(r.vendor) + '</td><td>' + (r.addr_id ? '<button class="btn btn-danger" data-deladdr="' + r.addr_id + '" style="padding:0.2rem 0.6rem;">✕</button>' : '') + '</td></tr>';
      }).join('') || '<tr><td colspan="8" style="color:var(--text-muted);">Kayıt yok.</td></tr>';
    });
  }
  function refresh() {
    fetch('/ipam/data?q=' + encodeURIComponent(q('iQ').value)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      var s = j.stats;
      q('iStats').textContent = s.subnets + ' alt ağ · ' + s.unplanned + ' kayıtsız · ' + s.missing + ' görünmüyor · ' + s.full + ' dolu';
    });
    if (cur) detail(cur);
  }
  document.addEventListener('click', function (e) {
    var p = e.target.closest('[data-pick]'), d = e.target.closest('[data-deladdr]'), r = e.target.closest('tr[data-cidr]');
    if (p) { e.preventDefault(); q('iAddrIp').value = p.dataset.pick; }
    else if (d) fetch('/ipam/addr/' + d.dataset.deladdr + '/delete', {method: 'POST', headers: {'X-CSRFToken': csrf()}}).then(function () { detail(cur); });
    else if (r && !e.target.closest('form')) detail(r.dataset.cidr);
  });
  document.addEventListener('submit', function (e) { if (e.target.classList.contains('ip-del') && !window.confirm('Alt ağ silinsin mi?')) e.preventDefault(); });
  var t; q('iQ').addEventListener('input', function () { clearTimeout(t); t = setTimeout(function () { location.search = '?q=' + encodeURIComponent(q('iQ').value); }, 600); });
  setInterval(refresh, 20000);
})();
