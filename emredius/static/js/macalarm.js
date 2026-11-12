// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  var editing = false;
  function ruleRow(r) {
    var sev = ['INFO', 'WARNING', 'CRITICAL'].map(function (s) { return '<option' + (s === r.severity ? ' selected' : '') + '>' + s + '</option>'; }).join('');
    return '<tr data-rt="' + esc(r.rtype) + '"><td><input type="checkbox" class="ma-en" style="width:auto;"' + (r.enabled ? ' checked' : '') + '></td>' +
      '<td><b>' + esc(r.title) + '</b><br><small>' + esc(r.desc) + '</small></td>' +
      '<td>' + (r.param_label ? '<input type="number" class="ma-param" value="' + esc(r.param) + '" style="width:90px;" title="' + esc(r.param_label) + '">' : '-') + '</td>' +
      '<td><select class="ma-sev" style="width:auto;">' + sev + '</select></td>' +
      '<td><input type="text" class="ma-mail" value="' + esc(r.email_to) + '" placeholder="boş = bildirim yok" style="min-width:180px;"></td>' +
      '<td><button class="btn btn-primary ma-save" type="button">Kaydet</button></td></tr>';
  }
  function load() {
    if (editing) return;
    fetch('/macalarms/data').then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      q('maRules').innerHTML = j.rules.map(ruleRow).join('');
      q('maEvents').innerHTML = j.events.map(function (e) {
        return '<tr><td>' + esc(e.severity) + '</td><td>' + esc(e.device_ip) + '</td><td>' + esc(e.message) + '</td><td>' + esc(e.first_seen) +
          '</td><td>' + esc(e.last_seen) + '</td><td>' + esc(e.count) + '</td><td>' + esc(e.status) + '</td></tr>';
      }).join('') || '<tr><td colspan="7" style="color:var(--text-muted);">Alarm yok.</td></tr>';
    }).catch(function () {});
  }
  q('maRules').addEventListener('input', function () { editing = true; });
  q('maRules').addEventListener('click', function (ev) {
    var b = ev.target.closest('.ma-save');
    if (!b) return;
    var tr = b.closest('tr'), fd = new FormData();
    fd.append('enabled', tr.querySelector('.ma-en').checked ? '1' : '0');
    var p = tr.querySelector('.ma-param');
    if (p) fd.append('param', p.value);
    fd.append('severity', tr.querySelector('.ma-sev').value);
    fd.append('email_to', tr.querySelector('.ma-mail').value);
    fetch('/macalarms/rule/' + tr.dataset.rt, {method: 'POST', body: fd}).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) { alert(j.error); return; }
      editing = false; load();
    });
  });
  q('maRun').addEventListener('click', function () {
    fetch('/macalarms/run', {method: 'POST'}).then(function () { editing = false; load(); });
  });
  load();
  setInterval(load, 15000);
})();
