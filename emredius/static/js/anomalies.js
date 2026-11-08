// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function q(id) { return document.getElementById(id); }
  var SEV = {high: 'Yüksek', medium: 'Orta', low: 'Düşük'};
  function load() {
    fetch('/anomalies/data?days=' + encodeURIComponent(q('anDays').value)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      document.querySelectorAll('[data-rule]').forEach(function (i) { if (document.activeElement !== i) i.value = j.thresholds[i.dataset.rule]; });
      q('anInfo').textContent = j.available ? j.items.length + ' bulgu' : 'RADIUS veritabanına ulaşılamadı';
      q('anRows').innerHTML = j.items.map(function (x) {
        return '<tr><td><span class="status-pill ' + (x.severity === 'high' ? 'offline' : 'online') + '">' + esc(SEV[x.severity]) + '</span></td><td>' +
          esc(x.label) + '</td><td>' + esc(x.subject) + '</td><td>' + esc(x.count) + '</td><td>' + esc(x.detail) +
          '</td><td><a href="/correlation?q=' + encodeURIComponent(x.subject) + '">Korelasyon</a></td></tr>';
      }).join('') || '<tr><td colspan="6" style="color:var(--text-muted);">Anomali yok.</td></tr>';
    }).catch(function () {});
  }
  q('anSave').addEventListener('click', function () {
    var fd = new FormData();
    document.querySelectorAll('[data-rule]').forEach(function (i) { fd.append(i.dataset.rule, i.value); });
    fetch('/anomalies/rules', {method: 'POST', body: fd}).then(function (r) { return r.json(); }).then(function (j) {
      q('anRuleMsg').textContent = j.success ? 'Kaydedildi.' : (j.error || 'Hata'); load();
    }).catch(function () { q('anRuleMsg').textContent = 'İstek başarısız.'; });
  });
  q('anGo').addEventListener('click', load);
  q('anDays').addEventListener('change', load);
  load();
})();
