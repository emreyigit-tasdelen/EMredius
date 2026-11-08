// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
setInterval(function () {
  fetch('/svchealth/data').then(function (r) { return r.json(); }).then(function (j) {
    if (!j.success) return;
    var s = j.summary, el = document.getElementById('shSummary');
    el.textContent = s.up + '/' + s.total + ' çalışıyor' + (s.down ? ' · ' + s.down + ' DÜŞÜK' : '');
    el.className = 'status-pill ' + (s.ok ? 'online' : 'offline');
  }).catch(function () {});
}, 15000);