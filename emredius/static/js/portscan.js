// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Port scan page: polls the background scan job and renders progress + open ports
(function () {
  const card = document.getElementById('portscanResult');
  const jobId = card && card.getAttribute('data-job-id');
  if (!jobId) return;

  const badge = document.getElementById('psBadge');
  const summary = document.getElementById('psSummary');
  const bar = document.getElementById('psBar');
  const rows = document.getElementById('psRows');
  const empty = document.getElementById('psEmpty');
  const cancelBtn = document.getElementById('psCancel');
  const STATUS = { running: 'Taranıyor', done: 'Tamamlandı', cancelled: 'Durduruldu', error: 'Hata' };

  function render(job) {
    const pct = job.total ? Math.floor((job.done / job.total) * 100) : 0;
    bar.style.width = pct + '%';
    summary.textContent = job.label + ' (' + job.target + ') · port ' + job.range + ' · ' + job.done + '/' +
      job.total + ' (%' + pct + ') · ' + job.elapsed + ' sn · kapalı: ' + job.closed +
      ' · filtreli/yanıtsız: ' + job.filtered;
    badge.textContent = STATUS[job.status] + ' · ' + job.open.length + ' açık port';
    badge.className = 'status-pill ' + (job.open.length ? 'online' : (job.status === 'running' ? '' : 'offline'));
    rows.textContent = '';
    job.open.forEach(function (p) {
      const tr = document.createElement('tr');
      [p.port + '/tcp', 'açık', p.service || '-'].forEach(function (v) {
        const td = document.createElement('td');
        td.textContent = v;
        tr.appendChild(td);
      });
      rows.appendChild(tr);
    });
    empty.style.display = (job.status !== 'running' && !job.open.length) ? 'block' : 'none';
    cancelBtn.style.display = job.status === 'running' ? 'inline-flex' : 'none';
  }

  function poll() {
    fetch('/portscan/job/' + encodeURIComponent(jobId), { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.success) { summary.textContent = data.error || 'Tarama bulunamadı.'; return; }
        render(data.job);
        if (data.job.status === 'running') setTimeout(poll, 1000);
      })
      .catch(function () { setTimeout(poll, 3000); });
  }

  cancelBtn.addEventListener('click', function () {
    cancelBtn.disabled = true;
    fetch('/portscan/job/' + encodeURIComponent(jobId) + '/cancel', { method: 'POST' });
  });
  poll();
})();
